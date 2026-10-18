# sbom-tools/test_name_match.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Rule-based name matching (name_match.py): normalization, every layer, the
# ecosystem penalty, status cut-offs, the alias file, best_match over many
# candidates, and the CLI (dry run by default, --apply writes only the
# packages match columns, labeled_pairs is never written). No network;
# SQLite stand-in for MySQL (see fake_mysql.py).

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)

import db_storage                                   # noqa: E402
import fake_mysql                                   # noqa: E402
import name_match                                   # noqa: E402
from fake_mysql import SqliteTestCase               # noqa: E402
from name_match import (                            # noqa: E402
    ALIAS, EXACT, MATCHED, NO_MATCH, NORMALIZED, PREFIX_STRIPPED, REVIEW,
    SCOPE_STRIPPED, UNMATCHED, AliasFileError, CandidateIndex, best_match,
    load_aliases, load_candidates, match_pair, normalized_name, status_for,
)

ALIASES = load_aliases()   # the real name_aliases.json


def pair(a, eco_a, b, eco_b):
    return match_pair(a, eco_a, b, eco_b, ALIASES)


class TestNormalizedName(unittest.TestCase):

    def test_pypi_is_pep_503(self):
        self.assertEqual(normalized_name("Foo.Bar_baz", "pypi"), "foo-bar-baz")
        self.assertEqual(normalized_name("PyYAML", "python"), "pyyaml")

    def test_npm_only_lowercases(self):
        self.assertEqual(normalized_name("Lodash.Merge_x", "npm"), "lodash.merge_x")

    def test_maven_drops_the_version(self):
        self.assertEqual(normalized_name("Org.Foo:Bar:1.2.3", "maven"), "org.foo:bar")

    def test_whitespace_is_trimmed(self):
        self.assertEqual(normalized_name("  Requests ", "pypi"), "requests")
        self.assertEqual(normalized_name("  React ", None), "react")


class TestLayers(unittest.TestCase):

    def assertMatch(self, result, match_type, confidence):
        self.assertEqual((result["match_type"], result["confidence"]),
                         (match_type, confidence), result["reason"])

    def test_exact(self):
        r = pair("requests", "pypi", "requests", "pypi")
        self.assertMatch(r, EXACT, 1.0)
        self.assertIn("identical", r["reason"])

    def test_case_only(self):
        self.assertMatch(pair("React", "npm", "react", "npm"), NORMALIZED, 0.95)

    def test_pypi_separators_are_pep_503(self):
        r = pair("python_dateutil", "pypi", "Python.Dateutil", "pypi")
        self.assertMatch(r, NORMALIZED, 0.95)
        self.assertIn("PEP 503", r["reason"])

    def test_npm_separators_are_review(self):
        r = pair("lodash.merge", "npm", "lodash-merge", "npm")
        self.assertMatch(r, NORMALIZED, 0.75)
        self.assertIn("npm treats these as different", r["reason"])

    def test_alias_both_directions(self):
        for a, b in (("sklearn", "scikit-learn"), ("scikit-learn", "sklearn")):
            r = pair(a, "pypi", b, "pypi")
            self.assertMatch(r, ALIAS, 0.90)
            self.assertIn("sklearn is an alias of scikit-learn", r["reason"])

    def test_alias_matches_in_normalized_form(self):
        self.assertMatch(pair("PIL", "pypi", "pillow", "pypi"), ALIAS, 0.90)

    def test_alias_wins_over_prefix_stripping(self):
        """dateutil is listed as the import name of python-dateutil"""
        self.assertMatch(pair("dateutil", "pypi", "python-dateutil", "pypi"), ALIAS, 0.90)

    def test_npm_scope_stripped(self):
        r = pair("@babel/core", "npm", "core", "npm")
        self.assertMatch(r, SCOPE_STRIPPED, 0.60)
        self.assertIn("@babel/", r["reason"])

    def test_types_scope_is_never_stripped(self):
        r = pair("@types/node", "npm", "node", "npm")
        self.assertMatch(r, NO_MATCH, 0.0)
        self.assertIn("type definitions", r["reason"])

    def test_maven_group_stripped(self):
        for name in ("org.foo:bar", "org.foo:bar:1.2"):
            r = pair(name, "maven", "bar", "maven")
            self.assertMatch(r, SCOPE_STRIPPED, 0.60)
            self.assertIn("Maven group org.foo", r["reason"])

    def test_python_prefix(self):
        r = pair("python-docx", "pypi", "docx", "pypi")
        self.assertMatch(r, PREFIX_STRIPPED, 0.60)
        self.assertIn("python- prefix", r["reason"])

    def test_lib_prefix(self):
        self.assertMatch(pair("libsass", "npm", "sass", "npm"), PREFIX_STRIPPED, 0.50)
        self.assertMatch(pair("lib-yaml", "npm", "yaml", "npm"), PREFIX_STRIPPED, 0.50)

    def test_lib_prefix_too_short_is_rejected(self):
        r = pair("librt", "pypi", "rt", "pypi")
        self.assertMatch(r, NO_MATCH, 0.0)
        self.assertIn("too short", r["reason"])

    def test_no_match(self):
        r = pair("requests", "pypi", "flask", "pypi")
        self.assertMatch(r, NO_MATCH, 0.0)
        self.assertEqual(r["reason"], "no rule matched")


class TestEcosystemPenalty(unittest.TestCase):

    def test_same_name_in_two_ecosystems_is_review(self):
        r = pair("semver", "pypi", "semver", "npm")
        self.assertEqual((r["match_type"], r["confidence"]), (EXACT, 0.70))
        self.assertEqual(status_for(r["confidence"]), REVIEW)
        self.assertIn("ecosystem differs (pypi vs npm)", r["reason"])

    def test_none_counts_as_known(self):
        """A no-registry name never auto-matches a same-named PyPI project"""
        r = pair("cargo_metadata", "none", "cargo-metadata", "pypi")
        self.assertEqual((r["match_type"], r["confidence"]), (NORMALIZED, 0.65))
        self.assertEqual(status_for(r["confidence"]), REVIEW)

    def test_unknown_ecosystem_has_no_penalty(self):
        r = pair("requests", None, "requests", "pypi")
        self.assertEqual(r["confidence"], 1.0)
        self.assertIn("ecosystem unknown", r["reason"])

    def test_spellings_of_one_ecosystem_are_the_same(self):
        self.assertEqual(pair("requests", "python", "requests", "pypi")["confidence"], 1.0)

    def test_score_never_below_zero(self):
        r = pair("libsass", "npm", "sass", "pypi")   # 0.50 - 0.30
        self.assertEqual(r["confidence"], 0.2)
        for name_a, name_b in (("a", "a"), ("libyaml", "yaml"), ("x.y", "x-y")):
            for eco_a, eco_b in (("pypi", "npm"), ("none", "maven")):
                self.assertGreaterEqual(pair(name_a, eco_a, name_b, eco_b)["confidence"], 0)


class TestResultContract(unittest.TestCase):

    CASES = [("requests", "pypi", "requests", "pypi"), ("React", "npm", "react", "npm"),
             ("sklearn", "pypi", "scikit-learn", "pypi"), ("@babel/core", "npm", "core", "npm"),
             ("@types/node", "npm", "node", "npm"), ("semver", "none", "semver", "npm"),
             ("x", None, "y", None), ("", None, "", None)]

    def test_every_result_has_type_confidence_reason(self):
        for case in self.CASES:
            r = pair(*case)
            self.assertEqual(set(r), {"match_type", "confidence", "reason"}, case)
            self.assertTrue(0 <= r["confidence"] <= 1, case)
            self.assertEqual(r["confidence"], round(r["confidence"], 4), case)
            self.assertTrue(r["reason"], case)
            self.assertLessEqual(len(r["match_type"]), 30)   # packages.match_method

    def test_statuses_fit_the_column(self):
        for status in name_match.MATCH_STATUSES:
            self.assertLessEqual(len(status), 20)              # packages.match_status


class TestStatus(unittest.TestCase):

    def test_boundaries(self):
        self.assertEqual(status_for(1.0), MATCHED)
        self.assertEqual(status_for(0.90), MATCHED)
        self.assertEqual(status_for(0.8999), REVIEW)
        self.assertEqual(status_for(0.50), REVIEW)
        self.assertEqual(status_for(0.4999), UNMATCHED)
        self.assertEqual(status_for(0.0), UNMATCHED)


class TestAliasFile(unittest.TestCase):

    def write(self, entries):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "aliases.json"
        path.write_text(json.dumps({"version": 1, "aliases": entries}), encoding="utf-8")
        return path

    def test_real_file_loads(self):
        self.assertIn("pypi", ALIASES.ecosystems())
        self.assertEqual(ALIASES.canonical("pypi", "sklearn"), "scikit-learn")

    def test_one_alias_for_two_canonicals_is_rejected(self):
        path = self.write([
            {"ecosystem": "pypi", "canonical": "a", "aliases": ["x"]},
            {"ecosystem": "pypi", "canonical": "b", "aliases": ["X"]},   # same after PEP 503
        ])
        with self.assertRaisesRegex(AliasFileError, "already belongs"):
            load_aliases(path)

    def test_alias_equal_to_canonical_is_rejected(self):
        path = self.write([{"ecosystem": "pypi", "canonical": "PyYAML", "aliases": ["pyyaml"]}])
        with self.assertRaisesRegex(AliasFileError, "canonical name itself"):
            load_aliases(path)

    def test_unknown_ecosystem_is_rejected(self):
        for eco in ("cargo", "none", None):
            path = self.write([{"ecosystem": eco, "canonical": "a", "aliases": ["b"]}])
            with self.assertRaisesRegex(AliasFileError, "unknown ecosystem"):
                load_aliases(path)

    def test_custom_confidence(self):
        path = self.write([{"ecosystem": "npm", "canonical": "lodash", "aliases": ["underscore-ish"],
                            "confidence": 0.7}])
        r = match_pair("underscore-ish", "npm", "lodash", "npm", load_aliases(path))
        self.assertEqual((r["match_type"], r["confidence"]), (ALIAS, 0.7))


class TestBestMatch(unittest.TestCase):

    CANDIDATES = [
        ("requests", "pypi"), ("scikit-learn", "pypi"), ("semver", "pypi"), ("semver", "npm"),
        ("core", "npm"), ("node", "npm"), ("sass", "npm"), ("docx", "pypi"),
        ("lodash-merge", "npm"), ("cargo-metadata", "pypi"), ("react", "npm"),
        ("python-dateutil", "pypi"), ("dateutil", "pypi"),
    ]

    def setUp(self):
        self.index = CandidateIndex(self.CANDIDATES, ALIASES)

    def test_highest_confidence_wins(self):
        r = best_match("Requests", "pypi", self.index)
        self.assertEqual((r["matched_name"], r["match_type"], r["match_status"]),
                         ("requests", NORMALIZED, MATCHED))

    def test_same_ecosystem_wins_a_tie_break(self):
        r = best_match("semver", "npm", self.index)
        self.assertEqual((r["matched_name"], r["match_ecosystem"], r["confidence"]),
                         ("semver", "npm", 1.0))
        self.assertNotIn("ambiguous", r["reason"])

    def test_two_equally_good_names_are_ambiguous(self):
        """A no-registry 'semver' scores 0.70 against both pypi and npm semver"""
        r = best_match("semver", "none", self.index)
        self.assertEqual(r["match_status"], REVIEW)
        self.assertIn("ambiguous", r["reason"])

    def test_ambiguity_caps_matched_at_review(self):
        index = CandidateIndex([("foo", "pypi"), ("Foo", "pypi")], ALIASES)
        r = best_match("FOO", "pypi", index)
        self.assertEqual((r["confidence"], r["match_status"]), (0.95, REVIEW))

    def test_no_candidates(self):
        r = best_match("requests", "pypi", CandidateIndex([], ALIASES))
        self.assertEqual((r["match_status"], r["matched_name"], r["match_ecosystem"]),
                         (UNMATCHED, None, None))
        self.assertIn("no candidate", r["reason"])

    def test_nothing_matches(self):
        r = best_match("left-pad", "npm", self.index)
        self.assertEqual((r["match_type"], r["match_status"], r["matched_name"]),
                         (NO_MATCH, UNMATCHED, None))

    def test_alias_beats_prefix_stripping(self):
        r = best_match("dateutil", "pypi", self.index)
        self.assertEqual(r["matched_name"], "dateutil")      # exact first
        r = best_match("sklearn", "pypi", self.index)
        self.assertEqual((r["matched_name"], r["match_type"]), ("scikit-learn", ALIAS))

    def test_index_gives_the_same_answer_as_scoring_everything(self):
        names = [("Requests", "pypi"), ("sklearn", "pypi"), ("semver", "none"),
                 ("@babel/core", "npm"), ("@types/node", "npm"), ("libsass", "npm"),
                 ("python-docx", "pypi"), ("lodash.merge", "npm"), ("cargo_metadata", "none"),
                 ("React", None), ("python_dateutil", "pypi"), ("nothing-like-it", "npm")]
        for name, eco in names:
            fast = best_match(name, eco, self.index)
            slow = best_match(name, eco, self.index, candidates=self.index.candidates)
            for key in ("matched_name", "match_ecosystem", "match_type", "confidence",
                        "match_status", "reason"):
                self.assertEqual(fast[key], slow[key], (name, key))


class TestLoadCandidates(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def test_release_cache_keys(self):
        path = self.dir / "cache.json"
        path.write_text(json.dumps({"pypi:requests": {}, "npm:@babel/core": {},
                                    "maven:org.foo:bar": {}}), encoding="utf-8")
        self.assertEqual(sorted(load_candidates(path)),
                         [("@babel/core", "npm"), ("org.foo:bar", "maven"), ("requests", "pypi")])

    def test_release_cache_misses_are_not_known_names(self):
        """null = the registry doesn't have that name"""
        path = self.dir / "cache.json"
        path.write_text(json.dumps({"pypi:requests": {"versions": {}}, "pypi:libloading": None,
                                    "npm:libloading": None}), encoding="utf-8")
        self.assertEqual(load_candidates(path), [("requests", "pypi")])

    def test_csv(self):
        path = self.dir / "names.csv"
        path.write_text("name,ecosystem\nrequests,pypi\nreact,npm\n,npm\n", encoding="utf-8")
        self.assertEqual(load_candidates(path), [("requests", "pypi"), ("react", "npm")])

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_candidates(self.dir / "nope.json")


# ============================================================
# CLI against the SQLite stand-in
# ============================================================
MATCH_COLUMNS = ["normalized_name", "matched_name", "match_ecosystem", "match_method",
                 "match_score", "match_status", "matched_at"]


class TestCli(SqliteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("""
            INSERT INTO packages (package_id, package_name, ecosystem, risk_score,
                                  risk_level, priority_rank)
            VALUES (1, 'Requests', 'pypi', 42.0, 'Medium', 3),
                   (2, '@babel/core', 'npm', 10.0, 'Low', 7),
                   (3, 'sklearn', 'pypi', NULL, NULL, NULL),
                   (4, 'cargo_metadata', 'none', NULL, NULL, NULL),
                   (5, 'left-pad', 'npm', NULL, NULL, NULL);
            INSERT INTO labeled_pairs (name_a, name_b, label, labeled_by)
            VALUES ('a', 'b', 'match', 'tester');
            CREATE TRIGGER lp_no_insert BEFORE INSERT ON labeled_pairs
                BEGIN SELECT RAISE(ABORT, 'labeled_pairs must not be written'); END;
            CREATE TRIGGER lp_no_update BEFORE UPDATE ON labeled_pairs
                BEGIN SELECT RAISE(ABORT, 'labeled_pairs must not be written'); END;
            CREATE TRIGGER lp_no_delete BEFORE DELETE ON labeled_pairs
                BEGIN SELECT RAISE(ABORT, 'labeled_pairs must not be written'); END;
        """)
        self.sqlite.commit()

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.candidates = Path(tmp.name) / "names.csv"
        self.candidates.write_text(
            "name,ecosystem\nrequests,pypi\nscikit-learn,pypi\ncore,npm\ncargo-metadata,pypi\n",
            encoding="utf-8")

        # Record every SQL statement the CLI runs
        self.executed = []
        real_execute = fake_mysql.SqliteCursor.execute

        def recording_execute(cursor, sql, params=()):
            self.executed.append(sql)
            return real_execute(cursor, sql, params)

        for patcher in (
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(fake_mysql.SqliteCursor, "execute", recording_execute),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = name_match.main(["--candidates", str(self.candidates), *args])
        return code, out.getvalue()

    def packages(self):
        return {r["package_id"]: r for r in self.rows("SELECT * FROM packages")}

    def test_dry_run_writes_nothing(self):
        before = self.packages()
        code, out = self.run_cli()

        self.assertEqual(code, 0)
        self.assertEqual(self.packages(), before)
        self.assertTrue(all(r[c] is None for r in before.values() for c in MATCH_COLUMNS))
        self.assertIn("Preview only", out)

    def test_apply_writes_only_the_match_columns(self):
        before = self.packages()
        code, out = self.run_cli("--apply")
        after = self.packages()

        self.assertEqual(code, 0)
        self.assertIn("Wrote match columns for 5 packages", out)
        for pid, row in after.items():
            for column, value in row.items():
                if column not in MATCH_COLUMNS:
                    self.assertEqual(value, before[pid][column], (pid, column))
        self.assertEqual(
            {k: after[1][k] for k in ("normalized_name", "matched_name", "match_ecosystem",
                                      "match_method", "match_score", "match_status")},
            {"normalized_name": "requests", "matched_name": "requests",
             "match_ecosystem": "pypi", "match_method": NORMALIZED,
             "match_score": 0.95, "match_status": MATCHED})
        self.assertEqual((after[2]["match_method"], after[2]["match_status"]),
                         (SCOPE_STRIPPED, REVIEW))
        self.assertEqual((after[3]["matched_name"], after[3]["match_method"]),
                         ("scikit-learn", ALIAS))
        self.assertEqual(after[4]["match_status"], REVIEW)   # none vs pypi: 0.65
        self.assertEqual((after[5]["match_status"], after[5]["matched_name"]), (UNMATCHED, None))
        self.assertIsNotNone(after[1]["matched_at"])

    def test_rerun_gives_the_same_values(self):
        self.run_cli("--apply")
        first = self.packages()
        self.run_cli("--apply")
        second = self.packages()
        for pid in first:
            for column in MATCH_COLUMNS[:-1]:            # matched_at is a timestamp
                self.assertEqual(first[pid][column], second[pid][column])

    def test_ecosystem_filter(self):
        self.run_cli("--ecosystem", "npm", "--apply")
        written = {pid for pid, r in self.packages().items() if r["match_status"]}
        self.assertEqual(written, {2, 5})

    def test_missing_candidates_file_exits_2(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = name_match.main(["--candidates", str(self.candidates) + ".missing"])
        self.assertEqual(code, 2)
        self.assertIn("not found", out.getvalue())

    def test_labeled_pairs_is_never_written(self):
        """Triggers make any write fail; and no statement names the table"""
        self.run_cli()
        self.run_cli("--apply")
        self.assertFalse([sql for sql in self.executed if "labeled_pairs" in sql])
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM labeled_pairs")[0]["n"], 1)

    def test_module_has_no_sql_for_labeled_pairs(self):
        source = Path(name_match.__file__).read_text(encoding="utf-8")
        code_lines = [line for line in source.splitlines()
                      if "labeled_pairs" in line and not line.strip().startswith("#")]
        self.assertEqual(code_lines, [])

    def test_out_csv_has_reasons(self):
        out_csv = self.candidates.with_name("results.csv")
        self.run_cli("--out", str(out_csv))
        text = out_csv.read_text(encoding="utf-8")
        self.assertIn("reason", text.splitlines()[0])
        self.assertIn("sklearn is an alias of scikit-learn", text)


if __name__ == "__main__":
    unittest.main()
