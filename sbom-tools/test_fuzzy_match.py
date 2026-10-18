# sbom-tools/test_fuzzy_match.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Fuzzy suggestions (fuzzy_match.py): the hard rules (only unmatched rows,
# no "none" packages, short names never, version-only and type-stub variants
# rejected), the 0.70 confidence cap (never "matched"), ambiguity, same
# ecosystem preferred, the CLI (preview by default, --apply writes only the
# 7 match columns of rows that are still unmatched) and labeled_pairs never
# written. No network; SQLite stand-in for MySQL (see fake_mysql.py).

import contextlib
import csv
import difflib
import io
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import db_storage                                    # noqa: E402
import fake_mysql                                    # noqa: E402
import fuzzy_match                                   # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402
from fuzzy_match import (                            # noqa: E402
    BELOW_MINIMUM, CONFIDENCE_CAP, EXACT_EXISTS, FUZZY, NOT_ON_REGISTRY, OTHER_ECOSYSTEM,
    SUGGESTED, TOO_SHORT, FuzzyIndex, confidence_for, stub_variant, suggest, version_only,
)
from name_match import MATCHED, REVIEW, UNMATCHED, status_for   # noqa: E402


def ratio(a, b):
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def index(*pairs):
    return FuzzyIndex(pairs)


# ============================================================
# The user's real-data cases
# ============================================================
class TestRealDataCases(unittest.TestCase):

    def test_jinja2_gets_no_suggestion_of_jinja(self):
        r = suggest("jinja2", "pypi", index(("jinja", "pypi")))
        self.assertEqual((r["match_type"], r["match_status"], r["matched_name"]),
                         ("none", UNMATCHED, None))
        self.assertIn("'jinja' (pypi)", r["reason"])
        self.assertIn("version-only", r["reason"])

    def test_trailing_digit_or_version_is_rejected(self):
        for a, b in (("mysql2", "mysql"), ("pkg-1.2", "pkg-1.3"), ("foo-v2", "foo"),
                     ("bar3", "bar")):
            self.assertTrue(version_only(a, b), (a, b))
        self.assertFalse(version_only("mysql", "mysql"))
        self.assertFalse(version_only("abc1", "xyz1"))

    def test_zz_not_a_real_package_stays_unmatched(self):
        r = suggest("zz-not-a-real-package-1", "pypi",
                    index(("zz-not-a-real-package-2", "pypi"), ("zz-not-a-real-package-3", "pypi")))
        self.assertEqual((r["outcome"], r["match_status"]), (BELOW_MINIMUM, UNMATCHED))
        self.assertIn("version-only", r["reason"])

    def test_short_names_are_never_fuzzy_matched(self):
        for name in ("six", "re", "abc"):
            r = suggest(name, "pypi", index(("sixx", "pypi"), ("sex", "pypi")))
            self.assertEqual((r["outcome"], r["match_type"]), (TOO_SHORT, "none"), name)

    def test_type_stub_packages_are_rejected(self):
        self.assertTrue(stub_variant("types-python-dateutil", "python-dateutil"))
        self.assertTrue(stub_variant("requests", "requests-stubs"))
        r = suggest("python-dateutil", "pypi", index(("types-python-dateutil", "pypi")),
                    threshold=0.80)
        self.assertEqual(r["match_status"], UNMATCHED)
        self.assertIn("type stub", r["reason"])

    def test_none_packages_get_no_fuzzy_match(self):
        r = suggest("darling_core", "none", index(("darling-cores", "pypi")))
        self.assertEqual((r["outcome"], r["match_status"]), (NOT_ON_REGISTRY, UNMATCHED))
        self.assertIn("not on a registry", r["reason"])


# ============================================================
# Score, confidence, cap, ambiguity, ecosystem
# ============================================================
class TestScoring(unittest.TestCase):

    def test_threshold_boundaries(self):
        self.assertAlmostEqual(ratio("abcdefghij", "abcdefghik"), 0.9)
        at = suggest("abcdefghij", "pypi", index(("abcdefghik", "pypi")), threshold=0.90)
        self.assertEqual((at["outcome"], at["confidence"], at["match_status"]),
                         (SUGGESTED, 0.5, REVIEW))
        below = suggest("abcdefghij", "pypi", index(("abcdefghik", "pypi")), threshold=0.91)
        self.assertEqual((below["outcome"], below["matched_name"]), (BELOW_MINIMUM, None))
        self.assertIn("best below: 'abcdefghik' (pypi) 0.900", below["reason"])

    def test_confidence_rises_with_similarity_and_is_capped(self):
        values = [confidence_for(0.90 + i / 1000, 0.90) for i in range(0, 101)]
        self.assertEqual(values, sorted(values))
        self.assertEqual(values[0], 0.5)
        self.assertEqual(max(values), CONFIDENCE_CAP)
        self.assertTrue(all(v <= 0.70 for v in values))

    def test_never_matched_whatever_the_similarity(self):
        """The cap: from the threshold up to 0.999 the status is review, never matched"""
        for threshold in (0.80, 0.85, 0.90, 0.95):
            for i in range(0, 1000):
                s = threshold + (0.999 - threshold) * i / 999
                c = confidence_for(s, threshold)
                self.assertLessEqual(c, 0.70)
                self.assertEqual(status_for(c), REVIEW, (threshold, s, c))
                self.assertNotEqual(status_for(c), MATCHED)

    def test_very_similar_names_still_only_review(self):
        name, cand = "abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyy"
        r = suggest(name, "pypi", index((cand, "pypi")))
        self.assertEqual((r["match_type"], r["match_status"]), (FUZZY, REVIEW))
        self.assertLessEqual(r["confidence"], 0.70)

    def test_cross_ecosystem_candidate_is_never_suggested(self):
        r = suggest("abcdefghij", "pypi", index(("abcdefghik", "npm")))
        self.assertEqual((r["outcome"], r["matched_name"]), (OTHER_ECOSYSTEM, None))
        self.assertIn("'abcdefghik' (npm) 0.900", r["reason"])
        self.assertEqual(confidence_for(1.0, 0.90, same_ecosystem=False), 0.4)

    def test_same_ecosystem_is_preferred(self):
        r = suggest("abcdefghij", "pypi", index(("abcdefghik", "npm"), ("abcdefghik", "pypi")))
        self.assertEqual((r["matched_name"], r["match_ecosystem"]), ("abcdefghik", "pypi"))
        self.assertIn("competing: 'abcdefghik' (npm)", r["reason"])

    def test_two_alike_candidates_are_ambiguous(self):
        r = suggest("abcdefghij", "pypi", index(("abcdefghik", "pypi"), ("abcdefghil", "pypi")))
        self.assertEqual((r["outcome"], r["confidence"], r["match_status"]), (SUGGESTED, 0.5, REVIEW))
        self.assertIn("ambiguous", r["reason"])
        self.assertIn("'abcdefghil' (pypi)", r["reason"])

    def test_clear_winner_is_not_ambiguous(self):
        name = "abcdefghijklmnopqrst"
        r = suggest(name, "pypi", index(("abcdefghijklmnopqrsu", "pypi"),     # 0.95
                                        ("abcdefghijklmnopqxyz", "pypi")))    # 0.85
        self.assertNotIn("ambiguous", r["reason"])
        self.assertEqual(r["confidence"], 0.6)
        self.assertIn("fuzzy similarity 0.950", r["reason"])

    def test_exact_key_is_left_to_name_match(self):
        r = suggest("Requests", "pypi", index(("requests", "pypi")))
        self.assertEqual((r["outcome"], r["match_type"]), (EXACT_EXISTS, "none"))

    def test_result_keys(self):
        r = suggest("abcdefghij", "pypi", index(("abcdefghik", "pypi")))
        for key in ("match_type", "confidence", "match_status", "matched_name", "match_ecosystem",
                    "normalized_name", "similarity", "competitors", "reason"):
            self.assertIn(key, r)
        self.assertEqual(r["match_type"], FUZZY)
        self.assertEqual(r["normalized_name"], "abcdefghij")


# ============================================================
# CLI against the SQLite stand-in
# ============================================================
MATCH_COLUMNS = ["normalized_name", "matched_name", "match_ecosystem", "match_method",
                 "match_score", "match_status", "matched_at"]


class FuzzyCliTestCase(SqliteTestCase):

    CANDIDATES = ("name,ecosystem\npydantic-settings,pypi\njinja,pypi\n"
                  "zz-not-a-real-package-2,pypi\ndocling-core,pypi\nsixx,pypi\n")

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("""
            INSERT INTO packages (package_id, package_name, ecosystem, normalized_name,
                matched_name, match_ecosystem, match_method, match_score, match_status,
                matched_at, risk_score, risk_level)
            VALUES
              (1, 'pydantic-settingz', 'pypi', 'pydantic-settingz', NULL, NULL, 'none', 0,
                  'unmatched', '2026-10-18 10:00:00', 12.0, 'Low'),
              (2, 'pydantic-settingz', 'npm', 'pydantic-settingz', 'x', 'npm', 'exact', 0.7,
                  'review', '2026-10-18 10:00:00', NULL, NULL),
              (3, 'pydantic-settingy', 'pypi', 'pydantic-settingy', 'pydantic-settingy', 'pypi',
                  'exact', 1.0, 'matched', '2026-10-18 10:00:00', NULL, NULL),
              (4, 'jinja2', 'pypi', 'jinja2', NULL, NULL, 'none', 0, 'unmatched',
                  '2026-10-18 10:00:00', NULL, NULL),
              (5, 'six', 'pypi', 'six', NULL, NULL, 'none', 0, 'unmatched',
                  '2026-10-18 10:00:00', NULL, NULL),
              (6, 'darling_core', 'none', 'darling_core', NULL, NULL, 'none', 0, 'unmatched',
                  '2026-10-18 10:00:00', NULL, NULL),
              (7, 'zz-not-a-real-package-1', 'pypi', 'zz-not-a-real-package-1', NULL, NULL,
                  'none', 0, 'unmatched', '2026-10-18 10:00:00', NULL, NULL);
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
        self.dir = Path(tmp.name)
        self.candidates = self.dir / "reference_names.csv"
        self.candidates.write_text(self.CANDIDATES, encoding="utf-8")
        self.review = self.dir / "labeled_pairs_review.csv"
        self.review.write_text(
            "name_a,ecosystem_a,name_b,ecosystem_b,label,source\n"
            "node-lodash,deb,lodash,npm,match,purl2cpe\n"
            "django,pypi,django,github,match,purl2cpe\n"
            "requests,pypi,requests2,pypi,match,purl2cpe\n"
            "bitflags,pypi,bitflags,npm,non-match,same-name-different-repo\n",
            encoding="utf-8")

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

    def run_cli(self, *args, review=None):
        argv = ["--candidates", str(self.candidates),
                "--review-csv", str(self.review if review is None else review), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fuzzy_match.main(argv)
        return code, out.getvalue()

    def packages(self):
        return {r["package_id"]: r for r in self.rows("SELECT * FROM packages")}


class TestFuzzyCli(FuzzyCliTestCase):

    def test_preview_writes_nothing_and_lists_every_unmatched_row(self):
        before = self.packages()
        code, out = self.run_cli()

        self.assertEqual(code, 0)
        self.assertEqual(self.packages(), before)
        self.assertIn("Unmatched packages: 5; would get a fuzzy suggestion: 1", out)
        for name in ("pydantic-settingz (pypi) -> pydantic-settings (pypi)", "jinja2 (pypi)",
                     "six (pypi)", "darling_core (none)", "zz-not-a-real-package-1 (pypi)"):
            self.assertIn(name, out)
        self.assertNotIn("pydantic-settingy", out)          # matched row: not considered
        self.assertIn("Preview only", out)

    def test_apply_writes_only_unmatched_suggestions(self):
        before = self.packages()
        code, out = self.run_cli("--apply")
        after = self.packages()

        self.assertEqual(code, 0)
        self.assertIn("Wrote fuzzy suggestions for 1 packages", out)
        row = after[1]
        self.assertEqual((row["match_method"], row["match_status"], row["matched_name"],
                          row["match_ecosystem"]), (FUZZY, REVIEW, "pydantic-settings", "pypi"))
        self.assertLessEqual(row["match_score"], 0.70)
        self.assertNotEqual(row["matched_at"], before[1]["matched_at"])
        for column in row:                                   # nothing outside the 7 columns
            if column not in MATCH_COLUMNS:
                self.assertEqual(row[column], before[1][column], column)
        for pid in (2, 3, 4, 5, 6, 7):                       # review, matched, no suggestion
            self.assertEqual(after[pid], before[pid], pid)

    def test_matched_and_review_rows_are_never_overwritten(self):
        """Even rows that would fuzzy-match keep exactly what they had"""
        before = self.packages()
        self.run_cli("--apply")
        after = self.packages()
        self.assertEqual(after[2], before[2])                # review, same name as row 1
        self.assertEqual(after[3], before[3])                # matched, scores 0.94 too

    def test_row_that_changed_meanwhile_is_not_overwritten(self):
        """The SQL guard: read as unmatched, but review by the time of the write"""
        stale = [dict(r) for r in self.db.package_match_status_rows()]
        self.sqlite.execute("UPDATE packages SET match_status = 'review', match_method = 'exact' "
                            "WHERE package_id = 1")
        self.sqlite.commit()
        before = self.packages()
        with mock.patch.object(db_storage.DatabaseStorage, "package_match_status_rows",
                               lambda db_self: stale):
            _, out = self.run_cli("--apply")
        self.assertEqual(self.packages()[1], before[1])
        self.assertIn("1 skipped: no longer unmatched", out)

    def test_rerun_changes_nothing_more(self):
        self.run_cli("--apply")
        first = self.packages()
        _, out = self.run_cli("--apply")
        self.assertEqual(self.packages(), first)
        self.assertIn("would get a fuzzy suggestion: 0", out)

    def test_out_csv_has_reasons_and_competitors(self):
        out_csv = self.dir / "fuzzy.csv"
        self.run_cli("--out", str(out_csv))
        with open(out_csv, encoding="utf-8") as f:
            rows = {r["package_name"]: r for r in csv.DictReader(f)}
        self.assertEqual(set(rows), {"pydantic-settingz", "jinja2", "six", "darling_core",
                                     "zz-not-a-real-package-1"})
        self.assertIn("fuzzy similarity", rows["pydantic-settingz"]["reason"])
        self.assertIn("version-only", rows["jinja2"]["reason"])
        with open(out_csv, encoding="utf-8") as f:
            self.assertIn("competitors", f.readline())

    def test_threshold_report_says_proposals(self):
        _, out = self.run_cli()
        self.assertIn("4 PROPOSED pairs, not reviewed: indicative only", out)
        self.assertIn("cannot measure fuzzy precision", out)
        _, out = self.run_cli(review="")
        self.assertNotIn("PROPOSED", out)

    def test_bad_inputs_exit_2(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(fuzzy_match.main(["--candidates", str(self.dir / "nope.csv")]), 2)
        self.assertEqual(self.run_cli(review=self.dir / "nope.csv")[0], 2)
        self.assertEqual(self.run_cli("--min-similarity", "0.5")[0], 2)

    def test_labeled_pairs_is_never_written(self):
        self.run_cli()
        self.run_cli("--apply")
        self.assertFalse([sql for sql in self.executed if "labeled_pairs" in sql])
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM labeled_pairs")[0]["n"], 1)

    def test_module_has_no_sql_for_labeled_pairs(self):
        sql = re.compile(r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM|FROM|INTO|JOIN)\s+`?labeled_pairs\b",
                         re.IGNORECASE)
        source = Path(fuzzy_match.__file__).read_text(encoding="utf-8")
        self.assertIsNone(sql.search(source))


if __name__ == "__main__":
    unittest.main()
