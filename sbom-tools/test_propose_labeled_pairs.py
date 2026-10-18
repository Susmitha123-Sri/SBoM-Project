# sbom-tools/test_propose_labeled_pairs.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# propose_labeled_pairs.py: positives from purl2cpe products and shared
# repositories, non-match candidates from same name / different repository,
# labels only match / non-match, reproducible sampling, preview by default,
# and labeled_pairs is never written (only a review CSV). No network; SQLite
# stand-in for MySQL (see fake_mysql.py).

import contextlib
import csv
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
import propose_labeled_pairs                         # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402
from propose_labeled_pairs import (COLUMNS, HIGH, LABELS, LOW, MATCH, NON_MATCH,  # noqa: E402
                                   name_similarity, sample)
from test_reference_sources import (PURL2CPE_ROWS, make_package_lists,  # noqa: E402
                                    make_purl2cpe_zip)

# One CPE product, two different packages: Jinja (old, PyPI) and jinja2 (deb)
JINJA_ROWS = [
    ("pkg:pypi/jinja", "cpe:2.3:a:palletsprojects:jinja:2.10:*:*:*:*:*:*:*"),
    ("pkg:deb/debian/jinja2", "cpe:2.3:a:palletsprojects:jinja:2.10:*:*:*:*:*:*:*"),
]


class ProposeTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.lists = make_package_lists(self.dir / "Package-List")
        self.zip = make_purl2cpe_zip(self.dir / "purl2cpe.db.zip", PURL2CPE_ROWS + JINJA_ROWS)
        self.out = self.dir / "labeled_pairs_review.csv"

        self.sqlite.executescript("""
            INSERT INTO packages (package_id, package_name, ecosystem) VALUES
                (1, 'protobuf', 'pypi'), (2, 'bitflags', 'none'), (3, 'django', 'pypi'),
                (4, 'lodash', 'npm'), (5, 'semver', 'pypi');
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

    def run_cli(self, *args, lists=None, zip_path=None):
        argv = ["--package-lists", str(self.lists if lists is None else lists),
                "--purl2cpe", str(self.zip if zip_path is None else zip_path),
                "--out", str(self.out), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = propose_labeled_pairs.main(argv)
        return code, out.getvalue()

    def pairs(self):
        with open(self.out, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def find(self, rows, a, b):
        """The row for an unordered pair of (name, ecosystem)."""
        want = {a, b}
        return [r for r in rows
                if {(r["name_a"], r["ecosystem_a"]), (r["name_b"], r["ecosystem_b"])} == want]


class TestProposeLabeledPairs(ProposeTestCase):

    def test_preview_writes_nothing(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0)
        self.assertFalse(self.out.exists())
        self.assertIn("Preview only", out)

    def test_purl2cpe_product_pairs_are_matches(self):
        self.run_cli("--apply")
        rows = self.pairs()
        [r] = self.find(rows, ("django", "pypi"), ("django/django", "github"))
        self.assertEqual((r["label"], r["source"]), (MATCH, "purl2cpe"))
        self.assertIn("djangoproject:django", r["evidence"])
        # deb PURLs: the namespace is the distribution, not part of the name
        [r] = self.find(rows, ("lodash", "npm"), ("node-lodash", "deb"))
        self.assertEqual(r["label"], MATCH)
        cpe = self.find(rows, ("lodash", "npm"), ("lodash", "cpe"))
        self.assertEqual(cpe[0]["note"], "name_b is a CPE product name")

    def test_shared_repository_gives_cross_ecosystem_matches(self):
        self.run_cli("--apply")
        rows = self.pairs()
        [r] = self.find(rows, ("protobuf", "pypi"), ("google-protobuf", "npm"))
        self.assertEqual((r["label"], r["source"]), (MATCH, "cross-eco-repo"))
        self.assertIn("github.com/protocolbuffers/protobuf", r["evidence"])
        self.assertTrue(self.find(rows, ("protobuf", "pypi"),
                                  ("com.google.protobuf:protobuf-java", "maven")))

    def test_same_name_different_repository_is_a_non_match_candidate(self):
        self.run_cli("--apply")
        rows = self.pairs()
        [r] = self.find(rows, ("bitflags", "pypi"), ("bitflags", "npm"))
        self.assertEqual((r["label"], r["source"]), (NON_MATCH, "same-name-different-repo"))
        [r] = self.find(rows, ("semver", "pypi"), ("semver", "npm"))
        self.assertEqual(r["label"], NON_MATCH)
        self.assertEqual(r["package_id"], "5")             # our semver (pypi) is name_a
        self.assertEqual((r["name_a"], r["ecosystem_a"]), ("semver", "pypi"))

    def test_same_name_same_repository_is_only_a_match(self):
        """tree-sitter on PyPI and npm from one repository: match, no conflict"""
        _, out = self.run_cli("--apply", "--all")
        [r] = self.find(self.pairs(), ("tree-sitter", "pypi"), ("tree-sitter", "npm"))
        self.assertEqual((r["label"], r["source"]), (MATCH, "cross-eco-repo"))
        self.assertNotIn("conflicting", r["note"])
        self.assertIn("conflicting evidence resolved: 0", out)

    def test_rows_fit_labeled_pairs(self):
        self.run_cli("--apply")
        rows = self.pairs()
        self.assertTrue(rows)
        self.assertEqual(list(rows[0]), COLUMNS)
        for r in rows:
            self.assertIn(r["label"], LABELS)
            self.assertLessEqual(len(r["source"]), 50)       # labeled_pairs.source
            self.assertLessEqual(len(r["note"]), 500)        # labeled_pairs.note
            self.assertTrue(r["name_a"] and r["name_b"])
            self.assertEqual(r["reviewed"], "")              # proposals only

    def test_only_names_related_to_our_packages_by_default(self):
        self.run_cli("--apply")
        names = {r["name_a"] for r in self.pairs()} | {r["name_b"] for r in self.pairs()}
        self.assertNotIn("requests", names)                  # not one of our packages
        self.run_cli("--apply", "--all")
        names = {r["name_a"] for r in self.pairs()} | {r["name_b"] for r in self.pairs()}
        self.assertIn("@babel/core", names)

    def test_same_seed_same_output(self):
        self.run_cli("--apply", "--all", "--max-pairs", "6", "--seed", "7")
        first = self.out.read_text(encoding="utf-8")
        self.run_cli("--apply", "--all", "--max-pairs", "6", "--seed", "7")
        self.assertEqual(self.out.read_text(encoding="utf-8"), first)
        self.assertEqual(len(self.pairs()), 6)

    def test_sampling_keeps_both_labels(self):
        rows = [{"label": MATCH, "source": "s", "ecosystem_a": "e", "name_a": f"m{i}",
                 "ecosystem_b": "e", "name_b": "x",
                 "name_similarity": HIGH if i % 2 else LOW} for i in range(20)]
        rows += [{"label": NON_MATCH, "source": "s", "ecosystem_a": "e", "name_a": f"n{i}",
                  "ecosystem_b": "e", "name_b": "x", "name_similarity": HIGH} for i in range(3)]
        picked = sample(rows, 10, seed=1)
        self.assertEqual(len(picked), 10)
        self.assertEqual(sum(r["label"] == NON_MATCH for r in picked), 3)
        self.assertEqual(picked, sample(rows, 10, seed=1))
        order = [r["name_similarity"] for r in picked]
        self.assertEqual(order, sorted(order, key=lambda x: x != HIGH))   # high first

    def test_missing_inputs_exit_2(self):
        for kwargs in ({"lists": self.dir / "nope"}, {"zip_path": self.dir / "nope.zip"},
                       {"lists": "", "zip_path": ""}):
            code, out = self.run_cli(**kwargs)
            self.assertEqual(code, 2, kwargs)
        self.assertFalse(self.out.exists())

    def test_labeled_pairs_is_never_written(self):
        """Triggers make any write fail; no statement names the table"""
        self.run_cli()
        self.run_cli("--apply", "--all")
        self.assertFalse([sql for sql in self.executed if "labeled_pairs" in sql])
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM labeled_pairs")[0]["n"], 1)

    def test_modules_have_no_sql_for_labeled_pairs(self):
        sql = re.compile(r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM|FROM|INTO|JOIN)\s+`?labeled_pairs\b",
                         re.IGNORECASE)
        for module in ("propose_labeled_pairs.py", "build_reference_list.py",
                       "reference_sources.py"):
            source = (Path(propose_labeled_pairs.__file__).parent / module).read_text(encoding="utf-8")
            self.assertIsNone(sql.search(source), module)


class TestNameSimilarity(unittest.TestCase):

    def assertSimilarity(self, a, b, expected):
        self.assertEqual(name_similarity(a, b), expected, (a, b))
        self.assertEqual(name_similarity(b, a), expected, (b, a))   # symmetric

    def test_equal_names(self):
        self.assertSimilarity("lodash", "lodash", HIGH)
        self.assertSimilarity("Foo_Bar", "foo-bar", HIGH)
        self.assertSimilarity("Foo.Bar", "foo bar", HIGH)

    def test_whole_words_contained(self):
        self.assertSimilarity("node-lodash", "lodash", HIGH)
        self.assertSimilarity("log4j-core", "log4j", HIGH)
        self.assertSimilarity("python-six", "six", HIGH)

    def test_github_npm_and_maven_name_parts(self):
        self.assertSimilarity("django", "django/django", HIGH)
        self.assertSimilarity("@babel/core", "core", HIGH)
        self.assertSimilarity("org.x:protobuf-java", "protobuf-java", HIGH)
        self.assertSimilarity("com.google.protobuf:protobuf-java:3.25.0", "protobuf", HIGH)

    def test_substrings_that_are_not_whole_words_are_low(self):
        self.assertSimilarity("jinja2", "jinja", LOW)
        self.assertSimilarity("libxml++2.6", "com.viliussutkus89.licenseonly:libxml", LOW)
        self.assertSimilarity("re", "regex", LOW)

    def test_words_must_be_contiguous(self):
        self.assertSimilarity("a-b-c", "a-c", LOW)
        self.assertSimilarity("a-b-c", "b-c", HIGH)

    def test_unrelated_and_empty(self):
        self.assertSimilarity("requests", "flask", LOW)
        self.assertSimilarity("", "flask", LOW)


class TestNameSimilarityInOutput(ProposeTestCase):

    def test_purl2cpe_confidence_follows_similarity(self):
        self.run_cli("--apply", "--all")
        rows = self.pairs()
        [r] = self.find(rows, ("jinja2", "deb"), ("jinja", "pypi"))
        self.assertEqual((r["label"], r["source"], r["name_similarity"], r["proposed_confidence"]),
                         (MATCH, "purl2cpe", LOW, "0.5"))
        [r] = self.find(rows, ("django", "pypi"), ("django/django", "github"))
        self.assertEqual((r["name_similarity"], r["proposed_confidence"]), (HIGH, "0.95"))

    def test_other_sources_keep_their_confidence(self):
        self.run_cli("--apply")
        [r] = self.find(self.pairs(), ("bitflags", "pypi"), ("bitflags", "npm"))
        self.assertEqual((r["source"], r["name_similarity"], r["proposed_confidence"]),
                         ("same-name-different-repo", HIGH, "0.8"))
        [r] = self.find(self.pairs(), ("protobuf", "pypi"), ("google-protobuf", "npm"))
        self.assertEqual((r["name_similarity"], r["proposed_confidence"]), (HIGH, "0.9"))

    def test_high_rows_come_first(self):
        self.run_cli("--apply", "--all")
        order = [r["name_similarity"] for r in self.pairs()]
        self.assertIn(LOW, order)
        self.assertEqual(order, sorted(order, key=lambda x: x != HIGH))
        self.assertEqual(open(self.out, encoding="utf-8").readline().strip().split(","), COLUMNS)

    def test_dry_run_prints_the_counts_and_writes_nothing(self):
        code, out = self.run_cli("--all")
        self.assertEqual(code, 0)
        self.assertFalse(self.out.exists())
        self.assertRegex(out, r"Name similarity: high \d+, low [1-9]\d* \(purl2cpe: high \d+, low [1-9]")
        self.assertIn("Examples: low name similarity", out)
        self.assertIn("jinja2 (deb) ~ jinja (pypi)", out)

    def test_sampled_output_is_high_first_and_repeatable(self):
        self.run_cli("--apply", "--all", "--max-pairs", "8", "--seed", "3")
        first = self.pairs()
        self.run_cli("--apply", "--all", "--max-pairs", "8", "--seed", "3")
        self.assertEqual(self.pairs(), first)
        order = [r["name_similarity"] for r in first]
        self.assertEqual(order, sorted(order, key=lambda x: x != HIGH))


class TestRepoUrls(ProposeTestCase):
    """--repo-urls: repository URLs looked up by fetch_repo_urls.py"""

    REPO_URLS = (
        "name,ecosystem,repository_url,status\n"
        "bitflags,pypi,https://github.com/a/x,ok\n"
        "bitflags,npm,https://github.com/b/y,ok\n"
        "semver,pypi,git+https://github.com/S/Semver.git,ok\n"
        "semver,npm,https://github.com/s/semver,ok\n"
        "lodash,pypi,https://gitlab.com/l/l,non_github\n"
        "lodash,npm,https://github.com/lodash/lodash,ok\n"
        "django,pypi,,error\n"
        "django,pypi,https://github.com/django/django,ok\n"
        "django,npm,https://github.com/other/django,ok\n"
        "protobuf,npm,,not_found\n"
    )

    def setUp(self):
        super().setUp()
        self.repo_urls = self.dir / "repo_urls.csv"
        self.repo_urls.write_text(self.REPO_URLS, encoding="utf-8")

    def run_repo_urls(self, *args):
        return self.run_cli("--repo-urls", str(self.repo_urls), *args, lists="", zip_path="")

    def test_same_name_different_repository_is_a_non_match(self):
        code, _ = self.run_repo_urls("--apply")
        self.assertEqual(code, 0)
        [r] = self.find(self.pairs(), ("bitflags", "pypi"), ("bitflags", "npm"))
        self.assertEqual((r["label"], r["source"]), (NON_MATCH, "same-name-different-repo"))
        self.assertIn("github.com/a/x", r["evidence"])
        self.assertIn("github.com/b/y", r["evidence"])
        self.assertIn("(repo_urls.csv)", r["evidence"])

    def test_same_repository_after_normalizing_is_a_match(self):
        _, out = self.run_repo_urls("--apply")
        [r] = self.find(self.pairs(), ("semver", "pypi"), ("semver", "npm"))
        self.assertEqual((r["label"], r["source"]), (MATCH, "cross-eco-repo"))
        self.assertIn("same repository github.com/s/semver (repo_urls.csv)", r["evidence"])
        self.assertIn("conflicting evidence resolved: 0", out)

    def test_rows_that_are_not_ok_are_ignored(self):
        self.run_repo_urls("--apply")
        rows = self.pairs()
        self.assertEqual(self.find(rows, ("lodash", "pypi"), ("lodash", "npm")), [])
        names = {r["name_a"] for r in rows} | {r["name_b"] for r in rows}
        self.assertNotIn("protobuf", names)

    def test_last_row_per_name_wins(self):
        self.run_repo_urls("--apply")
        [r] = self.find(self.pairs(), ("django", "pypi"), ("django", "npm"))
        self.assertEqual(r["label"], NON_MATCH)

    def test_only_rows_related_to_our_packages(self):
        self.repo_urls.write_text(self.REPO_URLS + "unrelated,pypi,https://github.com/u/1,ok\n"
                                  "unrelated,npm,https://github.com/u/2,ok\n", encoding="utf-8")
        self.run_repo_urls("--apply")
        self.assertEqual(self.find(self.pairs(), ("unrelated", "pypi"), ("unrelated", "npm")), [])
        self.run_repo_urls("--apply", "--all")
        self.assertTrue(self.find(self.pairs(), ("unrelated", "pypi"), ("unrelated", "npm")))

    def test_preview_writes_nothing(self):
        code, out = self.run_repo_urls()
        self.assertEqual(code, 0)
        self.assertFalse(self.out.exists())
        self.assertIn("same-name-different-repo", out)

    def test_missing_file_exits_2(self):
        code, out = self.run_cli("--repo-urls", str(self.dir / "nope.csv"), lists="", zip_path="")
        self.assertEqual(code, 2)
        self.assertIn("repo URLs file not found", out)

    def test_combines_with_package_lists(self):
        """Package-List and repo_urls.csv rows for one name are merged, not duplicated"""
        self.run_cli("--repo-urls", str(self.repo_urls), "--apply", zip_path="")
        rows = self.find(self.pairs(), ("bitflags", "pypi"), ("bitflags", "npm"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], NON_MATCH)

    def test_labeled_pairs_is_never_written(self):
        self.run_repo_urls()
        self.run_repo_urls("--apply", "--all")
        self.assertFalse([sql for sql in self.executed if "labeled_pairs" in sql])
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM labeled_pairs")[0]["n"], 1)


if __name__ == "__main__":
    import unittest
    unittest.main()
