# sbom-tools/test_evaluate_matcher.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# evaluate_matcher.py: which pairs are evaluable, the two views and their
# counts / agreement rates, the groups, disagreements, the limits text, the
# output rules (only inside data-prep/) and that no database is used.
# Small fixture files in a temp folder; no network, no database.

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

import pymysql                                       # noqa: E402

import db_storage                                    # noqa: E402
import evaluate_matcher                              # noqa: E402
from evaluate_matcher import (                       # noqa: E402
    HEADING, LOOSE, STRICT, confusion, evaluate_row, fmt_rate,
)

HEADER = "name_a,ecosystem_a,name_b,ecosystem_b,label,source,name_similarity\n"
# Every cell of the two confusion tables is known:
#   1 requests ~ requests (pypi, pypi)  match      -> matched   strict TP, loose TP
#   2 semver ~ semver (pypi, npm)       match      -> review    strict FN, loose TP
#   3 bitflags ~ bitflags (pypi, npm)   non-match  -> review    strict TN, loose FP
#   4 flask ~ django (pypi, pypi)       match      -> unmatched FN in both views
#   8 xyzzy ~ xyzzy (python, pypi)      match      -> matched   TP in both (python = pypi)
FIXTURE = HEADER + (
    "requests,pypi,requests,pypi,match,purl2cpe,high\n"
    "semver,pypi,semver,npm,match,cross-eco-repo,high\n"
    "bitflags,pypi,bitflags,npm,non-match,same-name-different-repo,high\n"
    "flask,pypi,django,pypi,match,purl2cpe,low\n"
    "django,pypi,django/django,github,match,purl2cpe,high\n"
    "lodash,npm,lodash,cpe,match,purl2cpe,high\n"
    "node-lodash,deb,lodash,cpe,match,purl2cpe,high\n"
    "xyzzy,python,xyzzy,pypi,match,purl2cpe,\n"
    "a,,b,pypi,match,purl2cpe,high\n"
)


def row(a, ea, b, eb, label="match", source="purl2cpe", sim="high"):
    return {"name_a": a, "ecosystem_a": ea, "name_b": b, "ecosystem_b": eb,
            "label": label, "source": source, "name_similarity": sim}


class TestEvaluateRow(unittest.TestCase):

    def test_unsupported_identifier_types_are_not_evaluable(self):
        for ea, eb, why in (("pypi", "github", "github"), ("npm", "cpe", "cpe"),
                            ("deb", "cpe", "cpe+deb"), ("docker", "pypi", "docker")):
            r = evaluate_row(row("x", ea, "y", eb))
            self.assertFalse(r["evaluable"])
            self.assertEqual(r["not_evaluable_reason"],
                             f"identifier type not handled by name_match: {why}")
            self.assertEqual(r["status"], "")

    def test_missing_ecosystem(self):
        self.assertEqual(evaluate_row(row("a", "", "b", "pypi"))["not_evaluable_reason"],
                         "missing ecosystem")

    def test_pypi_npm_maven_are_evaluated(self):
        r = evaluate_row(row("requests", "pypi", "requests", "pypi"))
        self.assertEqual((r["evaluable"], r["relation"], r["match_type"], r["status"]),
                         (True, "same-ecosystem", "exact", "matched"))
        r = evaluate_row(row("org.x:lib", "maven", "lib", "maven"))
        self.assertEqual((r["evaluable"], r["match_type"]), (True, "scope_stripped"))

    def test_python_spelling_counts_as_pypi(self):
        r = evaluate_row(row("xyzzy", "python", "xyzzy", "pypi"))
        self.assertEqual((r["evaluable"], r["relation"]), (True, "same-ecosystem"))

    def test_agreement_columns(self):
        r = evaluate_row(row("semver", "pypi", "semver", "npm"))           # review
        self.assertEqual((r["status"], r["agrees_matched_only"], r["agrees_matched_or_review"]),
                         ("review", False, True))
        r = evaluate_row(row("bitflags", "pypi", "bitflags", "npm", label="non-match"))
        self.assertEqual((r["agrees_matched_only"], r["agrees_matched_or_review"]), (True, False))


class TestNumbers(unittest.TestCase):

    def setUp(self):
        self.rows = [evaluate_row(r) for r in csv.DictReader(io.StringIO(FIXTURE))]
        self.evaluable = [r for r in self.rows if r["evaluable"]]

    def test_evaluable_split(self):
        self.assertEqual(len(self.evaluable), 5)
        self.assertEqual(len(self.rows) - len(self.evaluable), 4)

    def test_strict_view(self):
        c = confusion(self.evaluable, STRICT)
        self.assertEqual((c["TP"], c["FP"], c["FN"], c["TN"]), (2, 0, 2, 1))
        self.assertEqual((c["precision_like"], c["recall_like"], c["non_match_agreement"]),
                         (1.0, 0.5, 1.0))

    def test_loose_view(self):
        c = confusion(self.evaluable, LOOSE)
        self.assertEqual((c["TP"], c["FP"], c["FN"], c["TN"]), (3, 1, 1, 0))
        self.assertEqual((c["precision_like"], c["recall_like"], c["non_match_agreement"]),
                         (0.75, 0.75, 0.0))

    def test_zero_denominator_is_na(self):
        only_non_matches = [r for r in self.evaluable if r["proposed_label"] == "non-match"]
        c = confusion(only_non_matches, STRICT)
        self.assertIsNone(c["precision_like"])
        self.assertIsNone(c["recall_like"])
        self.assertEqual(fmt_rate(None), "n/a")
        self.assertEqual(fmt_rate(0.021), "2.1%")


# ============================================================
# CLI with a temp data-prep folder
# ============================================================
class CliTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.data_prep = self.root / "data-prep"
        self.data_prep.mkdir()
        self.review = self.data_prep / "labeled_pairs_review.csv"
        self.review.write_text(FIXTURE, encoding="utf-8")

        def no_database(*args, **kwargs):
            raise AssertionError("the database must not be used")

        for patcher in (
            mock.patch.object(evaluate_matcher, "DATA_PREP", self.data_prep),
            mock.patch.object(pymysql, "connect", no_database),
            mock.patch.object(db_storage, "get_db_storage", no_database),
            mock.patch.object(db_storage, "get_new_connection", no_database),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = evaluate_matcher.main(list(args))
        return code, out.getvalue()

    def files(self):
        return sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*") if p.is_file())


class TestReport(CliTestCase):

    def test_limits_come_first(self):
        _, out = self.run_cli()
        self.assertTrue(out.startswith("LIMITS (read before the numbers):"))
        self.assertIn("PROPOSALS", out.split("Pairs:")[0])
        self.assertIn("partly circular", out.split("Pairs:")[0])
        # github, cpe, cpe+deb and the missing-ecosystem row
        self.assertIn("4 of 8 proposed matches are not evaluable", out)

    def test_every_table_is_labelled_as_agreement(self):
        _, out = self.run_cli()
        tables = [line for line in out.splitlines() if line.startswith("AGREEMENT")]
        self.assertEqual(len(tables), 4)                  # all + relation + source + similarity
        self.assertTrue(all(line.startswith(HEADING) for line in tables))
        self.assertNotIn("true precision:", out.lower())

    def test_counts_and_rates_on_screen(self):
        _, out = self.run_cli()
        self.assertIn("Pairs: 9; evaluable: 5; not evaluable: 4", out)
        self.assertIn("TP 2  FP 0  FN 2  TN 1  | precision-like 100.0%  recall-like 50.0%", out)
        self.assertIn("TP 3  FP 1  FN 1  TN 0  | precision-like 75.0%  recall-like 75.0%", out)

    def test_not_evaluable_reasons(self):
        _, out = self.run_cli()
        for why in ("github", "cpe", "cpe+deb"):
            self.assertRegex(out, rf"not evaluable:\s+1\s+identifier type not handled by name_match: {re.escape(why)}\n")
        self.assertIn("missing ecosystem", out)

    def test_groups(self):
        _, out = self.run_cli()
        self.assertIn("relation = same-ecosystem  (n=3)", out)
        self.assertIn("relation = cross-ecosystem  (n=2)", out)
        self.assertIn("source = same-name-different-repo  (n=1)", out)
        self.assertIn("name_similarity = missing  (n=1)", out)
        self.assertIn("name_similarity = low  (n=1)", out)
        group = out.split("source = same-name-different-repo")[1].split("source =")[0]
        self.assertIn("precision-like n/a", group)        # only a non-match, strict view
        self.assertIn("recall-like n/a", group)

    def test_disagreements_with_reasons_matches_first(self):
        _, out = self.run_cli()
        section = out.split("Disagreements (in at least one view): 3")[1]
        lines = [l for l in section.splitlines() if l.startswith("  proposed")]
        self.assertEqual(len(lines), 3)                   # semver, flask (matches), bitflags
        self.assertTrue(lines[0].startswith("  proposed match:"))
        self.assertTrue(lines[-1].startswith("  proposed non-match: bitflags"))
        self.assertIn("ecosystem differs (pypi vs npm)", section)

    def test_examples_limit_the_screen_not_the_csv(self):
        _, out = self.run_cli("--examples", "1")
        self.assertIn("Disagreements (in at least one view): 3, showing 1", out)
        with open(self.data_prep / "matcher_evaluation.csv", encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), 9)
        disagree = [r for r in rows if r["evaluable"] == "True"
                    and "False" in (r["agrees_matched_only"], r["agrees_matched_or_review"])]
        self.assertEqual(len(disagree), 3)


class TestOutputRules(CliTestCase):

    def test_default_writes_only_the_csv_in_data_prep(self):
        before = self.files()
        code, out = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(sorted(set(self.files()) - set(before)),
                         [str(Path("data-prep") / "matcher_evaluation.csv")])
        with open(self.data_prep / "matcher_evaluation.csv", encoding="utf-8") as f:
            self.assertEqual(f.readline().strip().split(","), evaluate_matcher.OUT_COLUMNS)

    def test_out_empty_writes_nothing(self):
        before = self.files()
        code, _ = self.run_cli("--out", "")
        self.assertEqual(code, 0)
        self.assertEqual(self.files(), before)

    def test_out_inside_data_prep_is_allowed(self):
        code, _ = self.run_cli("--out", str(self.data_prep / "sub" / ".." / "eval2.csv"))
        self.assertEqual(code, 0)
        self.assertTrue((self.data_prep / "eval2.csv").is_file())

    def test_out_outside_data_prep_is_refused(self):
        before = self.files()
        for path in (self.root / "elsewhere.csv", self.data_prep / ".." / "escape.csv",
                     Path(tempfile.gettempdir()) / "x.csv"):
            code, out = self.run_cli("--out", str(path))
            self.assertEqual(code, 2, path)
            self.assertIn("must be inside", out)
        self.assertEqual(self.files(), before)

    def test_missing_review_csv_exits_2(self):
        code, out = self.run_cli("--review-csv", str(self.data_prep / "nope.csv"))
        self.assertEqual(code, 2)
        self.assertFalse((self.data_prep / "matcher_evaluation.csv").exists())


class TestNoDatabase(unittest.TestCase):

    SOURCE = Path(evaluate_matcher.__file__).read_text(encoding="utf-8")

    def test_no_sql_for_labeled_pairs(self):
        sql = re.compile(r"(INSERT\s+INTO|UPDATE|DELETE\s+FROM|FROM|INTO|JOIN)\s+`?labeled_pairs\b",
                         re.IGNORECASE)
        self.assertIsNone(sql.search(self.SOURCE))

    def test_no_database_import(self):
        self.assertIsNone(re.search(r"^\s*(import|from)\s+(db_storage|pymysql)\b", self.SOURCE,
                                    re.MULTILINE))


if __name__ == "__main__":
    unittest.main()
