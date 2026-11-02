# sbom-tools/test_build_seed_dataset.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# dataset/build_seed_dataset.py: one row per repo-package with the seed columns
# repeated, scan_status for scanned / no_packages / not_scanned / report_error,
# the .csv report as a fallback, (name, version, type) de-duplication, db_row
# (the database keeps the last row per package name), warning flags, preview
# writes nothing, --apply writes a BOM CSV and the notes via a temp file,
# refuses to overwrite, and the inputs are never changed. Temporary folders and
# fake reports only; MySQL and the network are patched to fail.

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = Path(TESTS_DIR).parent
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, str(PROJECT_ROOT / "dataset"))

import build_seed_dataset as bsd                     # noqa: E402

NOW = datetime(2026, 11, 6, 12, 0, 0)
SEED_COLUMNS = ["name", "url", "language", "stars", "forks", "last_push", "dependency_files"]
REPOS = ["js/scanned", "py/empty", "py/later", "js/broken"]


def url(name):
    return f"https://github.com/{name}"


def pkg(name, version, ptype="npm", vuln="None", severity="None"):
    return {"package": name, "version": version, "type": ptype, "vulnerability_id": vuln,
            "severity": severity, "fixed_version": "N/A" if vuln == "None" else "See advisory",
            "latest_version": version, "version_status": "up_to_date"}


def no_network(*args, **kwargs):
    raise AssertionError("network or database access in a file-only script")


class SeedDatasetTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.reports = self.dir / "reports"
        self.out = self.dir / "dataset"
        self.reports.mkdir()
        self.out.mkdir()
        self.seed = self.dir / "seed_v2.csv"
        with open(self.seed, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=SEED_COLUMNS)
            writer.writeheader()
            for name in REPOS:
                writer.writerow({"name": name, "url": url(name),
                                 "language": "Python" if name.startswith("py") else "JavaScript",
                                 "stars": "900", "forks": "90", "last_push": "2026-10-01",
                                 "dependency_files": "package.json"})
        self.write_report("js/scanned", [pkg("react", "18.2.0", vuln="GHSA-1", severity="High"),
                                         pkg("lodash", "4.17.21"),
                                         pkg("actions/checkout", "4", "github-action")])
        self.write_report("py/empty", [])
        (self.reports / "js-broken.json").write_text("{not json", encoding="utf-8")
        for target in ("requests.get", "requests.head", "pymysql.connect"):
            patcher = mock.patch(target, no_network)
            patcher.start()
            self.addCleanup(patcher.stop)

    def write_report(self, name, packages, **overrides):
        report = {"scan_id": name.replace("/", "-"), "timestamp": "2026-11-01T18:00:00",
                  "target": url(name),
                  "summary": {"total_packages": len(packages), "total_vulnerabilities": 1},
                  "packages": packages, "dependency_graph": []}
        report.update(overrides)
        path = self.reports / f"{name.replace('/', '-')}.json"
        path.write_text(json.dumps(report), encoding="utf-8")
        return path

    def write_csv_report(self, name, packages):
        path = self.reports / f"{name.replace('/', '-')}.csv"
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["scan_id", "target", "timestamp"]
                                    + list(pkg("x", "1")))
            writer.writeheader()
            for p in packages:
                writer.writerow({"scan_id": "x", "target": url(name),
                                 "timestamp": "2026-11-02T10:00:00", **p})
        return path

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bsd.main(["--seed-csv", str(self.seed), *argv], now=NOW,
                            reports_dir=self.reports, out_dir=self.out)
        return code, out.getvalue()

    def rows(self):
        return bsd.build(self.seed, self.reports)[0]

    def repo(self, name):
        return [r for r in self.rows() if r["name"] == name]

    def read_output(self):
        with open(self.out / bsd.OUT_CSV, encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))


class TestRows(SeedDatasetTestCase):

    def test_one_row_per_package_with_seed_columns(self):
        rows = self.repo("js/scanned")
        self.assertEqual([r["package_name"] for r in rows], ["react", "lodash", "actions/checkout"])
        for r in rows:
            self.assertEqual(r["url"], url("js/scanned"))
            self.assertEqual(r["language"], "JavaScript")
            self.assertEqual(r["stars"], "900")
            self.assertEqual(r["scan_status"], "scanned")
            self.assertEqual(r["report_source"], "json")
            self.assertEqual(r["report_file"], "js-scanned.json")
            self.assertEqual(r["report_timestamp"], "2026-11-01T18:00:00")
            self.assertEqual(r["report_total_packages"], "3")
            self.assertEqual(r["report_warning"], "")
        react = rows[0]
        self.assertEqual((react["package_version"], react["package_type"], react["ecosystem"]),
                         ("18.2.0", "npm", "npm"))
        self.assertEqual((react["vulnerability_id"], react["severity"], react["has_vulnerability"]),
                         ("GHSA-1", "High", "1"))
        self.assertEqual(rows[1]["has_vulnerability"], "0")
        self.assertEqual(rows[2]["ecosystem"], "none")
        self.assertEqual(list(react), bsd.COLUMNS)

    def test_statuses(self):
        rows, stats, _ = bsd.build(self.seed, self.reports)
        self.assertEqual(stats["repos_by_status"],
                         {"scanned": 1, "no_packages": 1, "not_scanned": 1, "report_error": 1})
        self.assertEqual(stats["rows"], 6)
        self.assertEqual(stats["package_rows"], 3)

        for name, status in (("py/empty", "no_packages"), ("py/later", "not_scanned"),
                             ("js/broken", "report_error")):
            rows = self.repo(name)
            self.assertEqual(len(rows), 1, name)
            self.assertEqual(rows[0]["scan_status"], status)
            self.assertEqual(rows[0]["name"], name)
            for column in bsd.PACKAGE_COLUMNS:
                self.assertEqual(rows[0][column], "", (name, column))
        self.assertEqual(self.repo("py/later")[0]["report_source"], "none")
        self.assertIn("js-broken.json", self.repo("js/broken")[0]["report_warning"])

    def test_csv_fallback(self):
        self.write_csv_report("js/broken", [pkg("vue", "3.4.0")])
        rows = self.repo("js/broken")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_status"], "scanned")
        self.assertEqual(rows[0]["report_source"], "csv")
        self.assertEqual(rows[0]["report_file"], "js-broken.csv")
        self.assertEqual(rows[0]["report_warning"], "from_csv")
        self.assertEqual(rows[0]["report_timestamp"], "2026-11-02T10:00:00")
        self.assertEqual(rows[0]["package_name"], "vue")

    def test_json_wins_over_csv(self):
        self.write_csv_report("js/scanned", [pkg("other", "1.0.0")])
        self.assertEqual({r["report_source"] for r in self.repo("js/scanned")}, {"json"})

    def test_empty_csv_is_no_packages(self):
        self.write_csv_report("py/later", [])
        self.assertEqual(self.repo("py/later")[0]["scan_status"], "no_packages")

    def test_duplicates_dropped_per_name_version_type(self):
        self.write_report("js/scanned", [pkg("a", "1"), pkg("a", "1"), pkg("a", "1", "python"),
                                         pkg("a", "2")], summary={"total_packages": 4})
        rows = self.repo("js/scanned")
        self.assertEqual([(r["package_version"], r["package_type"]) for r in rows],
                         [("1", "npm"), ("1", "python"), ("2", "npm")])
        self.assertEqual(rows[0]["report_warning"], "duplicates_dropped=1")
        self.assertEqual(bsd.build(self.seed, self.reports)[1]["duplicates_dropped"], 1)

    def test_db_row_keeps_the_last_name_case_insensitively(self):
        self.write_report("js/scanned", [pkg("React", "17.0.0"), pkg("lodash", "4"),
                                         pkg("react", "18.2.0")])
        rows = self.repo("js/scanned")
        self.assertEqual([r["db_row"] for r in rows], ["collapsed", "kept", "kept"])
        self.assertEqual(bsd.build(self.seed, self.reports)[1]["db_kept_rows"], 2)

    def test_ecosystem_rule(self):
        for ptype, eco in (("python", "python"), ("pypi", "python"), ("npm", "npm"),
                           ("node", "npm"), ("go-module", "none"), ("", "none"), (None, "none")):
            self.assertEqual(bsd.db_ecosystem(ptype), eco, ptype)

    def test_count_and_target_mismatch(self):
        self.write_report("js/scanned", [pkg("a", "1")], target=url("someone/else"),
                          summary={"total_packages": 5})
        self.assertEqual(self.repo("js/scanned")[0]["report_warning"],
                         "count_mismatch;target_mismatch")

    def test_target_compare_ignores_git_suffix_slash_and_case(self):
        self.write_report("js/scanned", [pkg("a", "1")], target=url("JS/Scanned") + ".git/")
        self.assertEqual(self.repo("js/scanned")[0]["report_warning"], "")

    def test_report_name_is_the_scanner_file_name(self):
        self.assertEqual(bsd.report_name("https://github.com/0xPolygon/matic.js"),
                         "0xPolygon-matic.js")


class TestCli(SeedDatasetTestCase):

    def test_preview_writes_nothing(self):
        code, out = self.run_main("--show", "2")
        self.assertEqual(code, 0)
        self.assertEqual(list(self.out.iterdir()), [])
        self.assertIn("4 repos; scanned 1, no_packages 1, not_scanned 1, report_error 1", out)
        self.assertIn("Rows: 6 (3 package rows", out)
        self.assertIn("First 2 rows", out)
        self.assertIn("js/scanned | scanned | react | 18.2.0 | npm", out)
        self.assertIn("| lodash |", out)
        self.assertNotIn("| actions/checkout |", out)                    # row 3 not shown
        self.assertIn("Warning: js/broken:", out)
        self.assertIn("Preview only", out)

    def test_apply_writes_csv_with_bom_and_notes(self):
        code, out = self.run_main("--apply")
        self.assertEqual(code, 0)
        raw = (self.out / bsd.OUT_CSV).read_bytes()
        self.assertTrue(raw.startswith(b"\xef\xbb\xbf"))
        self.assertEqual(self.read_output(), self.rows())

        notes = json.loads((self.out / bsd.OUT_NOTES).read_text(encoding="utf-8"))
        self.assertEqual(notes["created_at"], "2026-11-06T12:00:00")
        self.assertEqual(notes["counts"]["repos_by_status"]["scanned"], 1)
        self.assertEqual(notes["counts"]["rows"], 6)
        self.assertEqual(notes["columns"], bsd.COLUMNS)
        self.assertEqual(notes["seed_csv"]["bytes"], self.seed.stat().st_size)
        self.assertEqual(len(notes["seed_csv"]["sha256"]), 64)
        self.assertTrue(any("db_row = kept" in rule for rule in notes["rules"]))
        self.assertEqual([w["name"] for w in notes["repos_with_warnings"]], ["js/broken"])
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         sorted([bsd.OUT_CSV, bsd.OUT_NOTES]))           # no temp files left

    def test_refuses_to_overwrite(self):
        for name in (bsd.OUT_CSV, bsd.OUT_NOTES):
            (self.out / name).write_text("old", encoding="utf-8")
            code, out = self.run_main("--apply")
            self.assertEqual(code, 2)
            self.assertIn("--overwrite", out)
            (self.out / name).unlink()
        (self.out / bsd.OUT_NOTES).write_text("old", encoding="utf-8")
        self.run_main("--apply")
        self.assertFalse((self.out / bsd.OUT_CSV).exists())             # nothing written at all

    def test_overwrite_replaces(self):
        (self.out / bsd.OUT_CSV).write_text("old", encoding="utf-8")
        (self.out / bsd.OUT_NOTES).write_text("old", encoding="utf-8")
        code, _ = self.run_main("--apply", "--overwrite")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.read_output()), 6)

    def test_failed_write_keeps_the_old_file(self):
        target = self.out / bsd.OUT_CSV
        target.write_text("old", encoding="utf-8")

        def broken(f):
            f.write("half")
            raise RuntimeError("disk full")

        with self.assertRaises(RuntimeError):
            bsd.write_atomic(target, broken, "utf-8-sig")
        self.assertEqual(target.read_text(encoding="utf-8"), "old")
        self.assertEqual([p.name for p in self.out.iterdir()], [bsd.OUT_CSV])

    def test_inputs_are_not_changed(self):
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                  for p in [self.seed, *self.reports.iterdir()]}
        self.run_main()
        self.run_main("--apply")
        after = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                 for p in [self.seed, *self.reports.iterdir()]}
        self.assertEqual(before, after)

    def test_missing_seed_csv(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bsd.main(["--seed-csv", str(self.dir / "missing.csv")],
                            reports_dir=self.reports, out_dir=self.out)
        self.assertEqual(code, 2)
        self.assertIn("cannot read the seed list", out.getvalue())


if __name__ == "__main__":
    unittest.main()
