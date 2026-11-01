# sbom-tools/test_scan_seed_list.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# dataset/scan_seed_list.py: which repos are done / pending / incomplete
# (report AND database rows), preview writes nothing, resuming, --limit with
# Python / JS-TS alternating, scanner settings, one log line per repo, failures
# don't stop the run, a repo-cache folder without .git stops it before any git
# command, and the bundled tools go on PATH. SBOMScanner is a fake (no git,
# Syft, Grype or network); the database is the SQLite stand-in.

import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = Path(TESTS_DIR).parent
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, str(PROJECT_ROOT / "dataset"))

import db_storage                                    # noqa: E402
import sbom                                          # noqa: E402
import scan_seed_list                                # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402

TODAY = date(2026, 11, 5)
SEED_COLUMNS = ["name", "url", "language", "stars", "forks", "last_push", "dependency_files"]
# CSV order: Python first, like seed_v2.csv
REPOS = [("py/a", "Python"), ("py/b", "Python"), ("py/c", "Python"),
         ("js/d", "JavaScript"), ("ts/e", "TypeScript"), ("js/f", "JavaScript")]


def url(name):
    return f"https://github.com/{name}"


class FakeClock:
    def __init__(self):
        self.now = 50.0

    def monotonic(self):
        return self.now


class SeedScanTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.reports = self.dir / "reports"
        self.cache = self.dir / "repo-cache"
        self.logs = self.dir / "logs"
        self.reports.mkdir()
        self.cache.mkdir()
        self.seed = self.dir / "seed_v2.csv"
        with open(self.seed, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=SEED_COLUMNS)
            writer.writeheader()
            for name, language in REPOS:
                writer.writerow({"name": name, "url": url(name), "language": language,
                                 "stars": "900", "forks": "90", "last_push": "2026-10-01",
                                 "dependency_files": "x"})
        self.clock = FakeClock()
        self.scanned = []
        self.behaviour = {}          # url -> "fail" | "no_db" | "interrupt"
        self.instances = []

        test = self

        class FakeScanner:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
                test.instances.append(self)

            def scan(self, target):
                test.scanned.append(target)
                test.clock.now += 12.5
                behaviour = test.behaviour.get(target)
                if behaviour == "fail":
                    raise RuntimeError("Failed to clone repository x\nfatal: not found")
                if behaviour == "interrupt":
                    raise KeyboardInterrupt
                test.write_report(target, ["requests", "urllib3", "Requests"])
                if behaviour != "no_db":
                    test.write_db_rows(target, ["requests", "urllib3"])

        self.FakeScanner = FakeScanner
        for patcher in (
            mock.patch.dict(os.environ, {"PATH": r"C:\Windows"}),
            mock.patch.object(sbom.Config, "SYFT_PATH", sbom.Config.SYFT_PATH),
            mock.patch.object(sbom.Config, "GRYPE_PATH", sbom.Config.GRYPE_PATH),
            mock.patch.object(sbom.Config, "init_directories", lambda: None),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    # --- the effects of a real scan -----------------------------------
    def write_report(self, target, names):
        name = sbom.generate_safe_filename(target, True)
        report = {"summary": {"total_packages": len(names)},
                  "packages": [{"package": n, "version": "1.0"} for n in names]}
        (self.reports / f"{name}.json").write_text(json.dumps(report), encoding="utf-8")

    def write_db_rows(self, target, names):
        cur = self.sqlite.execute("INSERT INTO scan (target_name) VALUES (?)", (target,))
        self.sqlite.executemany(
            "INSERT INTO versions (scan_id, package_name, version_number) VALUES (?, ?, '1.0')",
            [(cur.lastrowid, n) for n in names])
        self.sqlite.commit()

    def mark_done(self, name):
        self.write_report(url(name), ["requests"])
        self.write_db_rows(url(name), ["requests"])

    def run_cli(self, *args):
        argv = ["--seed-csv", str(self.seed), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = scan_seed_list.main(argv, scanner_class=self.FakeScanner,
                                       clock=self.clock.monotonic, reports_dir=self.reports,
                                       cache_dir=self.cache, log_dir=self.logs, today=TODAY)
        return code, out.getvalue()

    def log_text(self):
        return (self.logs / "scan_seed_list_2026-11-05.log").read_text(encoding="utf-8")


# ============================================================
# Preview and state
# ============================================================
class TestPreview(SeedScanTestCase):

    def test_states_and_nothing_written(self):
        self.mark_done("py/a")
        self.write_report(url("py/b"), ["requests"])            # report but no rows: incomplete
        code, out = self.run_cli()

        self.assertEqual(code, 0)
        self.assertIn("6 repos; done 1, pending 5 (of which 1 incomplete", out)
        self.assertRegex(out, r"Already done:\n  py/a\n")
        listed = re.findall(r"^  (\S+)\s+\S+\s+(pending|incomplete)$", out, re.M)
        self.assertEqual(listed, [("py/b", "incomplete"), ("js/d", "pending"),
                                  ("py/c", "pending"), ("ts/e", "pending"), ("js/f", "pending")])
        self.assertIn("Nothing was scanned or written", out)
        self.assertEqual(self.instances, [])
        self.assertFalse(self.logs.exists())

    def test_fewer_rows_than_report_names_is_incomplete(self):
        self.write_report(url("py/a"), ["requests", "urllib3"])
        self.write_db_rows(url("py/a"), ["requests"])
        _, out = self.run_cli()
        self.assertIn("done 0, pending 6 (of which 1 incomplete", out)

    def test_names_compare_without_case(self):
        """Requests and requests are one MySQL row"""
        self.write_report(url("py/a"), ["Requests", "requests"])
        self.write_db_rows(url("py/a"), ["requests"])
        _, out = self.run_cli()
        self.assertIn("done 1,", out)

    def test_warns_about_empty_cache_folders(self):
        (self.cache / "js-d").mkdir()
        _, out = self.run_cli()
        self.assertIn("js-d has no .git", out)

    def test_database_unreachable_exits_2(self):
        def broken():
            raise ConnectionError("refused")

        with mock.patch.object(db_storage, "get_new_connection", broken):
            code, out = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("database not reachable", out)


# ============================================================
# Scanning
# ============================================================
class TestApply(SeedScanTestCase):

    def test_scans_pending_alternating_and_logs_each(self):
        self.mark_done("py/a")
        code, out = self.run_cli("--apply")

        self.assertEqual(code, 0)
        self.assertEqual(self.scanned, [url(n) for n in ("py/b", "js/d", "py/c", "ts/e", "js/f")])
        self.assertIn("[1/5] py/b: ok, 3 packages, 12.5 s", out)
        self.assertIn("Scan finished: ok 5, failed 0, db_incomplete 0; still pending 0", out)
        log = self.log_text()
        self.assertEqual(len(re.findall(r"^\[\d/5\] ", log, re.M)), 5)

    def test_scanner_settings(self):
        self.run_cli("--apply", "--limit", "1")
        self.assertEqual(self.instances[0].kwargs,
                         {"use_cache": True, "shallow_clone": True, "skip_vuln": False})

    def test_limit_takes_both_languages(self):
        code, _ = self.run_cli("--apply", "--limit", "2")
        self.assertEqual(code, 0)
        self.assertEqual(self.scanned, [url("py/a"), url("js/d")])

    def test_resume_skips_done_repos(self):
        self.run_cli("--apply", "--limit", "2")
        self.scanned.clear()
        self.run_cli("--apply")
        self.assertEqual(self.scanned, [url(n) for n in ("py/b", "ts/e", "py/c", "js/f")])
        _, out = self.run_cli()
        self.assertIn("done 6, pending 0", out)

    def test_failure_is_logged_and_the_run_continues(self):
        self.behaviour[url("py/b")] = "fail"
        code, out = self.run_cli("--apply")

        self.assertEqual(code, 1)
        self.assertEqual(len(self.scanned), 6)
        self.assertIn("py/b: failed (RuntimeError: Failed to clone repository x), 12.5 s", out)
        self.assertIn("ok 5, failed 1", out)
        _, out = self.run_cli()
        self.assertIn("done 5, pending 1", out)

    def test_report_without_database_rows_is_db_incomplete(self):
        self.behaviour[url("ts/e")] = "no_db"
        code, out = self.run_cli("--apply")
        self.assertEqual(code, 1)
        self.assertIn("ts/e: db_incomplete (3 packages in the report)", out)
        self.scanned.clear()
        self.behaviour.clear()
        self.run_cli("--apply")
        self.assertEqual(self.scanned, [url("ts/e")])            # scanned again

    def test_interrupt_stops_after_logging(self):
        self.behaviour[url("js/d")] = "interrupt"
        code, out = self.run_cli("--apply")
        self.assertEqual(code, 130)
        self.assertIn("Interrupted after 1 of 6 repos.", self.log_text())

    def test_nothing_pending(self):
        for name, _ in REPOS:
            self.mark_done(name)
        code, out = self.run_cli("--apply")
        self.assertEqual(code, 0)
        self.assertIn("Nothing to scan.", out)
        self.assertEqual(self.instances, [])


class TestCacheFolderSafety(SeedScanTestCase):

    def test_empty_cache_folder_stops_before_any_scan(self):
        (self.cache / "js-d").mkdir()
        code, out = self.run_cli("--apply")

        self.assertEqual(code, 2)
        self.assertEqual(self.scanned, [])
        self.assertEqual(self.instances, [])
        self.assertIn("project repository", out)
        self.assertIn("js-d", out)

    def test_folder_with_git_is_fine(self):
        (self.cache / "js-d" / ".git").mkdir(parents=True)
        code, _ = self.run_cli("--apply")
        self.assertEqual(code, 0)
        self.assertIn(url("js/d"), self.scanned)

    def test_only_repos_about_to_be_scanned_are_checked(self):
        (self.cache / "js-f").mkdir()                        # not in the first 2
        code, _ = self.run_cli("--apply", "--limit", "2")
        self.assertEqual(code, 0)

    def test_folder_appearing_during_the_run_stops_it(self):
        test = self
        real_scan = self.FakeScanner.scan

        def scan_then_leave_empty_folder(scanner, target):
            real_scan(scanner, target)
            (test.cache / "js-d").mkdir(exist_ok=True)

        with mock.patch.object(self.FakeScanner, "scan", scan_then_leave_empty_folder):
            code, out = self.run_cli("--apply")
        self.assertEqual(code, 2)
        self.assertEqual(self.scanned, [url("py/a")])
        self.assertIn("[2/6] js/d: stopped", out)


class TestTools(SeedScanTestCase):

    def test_bundled_tools_first_on_path_only_with_apply(self):
        self.run_cli()
        self.assertEqual(os.environ["PATH"], r"C:\Windows")

        self.run_cli("--apply", "--limit", "1")
        parts = os.environ["PATH"].split(os.pathsep)
        self.assertEqual(parts[:3], [str(scan_seed_list.SYFT.parent),
                                     str(scan_seed_list.GRYPE.parent), r"C:\Windows"])
        self.assertEqual((sbom.Config.SYFT_PATH, sbom.Config.GRYPE_PATH),
                         (scan_seed_list.SYFT, scan_seed_list.GRYPE))

    def test_missing_tool_exits_2(self):
        with mock.patch.object(scan_seed_list, "GRYPE", self.dir / "nope.exe"):
            code, out = self.run_cli("--apply")
        self.assertEqual(code, 2)
        self.assertIn("bundled tool not found", out)
        self.assertEqual(self.scanned, [])

    def test_bulk_scan_is_not_used(self):
        source = Path(scan_seed_list.__file__).read_text(encoding="utf-8")
        self.assertNotIn("bulk_scan", source)


if __name__ == "__main__":
    unittest.main()
