# sbom-tools/test_daily_pass.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# sbom-tools/daily_pass.py: exits at once when today's snapshot exists,
# takes / respects / replaces a stale lock, runs the monitor job once, exit
# code 0 only when today's snapshot exists, errors and the database being down
# are logged, and everything printed lands in logs/daily_pass_YYYY-MM-DD.log.
# The monitor job is a fake; the database is the SQLite stand-in; no network.

import contextlib
import io
import os
import sys
import tempfile
import time
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import daily_pass                                    # noqa: E402
import db_storage                                    # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402

import ui_app                                        # noqa: E402

TODAY = date(2026, 11, 6)


class DailyPassTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.logs = self.dir / "logs"
        self.lock = self.dir / "sbom_daily_pass.lock"
        self.monitor_calls = 0
        self.lock_seen = []
        self.monitor = self.snapshot_monitor
        patcher = mock.patch.object(db_storage, "get_db_storage", lambda: self.db)
        patcher.start()
        self.addCleanup(patcher.stop)

    # --- fake monitor jobs ----------------------------------------------
    def snapshot_monitor(self):
        print("monitor ran")
        self.db.write_daily_snapshot(TODAY, trigger_source="monitor")

    def offline_monitor(self):
        print("PyPI or npm is not reachable")
        self.db.record_failed_run("monitor", "offline", TODAY)

    def broken_monitor(self):
        raise RuntimeError("boom in the monitor")

    def run_pass(self):
        def monitor():
            self.monitor_calls += 1
            self.lock_seen.append(self.lock.exists())
            self.monitor()

        out = io.StringIO()
        with mock.patch.object(ui_app, "auto_monitor_versions", monitor), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = daily_pass.main([], today=TODAY, lock_path=self.lock, log_dir=self.logs)
        return code, out.getvalue()

    def log_text(self):
        return (self.logs / "daily_pass_2026-11-06.log").read_text(encoding="utf-8")


class TestDailyPass(DailyPassTestCase):

    def test_normal_pass(self):
        code, out = self.run_pass()

        self.assertEqual(code, 0)
        self.assertEqual(self.monitor_calls, 1)
        self.assertEqual(self.lock_seen, [True])                # held during the pass
        self.assertFalse(self.lock.exists())                     # and released
        log = self.log_text()
        self.assertIn("(snapshot date 2026-11-06)", log)
        self.assertIn("monitor ran", log)
        self.assertIn("Pass complete: snapshot run 1.", log)
        self.assertIn("Exit code 0", log)
        self.assertIn("monitor ran", out)                         # also on screen

    def test_already_done_exits_at_once(self):
        self.db.write_daily_snapshot(TODAY)
        code, _ = self.run_pass()
        self.assertEqual(code, 0)
        self.assertEqual(self.monitor_calls, 0)
        self.assertIn("already exists (run 1)", self.log_text())
        self.assertFalse(self.lock.exists())

    def test_second_run_the_same_day_appends_to_the_log(self):
        self.run_pass()
        self.run_pass()
        log = self.log_text()
        self.assertEqual(log.count("===== Daily pass"), 2)
        self.assertEqual(self.monitor_calls, 1)

    def test_offline_exits_1(self):
        self.monitor = self.offline_monitor
        code, _ = self.run_pass()
        self.assertEqual(code, 1)
        self.assertIn("without a snapshot for today", self.log_text())
        self.assertFalse(self.lock.exists())

    def test_error_is_logged_with_traceback(self):
        self.monitor = self.broken_monitor
        code, _ = self.run_pass()
        self.assertEqual(code, 1)
        log = self.log_text()
        self.assertIn("Traceback", log)
        self.assertIn("RuntimeError: boom in the monitor", log)
        self.assertFalse(self.lock.exists())

    def test_database_down_exits_1(self):
        def broken():
            raise ConnectionError("refused")

        with mock.patch.object(db_storage, "get_new_connection", broken):
            code, _ = self.run_pass()
        self.assertEqual(code, 1)
        self.assertEqual(self.monitor_calls, 0)
        self.assertIn("Is XAMPP MySQL running?", self.log_text())


class TestLock(DailyPassTestCase):

    def test_fresh_lock_means_another_pass_is_running(self):
        self.lock.write_text("pid 1\n", encoding="utf-8")
        code, _ = self.run_pass()
        self.assertEqual(code, 0)
        self.assertEqual(self.monitor_calls, 0)
        self.assertIn("Another pass is running", self.log_text())
        self.assertTrue(self.lock.exists())                       # someone else's: kept

    def test_stale_lock_is_replaced(self):
        self.lock.write_text("pid 1\n", encoding="utf-8")
        old = time.time() - 21 * 3600
        os.utime(self.lock, (old, old))
        code, _ = self.run_pass()
        self.assertEqual(code, 0)
        self.assertEqual(self.monitor_calls, 1)
        self.assertIn("Removed a stale lock (21.0 h old", self.log_text())
        self.assertFalse(self.lock.exists())

    def test_lock_records_the_process(self):
        taken, _ = daily_pass.take_lock(self.lock)
        self.assertTrue(taken)
        self.assertIn(f"pid {os.getpid()} started ", self.lock.read_text(encoding="utf-8"))
        self.assertEqual(daily_pass.take_lock(self.lock)[0], False)


class TestTee(unittest.TestCase):

    def test_unencodable_text_does_not_crash(self):
        class Cp1252(io.StringIO):
            encoding = "cp1252"

            def write(self, text):
                text.encode("cp1252")                            # raises like a Windows console
                return super().write(text)

        console, log = Cp1252(), io.StringIO()
        daily_pass.Tee(console, log, None).write("ok ✅\n")
        self.assertEqual(log.getvalue(), "ok ✅\n")
        self.assertEqual(console.getvalue(), "ok ?\n")


if __name__ == "__main__":
    unittest.main()
