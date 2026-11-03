# sbom-tools/test_fake_snapshot_days.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# sbom-tools/fake_snapshot_days.py (test data for the copy database only):
# refuses any database but sbom_test_copy before connecting, refuses a
# connection to another database, a copy that already has fake days and dates
# that overlap real snapshots; the in-memory guard blocks other databases and
# is undone afterwards; preview writes nothing; --apply writes one fake_test
# run per day with tier, risk and review changes between days, through the real
# db_storage functions (so a changed signature fails here). SQLite stand-in.

import contextlib
import io
import os
import sys
import unittest
from datetime import date
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)

import db_storage                                    # noqa: E402
import fake_snapshot_days as fsd                     # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402

COPY = "sbom_test_copy"


class FakeDaysTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        rows = [(1, "https://github.com/a/one"), (2, "https://github.com/b/two")]
        self.sqlite.executemany("INSERT INTO scan (scan_id, target_name) VALUES (?, ?)", rows)
        for pid in range(1, 41):
            self.sqlite.execute("INSERT INTO packages (package_id, package_name, ecosystem) "
                                "VALUES (?, ?, 'npm')", (pid, f"pkg{pid}"))
        vid = 100
        for scan_id in (1, 2):
            for pid in range(1, 41):
                tier = "Fresh" if pid <= 25 else "Aging" if pid <= 35 else "Stale"
                self.sqlite.execute(
                    "INSERT INTO versions (version_id, scan_id, package_id, package_name, "
                    "version_number, status, age_tier, days_outdated) "
                    "VALUES (?, ?, ?, ?, '1.0', 'outdated', ?, 100)",
                    (vid, scan_id, pid, f"pkg{pid}", tier))
                vid += 1
        self.sqlite.commit()
        self.database = COPY
        for patcher in (
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(fsd, "current_database", lambda: self.database),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fsd.main(list(argv))
        return code, out.getvalue()

    def runs(self):
        return self.rows("SELECT run_id, snapshot_date, status, trigger_source, package_count "
                         "FROM scan_runs ORDER BY snapshot_date")


class TestRefusals(FakeDaysTestCase):

    def test_other_database_refused_before_connecting(self):
        def no_connection():
            raise AssertionError("connected although the database was refused")

        for name in ("sbom_common", "sbom_test_copy2", ""):
            with mock.patch.object(db_storage, "get_new_connection", no_connection):
                code, out = self.run_main("--database", name, "--apply")
            self.assertEqual(code, 2, name)
            self.assertIn("Refused: --database must be one of ['sbom_test_copy']", out)
        self.assertEqual(db_storage.DB_CONFIG["database"], "sbom_common")
        self.assertEqual(self.runs(), [])

    def test_connected_to_another_database(self):
        self.database = "sbom_common"
        code, out = self.run_main("--database", COPY, "--apply")
        self.assertEqual(code, 2)
        self.assertIn("Refused: connected to 'sbom_common', not 'sbom_test_copy'.", out)
        self.assertEqual(self.runs(), [])

    def test_runs_once_per_copy(self):
        self.db.write_daily_snapshot(date(2026, 9, 1), trigger_source="fake_test")
        code, out = self.run_main("--database", COPY, "--apply", "--start", "2026-08-01")
        self.assertEqual(code, 2)
        self.assertIn("already has fake_test runs", out)
        self.assertEqual(len(self.runs()), 1)

    def test_dates_must_be_before_real_snapshots(self):
        self.db.write_daily_snapshot(date(2026, 10, 3))
        code, out = self.run_main("--database", COPY, "--apply", "--start", "2026-10-01")
        self.assertEqual(code, 2)
        self.assertIn("must be before the earliest snapshot date 2026-10-03", out)
        self.assertEqual(len(self.runs()), 1)

    def test_guard_blocks_other_databases_and_is_undone(self):
        real = db_storage.pymysql.connect
        undo = fsd.install_guard(COPY)
        try:
            self.assertEqual(db_storage.DB_CONFIG["database"], COPY)
            with self.assertRaises(RuntimeError):
                db_storage.pymysql.connect(database="sbom_common")
        finally:
            undo()
        self.assertIs(db_storage.pymysql.connect, real)
        self.assertEqual(db_storage.DB_CONFIG["database"], "sbom_common")

    def test_guard_is_undone_after_main(self):
        real = db_storage.pymysql.connect
        self.run_main("--database", COPY)
        self.assertIs(db_storage.pymysql.connect, real)
        self.assertEqual(db_storage.DB_CONFIG["database"], "sbom_common")


class TestFakeDays(FakeDaysTestCase):

    def test_preview_writes_nothing(self):
        before = self.rows("SELECT version_id, age_tier FROM versions ORDER BY version_id")
        code, out = self.run_main("--database", COPY)
        self.assertEqual(code, 0)
        self.assertIn("40 packages; fake days 2026-10-01 .. 2026-10-05 (5)", out)
        self.assertIn("Preview only", out)
        self.assertEqual(self.runs(), [])
        self.assertEqual(self.rows("SELECT version_id, age_tier FROM versions "
                                   "ORDER BY version_id"), before)

    def test_apply_writes_changing_days(self):
        code, out = self.run_main("--database", COPY, "--apply", "--days", "3")
        self.assertEqual(code, 0, out)
        runs = self.runs()
        self.assertEqual([(r["snapshot_date"], r["status"], r["trigger_source"], r["package_count"])
                          for r in runs],
                         [("2026-10-01", "completed", "fake_test", 80),
                          ("2026-10-02", "completed", "fake_test", 80),
                          ("2026-10-03", "completed", "fake_test", 80)])

        def tiers(run_id):
            return {r["age_tier"]: r["n"] for r in self.rows(
                "SELECT age_tier, COUNT(*) AS n FROM package_snapshots WHERE run_id = ? "
                "GROUP BY age_tier", (run_id,))}

        day1, day2 = tiers(runs[0]["run_id"]), tiers(runs[1]["run_id"])
        self.assertEqual(day1, {"Fresh": 50, "Aging": 20, "Stale": 10})
        # Aging -> Stale first (all 20 Aging rows), then Fresh -> Aging (all 50 Fresh rows)
        self.assertEqual(day2, {"Aging": 50, "Stale": 30})

        history = self.rows("SELECT reviewer, note, new_status FROM package_review_history")
        self.assertEqual(len(history), 2 * fsd.REVIEWS_PER_DAY)
        self.assertEqual({h["reviewer"] for h in history}, {"fake-test"})
        self.assertNotIn("Open", {h["new_status"] for h in history})
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM packages WHERE risk_level IS NULL"),
                         [{"n": 0}])                               # risk recomputed
        self.assertIn("2026-10-02: Aging->Stale 20, Fresh->Aging 50, 20 reviews; snapshot run", out)


if __name__ == "__main__":
    unittest.main()
