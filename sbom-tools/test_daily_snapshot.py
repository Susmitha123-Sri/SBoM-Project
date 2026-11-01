# sbom-tools/test_daily_snapshot.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Daily snapshots and the monitor job around them: write_daily_snapshot()
# copies one row per versions row (repo + package), at most once per date,
# completed / partial / failed runs; the monitor job empties the version
# caches, records an offline run and refreshes nothing when PyPI or npm is
# unreachable, then snapshots after the refresh; migration 004 and its
# rollback; the write_snapshot.py CLI. No MySQL (SQLite stand-in, see
# fake_mysql.py) and no network: any unexpected HTTP call fails the test.

import contextlib
import io
import os
import re
import sqlite3
import sys
import unittest
from collections import Counter
from datetime import date
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = Path(TESTS_DIR).parent
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, str(PROJECT_ROOT))   # project root, for ui_app

import requests                                      # noqa: E402

import db_storage                                    # noqa: E402
import fake_mysql                                    # noqa: E402
import version_monitor                               # noqa: E402
import write_snapshot                                # noqa: E402
from db_storage import DatabaseStorage               # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402

import ui_app                                        # noqa: E402

DAY1, DAY2 = date(2026, 11, 3), date(2026, 11, 4)
MIGRATION = PROJECT_ROOT / "migrations" / "004_snapshot_per_version.sql"
ROLLBACK = PROJECT_ROOT / "migrations" / "004_rollback.sql"


def no_http(url, *args, **kwargs):
    raise AssertionError(f"unexpected HTTP request: {url}")


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


class SnapshotTestCase(SqliteTestCase):
    """
    Two repos (scans 1 and 2): requests in both at different versions,
    lodash in repo 2 with two vulnerabilities and a review, and one row
    without a package_id.
    """

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("""
            INSERT INTO scan (scan_id, target_name) VALUES
                (1, 'https://github.com/a/one'), (2, 'https://github.com/b/two');
            INSERT INTO packages (package_id, package_name, ecosystem, risk_score,
                                  risk_level, priority_rank) VALUES
                (1, 'requests', 'python', 40, 'Medium', 3),
                (2, 'lodash', 'npm', NULL, NULL, NULL);
            INSERT INTO versions (version_id, scan_id, package_id, package_name,
                version_number, latest_version, status, age_tier, days_outdated,
                days_since_release, versions_behind) VALUES
                (10, 1, 1, 'requests', '2.31.0', '2.32.0', 'outdated', 'Stale', 400, 500, '0.1.0'),
                (11, 2, 1, 'requests', '2.32.0', '2.32.0', 'up_to_date', NULL, 0, 10, '0.0.0'),
                (12, 2, 2, 'lodash', '4.17.20', '4.17.21', 'outdated', 'Abandoned', 1500, 1600, '0.0.1'),
                (13, 2, NULL, 'orphan', '1.0', NULL, 'unknown', NULL, 0, NULL, 'N/A');
            INSERT INTO package_reviews (package_id, status) VALUES (2, 'Resolved');
            INSERT INTO scan_results (scan_id, version_id, vulnerability_id) VALUES
                (2, 12, 'CVE-1'), (2, 12, 'CVE-2'), (2, 12, 'CVE-2');
        """)
        self.sqlite.commit()

        self.executed = []
        real_execute = fake_mysql.SqliteCursor.execute

        def recording_execute(cursor, sql, params=()):
            self.executed.append(sql)
            return real_execute(cursor, sql, params)

        for patcher in (
            mock.patch.object(fake_mysql.SqliteCursor, "execute", recording_execute),
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch("requests.get", no_http),
            mock.patch("requests.head", no_http),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def snapshots(self):
        return self.rows("SELECT * FROM package_snapshots ORDER BY version_id")

    def runs(self):
        return self.rows("SELECT * FROM scan_runs ORDER BY run_id")


# ============================================================
# write_daily_snapshot()
# ============================================================
class TestWriteDailySnapshot(SnapshotTestCase):

    def test_one_row_per_versions_row(self):
        result = self.db.write_daily_snapshot(DAY1)

        self.assertEqual((result["status"], result["rows"], result["skipped"]),
                         ("completed", 3, False))
        rows = self.snapshots()
        self.assertEqual([r["version_id"] for r in rows], [10, 11, 12])
        # the same package in two repositories is two rows
        self.assertEqual([(r["package_id"], r["scan_id"]) for r in rows[:2]], [(1, 1), (1, 2)])
        self.assertEqual({r["run_id"] for r in rows}, {result["run_id"]})
        self.assertEqual({r["snapshot_date"] for r in rows}, {"2026-11-03"})

    def test_copied_values(self):
        self.db.write_daily_snapshot(DAY1)
        stale, fresh, abandoned = self.snapshots()

        self.assertEqual(
            (stale["package_name"], stale["ecosystem"], stale["installed_version"],
             stale["latest_version"], stale["version_status"], stale["age_tier"],
             stale["days_behind"], stale["days_since_release"], stale["versions_behind"]),
            ("requests", "python", "2.31.0", "2.32.0", "outdated", "Stale", 400, 500, "0.1.0"))
        self.assertEqual((stale["risk_score"], stale["risk_level"], stale["priority_rank"]),
                         (40, "Medium", 3))
        self.assertEqual((stale["review_status"], stale["vuln_count"], stale["is_abandoned"]),
                         ("Open", 0, 0))
        self.assertIsNone(fresh["is_abandoned"])                 # no tier: unknown
        self.assertEqual((abandoned["review_status"], abandoned["vuln_count"],
                          abandoned["is_abandoned"]), ("Resolved", 2, 1))
        self.assertIsNone(stale["installed_release_date"])       # not stored anywhere yet

    def test_run_is_closed_with_counts(self):
        result = self.db.write_daily_snapshot(DAY1, trigger_source="cli")
        run, = self.runs()
        self.assertEqual(run["run_id"], result["run_id"])
        self.assertEqual((run["snapshot_date"], run["status"], run["package_count"],
                          run["trigger_source"]), ("2026-11-03", "completed", 3, "cli"))
        self.assertEqual(run["notes"], "lookup_failed=0; skipped_without_package_id=1")
        self.assertIsNotNone(run["finished_at"])

    def test_at_most_once_per_date(self):
        first = self.db.write_daily_snapshot(DAY1)
        again = self.db.write_daily_snapshot(DAY1)

        self.assertEqual((again["status"], again["skipped"], again["run_id"]),
                         ("skipped", True, first["run_id"]))
        self.assertEqual(len(self.snapshots()), 3)
        self.assertEqual(len(self.runs()), 1)

        next_day = self.db.write_daily_snapshot(DAY2)
        self.assertEqual(next_day["status"], "completed")
        self.assertEqual(len(self.snapshots()), 6)

    def test_partial_when_lookups_failed(self):
        result = self.db.write_daily_snapshot(DAY1, lookup_failed=5)
        self.assertEqual(result["status"], "partial")
        self.assertIn("lookup_failed=5", self.runs()[0]["notes"])
        self.assertTrue(self.db.write_daily_snapshot(DAY1)["skipped"])   # partial counts as done

    def test_failed_run_does_not_block_the_day(self):
        self.db.record_failed_run("monitor", "offline", DAY1)
        self.assertIsNone(self.db.snapshot_done(DAY1))
        self.assertEqual(self.db.write_daily_snapshot(DAY1)["status"], "completed")

    def test_error_marks_the_run_failed_and_copies_nothing(self):
        with mock.patch.object(db_storage, "SNAPSHOT_INSERT_SQL",
                               "INSERT INTO no_such_table SELECT %s, %s, %s"):
            result = self.db.write_daily_snapshot(DAY1)

        self.assertEqual(result["status"], "failed")
        self.assertIn("no_such_table", result["error"])
        self.assertEqual(self.snapshots(), [])
        run, = self.runs()
        self.assertEqual(run["status"], "failed")
        self.assertTrue(run["notes"].startswith("snapshot failed: "))
        # a failed run doesn't count: the retry the same day works
        self.assertEqual(self.db.write_daily_snapshot(DAY1)["status"], "completed")

    def test_snapshots_are_only_ever_inserted(self):
        self.db.write_daily_snapshot(DAY1)
        self.db.write_daily_snapshot(DAY1)
        self.db.write_daily_snapshot(DAY2)

        writes = [sql for sql in self.executed
                  if re.search(r"\b(UPDATE|DELETE)\b[^;]*\bpackage_snapshots\b", sql, re.I)]
        self.assertEqual(writes, [])
        with self.assertRaises(sqlite3.DatabaseError):           # the insert-only trigger
            self.sqlite.execute("UPDATE package_snapshots SET age_tier = 'Fresh'")

    def test_count_snapshot_rows(self):
        self.assertEqual(self.db.count_snapshot_rows(), (3, 1))


# ============================================================
# The monitor job: caches, offline check, refresh, snapshot
# ============================================================
class MonitorTestCase(SnapshotTestCase):

    def setUp(self):
        super().setUp()
        self.head_status = {url: 200 for url in version_monitor.REACHABILITY_URLS}
        self.head_calls = []
        self.recalculated = []
        self.cache_at_refresh = []

        def fake_head(url, *args, **kwargs):
            self.head_calls.append(url)
            status = self.head_status[url]
            if isinstance(status, Exception):
                raise status
            return FakeResponse(status)

        def fake_recalculate(db_self, scan_id):
            self.recalculated.append(scan_id)
            self.cache_at_refresh.append((dict(version_monitor.VERSION_CACHE),
                                          dict(version_monitor.NPM_CACHE)))
            return Counter({"refreshed": 1, "lookup_failed": 2})

        for patcher in (
            mock.patch("requests.head", fake_head),
            mock.patch.object(DatabaseStorage, "recalculate_metrics_for_scan", fake_recalculate),
            mock.patch.object(DatabaseStorage, "package_exists", lambda db_self, name: True),
            mock.patch.dict(version_monitor.VERSION_CACHE, {"old:python": "1.0"}),
            mock.patch.dict(version_monitor.NPM_CACHE, {"old": {"latest": "1.0", "releases": {}}}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def monitor(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ui_app.auto_monitor_versions()
        return out.getvalue()

    def test_offline_records_a_failed_run_and_refreshes_nothing(self):
        self.head_status["https://pypi.org/"] = requests.ConnectionError("offline")
        out = self.monitor()

        self.assertEqual(self.recalculated, [])
        self.assertEqual(self.snapshots(), [])
        run, = self.runs()
        self.assertEqual((run["status"], run["notes"], run["package_count"], run["trigger_source"]),
                         ("failed", "offline", 0, "monitor"))
        self.assertEqual(run["snapshot_date"], date.today().isoformat())
        self.assertIn("not reachable", out)

    def test_one_registry_answering_5xx_is_offline(self):
        self.head_status["https://registry.npmjs.org/"] = 503
        self.monitor()
        self.assertEqual(self.recalculated, [])
        self.assertEqual([r["notes"] for r in self.runs()], ["offline"])

    def test_online_refreshes_then_snapshots(self):
        self.monitor()

        self.assertEqual(sorted(self.recalculated), [1, 2])
        run, = self.runs()
        self.assertEqual((run["status"], run["package_count"]), ("partial", 3))
        self.assertIn("lookup_failed=4", run["notes"])            # 2 per scan
        self.assertEqual(len(self.snapshots()), 3)

    def test_second_run_the_same_day_adds_no_snapshot(self):
        self.monitor()
        self.monitor()
        self.assertEqual(len(self.runs()), 1)
        self.assertEqual(len(self.snapshots()), 3)

    def test_caches_are_empty_when_the_refresh_starts(self):
        self.monitor()
        self.assertEqual(self.cache_at_refresh[0], ({}, {}))


class TestRegistriesReachable(unittest.TestCase):

    def check(self, answers):
        calls = []

        def fake_head(url, *args, **kwargs):
            calls.append((url, kwargs.get("timeout")))
            answer = answers[url].pop(0)
            if isinstance(answer, Exception):
                raise answer
            return FakeResponse(answer)

        with mock.patch("requests.head", fake_head):
            return version_monitor.registries_reachable(), calls

    def test_any_answer_below_500_counts(self):
        ok, calls = self.check({"https://pypi.org/": [404], "https://registry.npmjs.org/": [200]})
        self.assertTrue(ok)
        self.assertEqual(calls, [("https://pypi.org/", 10), ("https://registry.npmjs.org/", 10)])

    def test_second_try_can_succeed(self):
        ok, calls = self.check({"https://pypi.org/": [requests.Timeout("slow"), 200],
                                "https://registry.npmjs.org/": [200]})
        self.assertTrue(ok)
        self.assertEqual(len(calls), 3)

    def test_two_failures_mean_unreachable(self):
        ok, _ = self.check({"https://pypi.org/": [200],
                            "https://registry.npmjs.org/": [502, requests.ConnectionError("x")]})
        self.assertFalse(ok)


class TestClearCaches(unittest.TestCase):

    def test_both_caches_are_emptied(self):
        with mock.patch.dict(version_monitor.VERSION_CACHE, {"a:python": "1"}), \
                mock.patch.dict(version_monitor.NPM_CACHE, {"b": {}}):
            version_monitor.clear_caches()
            self.assertEqual((version_monitor.VERSION_CACHE, version_monitor.NPM_CACHE), ({}, {}))


# ============================================================
# Migration 004 and its rollback
# ============================================================
def statements(path):
    """SQL statements of a migration file, comments removed."""
    text = "\n".join(line for line in path.read_text(encoding="utf-8").splitlines()
                     if not line.strip().startswith("--"))
    return [" ".join(s.split()) for s in text.split(";") if s.strip()]


class TestMigration004(unittest.TestCase):

    def test_steps_in_order(self):
        steps = statements(MIGRATION)
        self.assertEqual(steps, [
            "SET NAMES utf8mb4",
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_snap_run_version ON package_snapshots (run_id, version_id)",
            "DROP INDEX IF EXISTS uq_snap_run_pkg ON package_snapshots",
            "ALTER TABLE package_snapshots MODIFY version_id INT NOT NULL",
            "ALTER TABLE package_snapshots ADD COLUMN IF NOT EXISTS scan_id INT NULL AFTER version_id",
            "CREATE INDEX IF NOT EXISTS idx_snap_scan_date ON package_snapshots (scan_id, snapshot_date)",
        ])

    def test_rollback_fails_before_changing_anything(self):
        steps = statements(ROLLBACK)
        self.assertEqual(steps[0], "SET NAMES utf8mb4")
        self.assertEqual(steps[1], "CREATE UNIQUE INDEX IF NOT EXISTS uq_snap_run_pkg "
                                   "ON package_snapshots (run_id, package_id)")
        self.assertIn("DROP INDEX IF EXISTS uq_snap_run_version ON package_snapshots", steps)
        self.assertIn("ALTER TABLE package_snapshots DROP COLUMN IF EXISTS scan_id", steps)
        self.assertEqual(steps[-1], "ALTER TABLE package_snapshots MODIFY version_id INT NULL")

    def test_triggers_and_tables_untouched(self):
        for path in (MIGRATION, ROLLBACK):
            for step in statements(path):
                self.assertNotRegex(step, r"(?i)\bTRIGGER\b|\bDROP TABLE\b|\bDELETE\b|\bUPDATE\b",
                                    f"{path.name}: {step}")

    def test_commands_in_the_header_use_source(self):
        for path in (MIGRATION, ROLLBACK):
            text = path.read_text(encoding="utf-8")
            self.assertIn(f'-e "source migrations/{path.name}"', text)
            self.assertNotRegex(text, r"sbom_common\s*<")


# ============================================================
# write_snapshot.py
# ============================================================
class TestWriteSnapshotCli(SnapshotTestCase):

    def run_cli(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = write_snapshot.main(list(args), today=DAY1)
        return code, out.getvalue()

    def test_preview_counts_and_writes_nothing(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("Snapshot date: 2026-11-03", out)
        self.assertIn("Rows to copy: 3 (versions rows without a package_id, skipped: 1)", out)
        self.assertIn("Nothing was written", out)
        self.assertEqual((self.runs(), self.snapshots()), ([], []))

    def test_apply_writes_once(self):
        code, out = self.run_cli("--apply")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"Run \d+ completed: 3 rows written")
        self.assertEqual(self.runs()[0]["trigger_source"], "cli")

        code, out = self.run_cli("--apply")
        self.assertEqual(code, 0)
        self.assertIn("already exists", out)
        self.assertEqual(len(self.snapshots()), 3)

    def test_failure_exits_1(self):
        with mock.patch.object(db_storage, "SNAPSHOT_INSERT_SQL",
                               "INSERT INTO no_such_table SELECT %s, %s, %s"):
            code, out = self.run_cli("--apply")
        self.assertEqual(code, 1)
        self.assertIn("Snapshot failed", out)

    def test_no_date_option(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            write_snapshot.main(["--date", "2026-01-01"])


if __name__ == "__main__":
    unittest.main()
