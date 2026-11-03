# sbom-tools/test_trends_page.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# The read-only /trends page: the four charts say what they count, partial,
# failed and missing days are in the runs table, the not-summarised banner and
# the migration-005-missing message, Chart.js loaded from the pinned URL, the
# nav link; the page writes nothing, makes no registry lookups and doesn't
# touch the /analytics code. The Flask test client runs on the SQLite stand-in;
# the scheduler is a mock and never starts.

import contextlib
import io
import os
import sys
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, str(Path(TESTS_DIR).parent))     # project root, for ui_app

import analytics_ml                                  # noqa: E402
import db_storage                                    # noqa: E402
import snapshot_summary as ss                        # noqa: E402
import version_monitor                               # noqa: E402
from db_storage import DEFAULT_SETTINGS, DatabaseStorage   # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402

import ui_app                                        # noqa: E402

CHART_JS = "https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"
TABLES = ("scan", "packages", "versions", "package_reviews", "package_review_history",
          "scan_runs", "package_snapshots", "snapshot_summary_runs", "snapshot_summary",
          "snapshot_transition_pairs", "snapshot_transitions")


def must_not_run(*args, **kwargs):
    raise AssertionError("/trends must not call this")


class TrendsPageTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("""
            INSERT INTO scan (scan_id, target_name) VALUES (1, 'https://github.com/a/one');
            INSERT INTO packages (package_id, package_name, ecosystem, risk_level) VALUES
                (1, 'react', 'npm', 'Low'), (2, 'lodash', 'npm', 'High');
            INSERT INTO versions (version_id, scan_id, package_id, package_name,
                                  version_number, status, age_tier) VALUES
                (10, 1, 1, 'react', '17.0.0', 'outdated', 'Fresh'),
                (11, 1, 2, 'lodash', '4.0.0', 'outdated', 'Stale');
        """)
        self.sqlite.commit()
        self.run1 = self.db.write_daily_snapshot(date(2026, 11, 3))["run_id"]
        self.sqlite.execute("UPDATE versions SET age_tier = 'Aging' WHERE version_id = 10")
        self.sqlite.commit()
        self.run2 = self.db.write_daily_snapshot(date(2026, 11, 5), lookup_failed=3)["run_id"]
        self.failed = self.db.record_failed_run("monitor", "offline", date(2026, 11, 5))

        for patcher in (
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(DatabaseStorage, "get_settings", lambda s: dict(DEFAULT_SETTINGS)),
            mock.patch.object(db_storage, "ensure_schema", lambda: None),
            mock.patch.object(ui_app, "BackgroundScheduler", mock.MagicMock()),
            mock.patch.object(ui_app, "threading", mock.MagicMock()),
            mock.patch.object(analytics_ml, "run_analytics", must_not_run),
            mock.patch.object(version_monitor, "get_latest_version", must_not_run),
            mock.patch("requests.get", must_not_run),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        with contextlib.redirect_stdout(io.StringIO()):
            self.client = ui_app.create_app().test_client()

    def summarize_all(self):
        for r in ss.eligible_runs():
            ss.summarize_run(r["run_id"])
        for p, r, _ in ss.consecutive_pairs():
            ss.summarize_pair(p["run_id"], r["run_id"])

    def page(self):
        response = self.client.get("/trends")
        self.assertEqual(response.status_code, 200)
        return response.get_data(as_text=True)

    def counts(self):
        return {t: self.rows(f"SELECT COUNT(*) AS n FROM {t}")[0]["n"] for t in TABLES}


class TestTrendsPage(TrendsPageTestCase):

    def test_charts_say_what_they_count(self):
        self.summarize_all()
        html = self.page()
        for title in ("Tier distribution per day", "Packages crossing tiers between consecutive runs",
                      "Risk level distribution per day", "Review status per day", "Snapshot runs"):
            self.assertIn(title, html)
        self.assertEqual(html.count("Counts: repo rows (one per package per repository)"), 2)
        self.assertEqual(html.count("Counts: distinct packages"), 2)
        self.assertIn(f'<script src="{CHART_JS}"></script>', html)
        self.assertIn("Fresh -\\u003e Aging", html)              # crossings series (tojson)
        self.assertIn("2026-11-05 (partial)", html)
        self.assertNotIn("not summarised yet", html)

    def test_runs_table(self):
        self.summarize_all()
        html = self.page()
        self.assertIn('<tr class="run-missing">', html)           # 2026-11-04
        self.assertIn('<tr class="run-partial">', html)
        self.assertIn('<tr class="run-failed">', html)
        self.assertIn("1 missing day(s)", html)
        self.assertIn("offline", html)

    def test_unsummarized_banner(self):
        html = self.page()
        self.assertIn("2 run(s) and 1 pair(s) of runs are not\n        summarised yet", html)
        self.assertIn("python sbom-tools/summarize_snapshots.py --apply", html)
        self.assertIn("No summarised snapshot days yet.", html)

    def test_migration_missing(self):
        for table in ("snapshot_transitions", "snapshot_transition_pairs", "snapshot_summary",
                      "snapshot_summary_runs"):
            self.sqlite.execute(f"DROP TABLE {table}")
        html = self.page()
        self.assertIn("Migration 005 is not applied", html)
        self.assertNotIn(CHART_JS, html)

    def test_read_only(self):
        self.summarize_all()
        before = self.counts()
        snapshots = self.rows("SELECT * FROM package_snapshots ORDER BY snapshot_id")
        self.page()
        self.page()
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.rows("SELECT * FROM package_snapshots ORDER BY snapshot_id"), snapshots)

    def test_nav_link(self):
        html = self.client.get("/trends").get_data(as_text=True)
        self.assertIn('<a href="/trends">', html)
        self.assertIn('<a href="/analytics">', html)


if __name__ == "__main__":
    unittest.main()
