# sbom-tools/test_large_scans.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Scans with more than 500 rows (get_monitored_versions used to stop at 500).
# No MySQL or network: the real queries run against an in-memory SQLite
# database behind a small pymysql-style wrapper, and version lookups are
# patched.

import contextlib
import io
import os
import re
import sys
import unittest
from collections import Counter
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import db_storage
import version_monitor
from age_tiers import TIER_NAMES, UNKNOWN_TIER
from db_storage import DEFAULT_SETTINGS, DatabaseStorage
from fake_mysql import SqliteTestCase

import ui_app
from ui_app import MONITOR_PAGE_SIZE, dashboard_totals, paginate, repo_outdated_percentages

BIG_ROWS = 750      # > 500
SMALL_ROWS = 40
BIG_SCAN, SMALL_SCAN, EMPTY_SCAN = 1, 2, 3

STATUSES = ["up_to_date", "outdated", "unknown"]
TIERS = TIER_NAMES + [None, "not-a-tier"]   # the last two count as UNKNOWN_TIER


def big_row(i):
    return {
        "name": f"pkg-{i:04d}",
        "status": STATUSES[i % len(STATUSES)],
        "tier": TIERS[i % len(TIERS)],
    }


def seed_database(db):
    db.executemany("INSERT INTO scan VALUES (?, ?, ?)", [
        (BIG_SCAN, "big.csv", "2026-10-03 00:00:00"),
        (SMALL_SCAN, "small.csv", "2026-10-02 00:00:00"),
        (EMPTY_SCAN, "empty.csv", "2026-10-01 00:00:00"),
    ])

    def version(scan_id, name, status, tier):
        latest = "1.0.0" if status == "up_to_date" else "2.0.0"
        return (scan_id, name, "1.0.0", latest, status, "active",
                "2026-10-01 12:00:00", 0 if status == "up_to_date" else 400,
                tier)

    # Inserted in reverse so the name order differs from the insert order
    rows = [version(BIG_SCAN, r["name"], r["status"], r["tier"])
            for r in map(big_row, reversed(range(BIG_ROWS)))]
    rows += [version(SMALL_SCAN, f"small-{i:02d}", "outdated", "Stale")
             for i in range(SMALL_ROWS)]
    db.executemany("""
        INSERT INTO versions (scan_id, package_name, version_number,
            latest_version, status, baseline_status, release_date,
            days_outdated, age_tier)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    db.commit()


class LargeScanTestCase(SqliteTestCase):
    """The 750-row, 40-row and empty scans in the SQLite database."""

    def setUp(self):
        super().setUp()
        seed_database(self.sqlite)


class TestGetMonitoredVersions(LargeScanTestCase):

    def test_returns_every_row_of_a_large_scan(self):
        """750 rows in the scan -> all 750 returned (was capped at 500)"""
        rows = self.db.get_monitored_versions(BIG_SCAN)
        names = [r["package_name"] for r in rows]

        self.assertEqual(len(rows), BIG_ROWS)
        self.assertEqual(names, sorted(names))
        self.assertEqual(len(set(names)), BIG_ROWS)

    def test_limit_and_offset_slices_cover_every_row_once(self):
        """100-row slices put back together are the full, ordered list"""
        full = [r["package_name"] for r in self.db.get_monitored_versions(BIG_SCAN)]

        pieces = []
        for offset in range(0, BIG_ROWS, 100):
            pieces += [r["package_name"] for r in
                       self.db.get_monitored_versions(BIG_SCAN, limit=100, offset=offset)]

        self.assertEqual(pieces, full)

    def test_explicit_limit_still_caps(self):
        """limit=500 is opt-in now, and still returns exactly 500"""
        self.assertEqual(len(self.db.get_monitored_versions(BIG_SCAN, limit=500)), 500)


class TestScanSummaries(LargeScanTestCase):

    def expected_big(self):
        rows = [big_row(i) for i in range(BIG_ROWS)]
        tiers = Counter(r["tier"] if r["tier"] in TIER_NAMES else UNKNOWN_TIER
                        for r in rows)
        return {
            "total": BIG_ROWS,
            "outdated": sum(r["status"] == "outdated" for r in rows),
            "up_to_date": sum(r["status"] == "up_to_date" for r in rows),
            "tiers": {name: tiers[name] for name in TIER_NAMES + [UNKNOWN_TIER]},
        }

    def test_counts_for_a_large_scan(self):
        """Total, outdated, up-to-date and every tier for 750 rows"""
        summaries = self.db.get_scan_summaries()
        self.assertEqual(summaries[BIG_SCAN], self.expected_big())

    def test_empty_scan_is_left_out(self):
        self.assertNotIn(EMPTY_SCAN, self.db.get_scan_summaries())

    def test_dashboard_totals_add_up_all_scans(self):
        """750 + 40 = 790 (the bug showed 500 + 40 = 540)"""
        totals = dashboard_totals(self.db.get_scan_summaries())
        big = self.expected_big()

        self.assertEqual(totals["total"], BIG_ROWS + SMALL_ROWS)
        self.assertEqual(totals["outdated"], big["outdated"] + SMALL_ROWS)
        self.assertEqual(totals["up_to_date"], big["up_to_date"])
        self.assertEqual(totals["tiers"]["Stale"], big["tiers"]["Stale"] + SMALL_ROWS)
        self.assertEqual(sum(totals["tiers"].values()), totals["total"])

    def test_repo_outdated_percentages(self):
        """% outdated per scan uses every row; an empty scan is 0"""
        scans = self.db.get_all_scans()
        result = dict(repo_outdated_percentages(scans, self.db.get_scan_summaries()))

        big = self.expected_big()
        self.assertEqual(result["big.csv"], round(big["outdated"] / BIG_ROWS * 100, 2))
        self.assertEqual(result["small.csv"], 100.0)
        self.assertEqual(result["empty.csv"], 0)


class TestPaginate(unittest.TestCase):

    def test_pages_for_750_rows(self):
        self.assertEqual(paginate(750, 1, 100), (1, 8, 0))
        self.assertEqual(paginate(750, 8, 100), (8, 8, 700))

    def test_out_of_range_pages_are_clamped(self):
        self.assertEqual(paginate(750, 0, 100), (1, 8, 0))
        self.assertEqual(paginate(750, 99, 100), (8, 8, 700))

    def test_no_rows_is_one_empty_page(self):
        self.assertEqual(paginate(0, 3, 100), (1, 1, 0))


class MonitorAppTestCase(LargeScanTestCase):
    """Patches out network lookups, metric recalculation and the scheduler."""

    def setUp(self):
        super().setUp()
        self.refresh_calls = []

        def record_refresh(db_self, scan_id, package_name, ecosystem=None):
            self.refresh_calls.append((scan_id, package_name))
            return "refreshed"

        for patcher in (
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(version_monitor, "get_latest_version",
                              lambda name, kind: "2.0.0"),
            mock.patch.object(version_monitor, "registries_reachable", lambda: True),
            mock.patch.object(DatabaseStorage, "refresh_version", record_refresh),
            # Background work runs inline, so tests can check its effect
            mock.patch.object(ui_app, "run_in_background",
                              lambda target, *args: target(*args)),
            mock.patch.object(DatabaseStorage, "package_exists",
                              lambda db_self, name: True),
            mock.patch.object(DatabaseStorage, "get_settings",
                              lambda db_self: dict(DEFAULT_SETTINGS)),
            mock.patch.object(db_storage, "ensure_schema", lambda: None),
            mock.patch.object(ui_app, "BackgroundScheduler", mock.MagicMock()),
            mock.patch.object(ui_app, "threading", mock.MagicMock()),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def client(self):
        with contextlib.redirect_stdout(io.StringIO()):
            app = ui_app.create_app()
        return app.test_client()

    def get(self, url):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.client().get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.get_data(as_text=True)

    def refreshed(self, scan_id):
        return Counter(name for s, name in self.refresh_calls if s == scan_id)


class TestMonitorRefreshesAllRows(MonitorAppTestCase):

    def test_auto_monitor_versions_refreshes_every_row(self):
        """All 750 rows of the large scan are re-checked, not the first 500"""
        with contextlib.redirect_stdout(io.StringIO()):
            ui_app.auto_monitor_versions()

        big = self.refreshed(BIG_SCAN)
        self.assertEqual(len(big), BIG_ROWS)
        self.assertEqual(set(big.values()), {1})
        self.assertEqual(len(self.refreshed(SMALL_SCAN)), SMALL_ROWS)

    def test_run_monitor_refreshes_every_row(self):
        """/run-monitor starts the background job: one pass over all rows"""
        self.get("/run-monitor")

        big = self.refreshed(BIG_SCAN)
        self.assertEqual(len(big), BIG_ROWS)
        self.assertEqual(set(big.values()), {1})


class TestMonitorPage(MonitorAppTestCase):

    def table_rows(self, html):
        body = html.split('<tbody id="packageTable">', 1)[1].split("</tbody>", 1)[0]
        return re.findall(r"<td>(pkg-\d{4})</td>", body)

    def test_first_page_shows_100_rows_and_stats_cover_all(self):
        html = self.get(f"/monitor/{BIG_SCAN}")

        self.assertEqual(len(self.table_rows(html)), MONITOR_PAGE_SIZE)
        self.assertIn("Page 1 / 8", html)
        self.assertIn(f"<h2>{BIG_ROWS}</h2>", html)    # Total Packages card

    def test_last_page_has_the_remaining_rows(self):
        html = self.get(f"/monitor/{BIG_SCAN}?page=8")

        rows = self.table_rows(html)
        self.assertEqual(len(rows), BIG_ROWS - 700)
        self.assertEqual(rows[-1], f"pkg-{BIG_ROWS - 1:04d}")

    def test_outdated_filter_covers_all_pages(self):
        """1 of every 3 rows is outdated (unknown rows are not): 250 rows, 3 pages"""
        html = self.get(f"/monitor/{BIG_SCAN}?outdated=1")
        self.assertIn("Page 1 / 3", html)
        self.assertIn("of 250)", html)

    def test_search_covers_all_pages(self):
        """pkg-0700..pkg-0749 are past row 500 and are still found"""
        html = self.get(f"/monitor/{BIG_SCAN}?q=pkg-07")
        rows = self.table_rows(html)

        self.assertEqual(len(rows), 50)
        self.assertTrue(all(r.startswith("pkg-07") for r in rows))

    def test_dashboard_counts_without_loading_rows(self):
        """Dashboard total is 790 and comes from the GROUP BY query"""
        with mock.patch.object(DatabaseStorage, "get_monitored_versions") as loaded:
            html = self.get("/dashboard")

        loaded.assert_not_called()
        self.assertIn(str(BIG_ROWS + SMALL_ROWS), html)


if __name__ == "__main__":
    unittest.main()
