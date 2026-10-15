# sbom-tools/test_risk.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Package risk (risk.py): points per signal, level cut-offs, Unknown age,
# reasons text; and the database side (latest-scan rule, packages.risk_*
# writes, /packages risk filter, dashboard counts). No network; SQLite
# stand-in for MySQL (see fake_mysql.py).

import contextlib
import io
import os
import sys
import unittest
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import risk                                         # noqa: E402
from risk import (RISK_MODEL_VERSION, UNKNOWN_RISK, days_behind_points,  # noqa: E402
                  describe_days, level_for, score_risk, vuln_points)
from fake_mysql import SqliteTestCase               # noqa: E402
from db_storage import DatabaseStorage, RISK_FILTERS, RISK_NOT_SCORED  # noqa: E402
import test_upload_pipeline   # RouteTestCase (module import, so its tests aren't re-run here)


class TestPoints(unittest.TestCase):

    def test_days_behind_bands(self):
        for days, points in [(0, 0), (30, 0), (31, 15), (365, 15),
                             (366, 30), (730, 30), (731, 40), (5000, 40)]:
            self.assertEqual(days_behind_points(days), points, days)

    def test_vulnerability_bands(self):
        for count, points in [(0, 0), (1, 20), (2, 30), (4, 30), (5, 45), (50, 45)]:
            self.assertEqual(vuln_points(count), points, count)

    def test_level_cutoffs(self):
        for score, level in [(0, "Low"), (19, "Low"), (20, "Medium"), (44, "Medium"),
                             (45, "High"), (69, "High"), (70, "Critical"), (100, "Critical")]:
            self.assertEqual(level_for(score), level, score)

    def test_describe_days(self):
        self.assertEqual(describe_days(0), "up to date")
        self.assertEqual(describe_days(1), "1 day behind")
        self.assertEqual(describe_days(45), "45 days behind")
        self.assertEqual(describe_days(200), "6 months behind")
        self.assertEqual(describe_days(800), "2 years behind")


class TestScoreRisk(unittest.TestCase):

    def test_fresh_and_up_to_date_is_low(self):
        r = score_risk("Fresh", 0, None)
        self.assertEqual((r["score"], r["level"]), (0, "Low"))
        self.assertEqual(r["reasons"], "Fresh; up to date; no vulnerability data")
        self.assertEqual(r["tier"], "Fresh")
        self.assertIs(r["is_abandoned"], False)
        self.assertEqual(r["model_version"], RISK_MODEL_VERSION)
        self.assertEqual(RISK_MODEL_VERSION, "v1")

    def test_aging_is_low(self):
        r = score_risk("Aging", 200, None)
        self.assertEqual((r["score"], r["level"]), (15, "Low"))

    def test_stale_is_medium(self):
        r = score_risk("Stale", 548, None)
        self.assertEqual((r["score"], r["level"]), (30, "Medium"))
        self.assertEqual(r["reasons"], "Stale; 18 months behind; no vulnerability data")
        self.assertEqual(r["days_behind"], 548)

    def test_abandoned_but_up_to_date_is_medium(self):
        r = score_risk("Abandoned", 0, None)
        self.assertEqual((r["score"], r["level"]), (25, "Medium"))
        self.assertIs(r["is_abandoned"], True)
        self.assertTrue(r["reasons"].startswith("Abandoned (no release in 3+ years); up to date"))

    def test_abandoned_and_far_behind_is_high(self):
        r = score_risk("Abandoned", 1100, None)
        self.assertEqual((r["score"], r["level"]), (65, "High"))
        self.assertIn("3 years behind", r["reasons"])

    def test_vulnerabilities_add_up_to_critical(self):
        r = score_risk("Abandoned", 1100, 1)
        self.assertEqual((r["score"], r["level"]), (85, "Critical"))
        self.assertTrue(r["reasons"].endswith("; 1 vulnerability"))

    def test_any_known_vulnerability_is_at_least_medium(self):
        r = score_risk("Fresh", 0, 1)
        self.assertEqual((r["score"], r["level"]), (20, "Medium"))

    def test_score_is_capped(self):
        r = score_risk("Abandoned", 2000, 9)
        self.assertEqual((r["score"], r["level"]), (100, "Critical"))
        self.assertIn("9 vulnerabilities", r["reasons"])

    def test_zero_vulnerabilities_means_no_data(self):
        for count in (None, 0):
            r = score_risk("Stale", 400, count)
            self.assertIsNone(r["vuln_count"])
            self.assertIn("no vulnerability data", r["reasons"])
            self.assertEqual(r["score"], 30)

    def test_unknown_age_is_neither_safe_nor_risky(self):
        # days_outdated holds an estimate when dates are missing: ignored
        for tier in (None, "", "unknown"):
            r = score_risk(tier, 540, None)
            self.assertEqual(r["level"], UNKNOWN_RISK)
            self.assertIsNone(r["score"])
            self.assertIsNone(r["tier"])
            self.assertIsNone(r["days_behind"])
            self.assertIsNone(r["is_abandoned"])
            self.assertEqual(r["reasons"],
                             "Age unknown (no release dates); no vulnerability data")

    def test_unknown_age_with_vulnerabilities_is_scored_on_them(self):
        r = score_risk(None, 540, 3)
        self.assertEqual((r["score"], r["level"]), (30, "Medium"))
        self.assertEqual(r["reasons"], "Age unknown (no release dates); 3 vulnerabilities")

    def test_negative_days_count_as_up_to_date(self):
        r = score_risk("Fresh", -5, None)
        self.assertEqual(r["days_behind"], 0)
        self.assertIn("up to date", r["reasons"])

    def test_levels_listed_most_severe_first(self):
        self.assertEqual(risk.RISK_LEVELS, ["Critical", "High", "Medium", "Low"])


SEED = """
    INSERT INTO scan (scan_id, target_name) VALUES (1, 'repo-a'), (2, 'repo-b');
    INSERT INTO packages (package_id, package_name, ecosystem)
    VALUES (1, 'requests', 'pypi'), (2, 'oldlib', 'pypi'), (3, 'never-scanned', 'pypi');
    INSERT INTO versions (version_id, scan_id, package_id, package_name, version_number,
        latest_version, status, days_outdated, age_tier)
    VALUES
        -- requests is in both scans: scan 2 (the latest) must win
        (10, 1, 1, 'requests', '2.32.0', '2.32.0', 'up_to_date', 0, 'Fresh'),
        (20, 2, 1, 'requests', '2.20.0', '2.32.0', 'outdated', 800, 'Stale'),
        -- oldlib only in scan 1, abandoned, with vulnerabilities
        (11, 1, 2, 'oldlib', '1.0.0', '1.0.0', 'up_to_date', 0, 'Abandoned'),
        -- no package_id: can't be written to packages
        (12, 1, NULL, 'loose', '0.1', NULL, 'unknown', 30, NULL);
    INSERT INTO scan_results (scan_id, version_id, vulnerability_id)
    VALUES (1, 11, 'CVE-1'), (1, 11, 'CVE-2'), (1, 11, 'CVE-2');
"""


class TestPackageRiskDb(SqliteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript(SEED)
        self.sqlite.commit()

    def package(self, package_id):
        return self.rows("SELECT * FROM packages WHERE package_id = ?", (package_id,))[0]

    def test_latest_scan_wins_even_when_processed_last(self):
        # The monitor goes newest scan first, then older ones
        self.assertEqual(self.db.update_package_risk_for_scan(2), 1)
        self.assertEqual(self.db.update_package_risk_for_scan(1), 1)   # oldlib only

        p = self.package(1)
        self.assertEqual(p["risk_version_id"], 20)
        self.assertEqual(p["risk_tier"], "Stale")
        self.assertEqual(p["risk_days_behind"], 800)
        self.assertEqual(p["risk_level"], "Medium")          # 40 points
        self.assertEqual(p["risk_score"], 40)
        self.assertEqual(p["risk_model_version"], "v1")
        self.assertIsNotNone(p["risk_computed_at"])

    def test_vulnerabilities_are_counted_distinct(self):
        self.db.update_package_risk_for_scan(1)
        p = self.package(2)
        self.assertEqual(p["risk_vuln_count"], 2)
        self.assertEqual(p["risk_is_abandoned"], 1)
        self.assertEqual(p["risk_score"], 55)                # 0 + 25 + 30
        self.assertEqual(p["risk_level"], "High")
        self.assertEqual(p["risk_reasons"],
                         "Abandoned (no release in 3+ years); up to date; 2 vulnerabilities")

    def test_rows_without_package_id_and_unscanned_packages_are_skipped(self):
        rows = self.db.package_risk_rows(1)
        self.assertEqual([r["package_id"] for r in rows], [2])
        self.db.update_package_risk_for_scan(1)
        self.assertIsNone(self.package(3)["risk_level"])

    def test_preview_writes_nothing(self):
        self.db.package_risk_rows(1)
        self.db.package_risk_rows(2)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM packages "
                                   "WHERE risk_level IS NOT NULL")[0]["n"], 0)

    def test_monitor_job_updates_risk(self):
        with mock.patch.object(DatabaseStorage, "refresh_version", return_value="refreshed"):
            results = self.db.recalculate_metrics_for_scan(2)
        self.assertEqual(results["refreshed"], 1)
        self.assertEqual(results["risk_updated"], 1)
        self.assertEqual(self.package(1)["risk_version_id"], 20)

    def test_risk_failure_does_not_stop_the_monitor_job(self):
        with mock.patch.object(DatabaseStorage, "refresh_version", return_value="refreshed"), \
                mock.patch.object(DatabaseStorage, "update_package_risk_for_scan",
                                  side_effect=RuntimeError("boom")), \
                contextlib.redirect_stdout(io.StringIO()):
            results = self.db.recalculate_metrics_for_scan(1)
        self.assertEqual(results["refreshed"], 3)     # every row of scan 1
        self.assertEqual(results["risk_error"], 1)

    def test_risk_level_counts(self):
        self.db.update_package_risk_for_scan(2)
        self.db.update_package_risk_for_scan(1)
        counts = self.db.get_risk_level_counts()
        self.assertEqual(list(counts), RISK_FILTERS)
        self.assertEqual(counts["Medium"], 1)
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts[RISK_NOT_SCORED], 1)
        self.assertEqual(sum(counts.values()), 3)

    def test_list_and_total_agree_under_risk_and_review_filters(self):
        self.db.update_package_risk_for_scan(2)
        self.db.update_package_risk_for_scan(1)
        self.sqlite.execute("INSERT INTO package_reviews (package_id, status) "
                            "VALUES (2, 'Resolved')")
        self.sqlite.commit()

        cases = [
            ({"risk_level": "Medium"}, 2),              # both requests rows
            ({"risk_level": "High"}, 1),
            ({"risk_level": RISK_NOT_SCORED}, 1),       # the unlinked row
            ({"risk_level": "High", "review_status": "Resolved"}, 1),
            ({"risk_level": "High", "review_status": "Open"}, 0),
            ({"risk_level": "Bogus"}, 4),               # ignored
        ]
        for filters, expected in cases:
            listed = self.db.get_packages_paginated(limit=50, offset=0, **filters)
            self.assertEqual(len(listed), expected, filters)
            self.assertEqual(self.db.get_total_packages(**filters), expected, filters)


class TestRiskPages(test_upload_pipeline.RouteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript(SEED)
        self.sqlite.commit()
        self.db.update_package_risk_for_scan(2)
        self.db.update_package_risk_for_scan(1)

    def page(self, url):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.get_data(as_text=True)

    def test_packages_page_shows_risk_and_filters(self):
        html = self.page("/packages")
        self.assertIn("Severity (version gap)", html)
        self.assertIn('class="risk-badge risk-high"', html)
        self.assertIn("not scored", html)

        html = self.page("/packages?risk=High")
        self.assertIn("<td>oldlib</td>", html)
        self.assertNotIn("<td>requests</td>", html)
        # the review form returns to the filtered page
        self.assertIn('name="next" value="/packages?risk=High"', html)

    def test_dashboard_shows_risk_counts(self):
        html = self.page("/dashboard")
        self.assertIn("Packages by Risk (latest scan)", html)
        self.assertIn('href="/packages?risk=Not%20scored"', html)


if __name__ == "__main__":
    unittest.main()
