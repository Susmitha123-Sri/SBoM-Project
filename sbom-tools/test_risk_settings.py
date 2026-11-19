# sbom-tools/test_risk_settings.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# The risk formula as settings: with no saved formula the stored scores equal
# the hard-coded v1 ones; saving a changed formula adds the next version and
# rescores nothing (scored packages keep their version through normal passes,
# packages never scored get the new one); identical values and Reset reuse a
# version; the Rescore button moves every package and is refused while the
# monitor runs; invalid input is rejected with nothing saved; the page shows
# the version and counts; without migration 006 the page says so and the
# monitor still scores v1; snapshots copy risk_model_version. Flask test
# client on the SQLite stand-in; the scheduler is a mock.

import contextlib
import io
import os
import sys
import unittest
from datetime import date
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import db_storage                                    # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402
from risk import DEFAULT_RISK_PARAMS                 # noqa: E402

import ui_app                                        # noqa: E402

SEED = """
    INSERT INTO scan (scan_id, target_name) VALUES (1, 'repo-a'), (2, 'repo-b');
    INSERT INTO packages (package_id, package_name, ecosystem)
    VALUES (1, 'requests', 'pypi'), (2, 'oldlib', 'pypi'), (3, 'newlib', 'npm');
    INSERT INTO versions (version_id, scan_id, package_id, package_name, version_number,
        latest_version, status, days_outdated, age_tier)
    VALUES
        (10, 1, 1, 'requests', '2.32.0', '2.32.0', 'up_to_date', 0, 'Fresh'),
        (20, 2, 1, 'requests', '2.20.0', '2.32.0', 'outdated', 800, 'Stale'),
        (11, 1, 2, 'oldlib', '1.0.0', '1.0.0', 'up_to_date', 0, 'Abandoned');
    INSERT INTO scan_results (scan_id, version_id, vulnerability_id)
    VALUES (1, 11, 'CVE-1'), (1, 11, 'CVE-2');
"""


def form(**changes):
    return {**{k: str(v) for k, v in DEFAULT_RISK_PARAMS.items()},
            **{k: str(v) for k, v in changes.items()}, "action": "save"}


class RiskSettingsTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript(SEED)
        self.sqlite.commit()
        for patcher in (
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(db_storage, "ensure_schema", lambda: None),
            mock.patch.object(ui_app, "BackgroundScheduler", mock.MagicMock()),
            mock.patch.object(ui_app, "threading", mock.MagicMock()),
            mock.patch.object(ui_app, "run_in_background",
                              lambda target, *args: target(*args)),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            self.client = ui_app.create_app().test_client()

    def score_all(self):
        """One normal monitor-style pass (newest scan first)."""
        with contextlib.redirect_stdout(io.StringIO()):
            self.db.update_package_risk_for_scan(2)
            self.db.update_package_risk_for_scan(1)

    def package(self, package_id):
        p = self.rows("SELECT * FROM packages WHERE package_id = ?", (package_id,))[0]
        return p["risk_score"], p["risk_level"], p["risk_model_version"]

    def post(self, url, data):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.client.post(url, data=data)

    def stored(self):
        return (self.rows("SELECT setting_key, setting_value FROM settings ORDER BY 1"),
                self.rows("SELECT model_version, params FROM risk_models ORDER BY 1"))

    def add_newlib(self):
        """A package that appears after the formula changed (never scored)."""
        self.sqlite.execute(
            "INSERT INTO versions (version_id, scan_id, package_id, package_name, version_number,"
            " latest_version, status, days_outdated, age_tier)"
            " VALUES (21, 2, 3, 'newlib', '1.0.0', '2.0.0', 'outdated', 200, 'Aging')")
        self.sqlite.commit()


class TestDefaults(RiskSettingsTestCase):

    def test_no_saved_formula_gives_the_v1_scores(self):
        self.score_all()
        self.assertEqual(self.package(1), (40, "Medium", "v1"))     # Stale, 800 days
        self.assertEqual(self.package(2), (55, "High", "v1"))       # Abandoned + 2 vulns
        self.assertEqual(self.rows("SELECT * FROM settings"), [])   # nothing written

    def test_formula_read_from_settings(self):
        self.assertEqual(self.db.get_risk_formula(), ("v1", DEFAULT_RISK_PARAMS))
        self.sqlite.execute("INSERT INTO settings VALUES ('risk_abandoned_points', '10', NULL)")
        self.sqlite.commit()
        self.assertEqual(self.db.get_risk_formula()[1]["risk_abandoned_points"], 10)


class TestSaveFormula(RiskSettingsTestCase):

    def test_changed_formula_is_a_new_version_and_rescores_nothing(self):
        self.score_all()
        r = self.post("/settings/risk-formula", form(risk_abandoned_points=10, risk_band2_points=20))
        self.assertEqual(r.status_code, 302)
        self.assertIn("risk=saved&version=v2", r.headers["Location"])
        self.assertEqual(self.db.get_risk_formula()[0], "v2")
        self.assertEqual(sorted(self.db.get_risk_models()), ["v1", "v2"])

        self.add_newlib()
        self.score_all()                                              # a normal daily pass
        self.assertEqual(self.package(1), (40, "Medium", "v1"))      # kept its version
        self.assertEqual(self.package(2), (55, "High", "v1"))
        self.assertEqual(self.package(3), (20, "Medium", "v2"))      # new: 20 band-2 points

    def test_identical_values_and_reset_reuse_versions(self):
        r = self.post("/settings/risk-formula", form())
        self.assertIn("risk=unchanged&version=v1", r.headers["Location"])
        self.post("/settings/risk-formula", form(risk_max_score=90))
        self.post("/settings/risk-formula", form(risk_max_score=95))
        self.assertEqual(self.db.get_risk_formula()[0], "v3")
        r = self.post("/settings/risk-formula", form(risk_max_score=90))
        self.assertIn("version=v2", r.headers["Location"])           # same params as v2
        r = self.post("/settings/risk-formula", {"action": "reset"})
        self.assertIn("risk=saved&version=v1", r.headers["Location"])
        self.assertEqual(self.db.get_risk_formula(), ("v1", DEFAULT_RISK_PARAMS))
        self.assertEqual(sorted(self.db.get_risk_models()), ["v1", "v2", "v3"])

    def test_page_shows_version_and_counts(self):
        self.score_all()
        self.post("/settings/risk-formula", form(risk_abandoned_points=10))
        html = self.client.get("/settings?risk=saved&version=v2").get_data(as_text=True)
        self.assertIn("Current model version: <strong>v2</strong>", html)
        self.assertIn("v1: 2", html)
        self.assertIn("not scored yet: 1", html)
        self.assertIn("Saved as risk model v2. Scores are not changed until you press Rescore.",
                      html)
        self.assertIn("Rescore all packages with v2", html)
        self.assertIn('name="risk_abandoned_points"', html)
        self.assertIn('value="10"', html)


class TestRescore(RiskSettingsTestCase):

    def test_rescore_moves_every_package(self):
        self.score_all()
        self.post("/settings/risk-formula", form(risk_abandoned_points=10))
        r = self.post("/settings/risk-formula/rescore", {})
        self.assertIn("risk=rescore", r.headers["Location"])
        self.assertEqual(self.package(1), (40, "Medium", "v2"))
        self.assertEqual(self.package(2), (40, "Medium", "v2"))      # 10 + 30 points
        p = self.rows("SELECT priority_model_version FROM packages WHERE package_id = 2")[0]
        self.assertEqual(p["priority_model_version"], "p1")         # queue recomputed
        self.assertFalse(ui_app._monitor_lock.locked())

    def test_refused_while_the_monitor_runs(self):
        self.score_all()
        self.post("/settings/risk-formula", form(risk_abandoned_points=10))
        with ui_app._monitor_lock:
            r = self.post("/settings/risk-formula/rescore", {})
        self.assertIn("risk=busy", r.headers["Location"])
        self.assertEqual(self.package(2), (55, "High", "v1"))


class TestInvalidInput(RiskSettingsTestCase):

    def test_rejected_and_nothing_saved(self):
        before = self.stored()
        cases = [
            ({"risk_abandoned_points": "-5"}, "must not be negative"),
            ({"risk_abandoned_points": "2.5"}, "must be a whole number"),
            ({"risk_abandoned_points": "abc"}, "must be a whole number"),
            ({"risk_abandoned_points": ""}, "must be a whole number"),
            ({"risk_band2_max_days": "800"}, "bands must be in ascending order"),
            ({"risk_vuln3_min": "2"}, "counts must be in ascending order"),
            ({"risk_high_min": "10"}, "thresholds must be in ascending order"),
            ({"risk_critical_min": "120"}, "must not be above the maximum score"),
            ({"risk_max_score": "0"}, "between 1 and 999"),
        ]
        for change, text in cases:
            r = self.post("/settings/risk-formula", form(**change))
            self.assertEqual(r.status_code, 400, change)
            html = r.get_data(as_text=True)
            self.assertIn(text, html, change)
            self.assertIn("Nothing was saved.", html)
            self.assertEqual(self.stored(), before, change)


class TestWithoutMigration006(RiskSettingsTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("DROP TRIGGER trg_risk_models_no_update;"
                                  "DROP TRIGGER trg_risk_models_no_delete;"
                                  "DROP TABLE risk_models;")

    def test_page_and_save_say_so(self):
        html = self.client.get("/settings").get_data(as_text=True)
        self.assertIn("Risk formula storage is not set up: apply migration 006", html)
        r = self.post("/settings/risk-formula", form(risk_abandoned_points=10))
        self.assertEqual(r.status_code, 500)
        self.assertIn("apply migration 006", r.get_data(as_text=True))
        self.assertEqual(self.rows("SELECT * FROM settings"), [])

    def test_monitor_still_scores_v1(self):
        self.score_all()
        self.assertEqual(self.package(1), (40, "Medium", "v1"))


class TestSnapshotVersion(RiskSettingsTestCase):

    def test_snapshot_copies_the_model_version(self):
        self.score_all()
        self.db.write_daily_snapshot(date(2026, 11, 20))
        versions = {r["package_name"]: r["risk_model_version"] for r in self.rows(
            "SELECT package_name, risk_model_version FROM package_snapshots")}
        self.assertEqual(versions, {"requests": "v1", "oldlib": "v1"})


if __name__ == "__main__":
    unittest.main()
