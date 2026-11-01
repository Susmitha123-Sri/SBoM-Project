# sbom-tools/test_scheduler_ecosystem.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# The scheduler rescans repositories weekly and never at startup (the
# startup run is monitoring only; the settings page reschedules only the
# monitor job), and sbom.py stores each package's ecosystem: python / npm,
# or "none" for every other type (rust-crate, go-module, github-action, ...),
# which is never looked up online and never replaces a stored pypi/npm
# ecosystem. No MySQL (SQLite stand-in), no Syft / Grype / git runs and no
# network: any unexpected HTTP call fails the test.

import contextlib
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import db_storage                                    # noqa: E402
import sbom                                          # noqa: E402
import version_monitor                               # noqa: E402
from db_storage import DEFAULT_SETTINGS, DatabaseStorage   # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402

import ui_app                                        # noqa: E402
from ui_app import MONITOR_JOB_ID, SCAN_JOB_ID       # noqa: E402

REAL_GET_LATEST_VERSION = version_monitor.get_latest_version


def no_http(url, *args, **kwargs):
    raise AssertionError(f"unexpected HTTP request: {url}")


# ============================================================
# 5. Scheduler
# ============================================================
class SchedulerTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        self.scheduler_class = mock.MagicMock()
        self.threading = mock.MagicMock()
        for patcher in (
            mock.patch.object(ui_app, "BackgroundScheduler", self.scheduler_class),
            mock.patch.object(ui_app, "threading", self.threading),
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(db_storage, "ensure_schema", lambda: None),
            mock.patch.object(DatabaseStorage, "get_settings", lambda s: dict(DEFAULT_SETTINGS)),
            mock.patch.object(DatabaseStorage, "save_settings", lambda s, values: None),
            mock.patch("requests.get", no_http),
            mock.patch("requests.head", no_http),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        with contextlib.redirect_stdout(io.StringIO()):
            self.app = ui_app.create_app()
        self.scheduler = self.scheduler_class.return_value

    def jobs(self):
        return {c.kwargs["id"]: c for c in self.scheduler.add_job.call_args_list}


class TestScheduler(SchedulerTestCase):

    def test_repositories_rescanned_weekly(self):
        scan = self.jobs()[SCAN_JOB_ID]
        self.assertEqual(scan.kwargs["trigger"], "interval")
        self.assertEqual(scan.kwargs["weeks"], 1)
        self.assertNotIn("hours", scan.kwargs)

    def test_monitor_still_uses_the_settings_interval(self):
        monitor = self.jobs()[MONITOR_JOB_ID]
        self.assertIs(monitor.args[0], ui_app.auto_monitor_versions)
        self.assertEqual(monitor.kwargs["hours"], 6)              # default 6 hours

    def test_startup_runs_monitoring_only(self):
        target = self.threading.Thread.call_args.kwargs["target"]
        with mock.patch.object(ui_app, "auto_monitor_versions") as monitor, \
                mock.patch.object(ui_app, "get_scanner_class") as scanner, \
                contextlib.redirect_stdout(io.StringIO()):
            target()
        monitor.assert_called_once_with()
        scanner.assert_not_called()                               # no repository rescan

    def test_settings_reschedule_only_the_monitor(self):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.app.test_client().post("/settings", data={
                "rescan_interval_value": "2", "rescan_interval_unit": "days",
                "age_threshold_days": "365"})
        self.assertEqual(response.status_code, 302)
        self.scheduler.reschedule_job.assert_called_once_with(
            MONITOR_JOB_ID, trigger="interval", days=2)


# ============================================================
# 6. sbom.py ecosystems
# ============================================================
ARTIFACTS = [
    {"name": "requests", "version": "2.31.0", "type": "python"},
    {"name": "lodash", "version": "4.17.20", "type": "npm"},
    {"name": "serde", "version": "1.0.0", "type": "rust-crate"},
    {"name": "golang.org/x/text", "version": "v0.3.0", "type": "go-module"},
    {"name": "actions/checkout", "version": "v4", "type": "github-action"},
    {"name": ".github/workflows/ci.yml", "version": "", "type": "github-action-workflow"},
    {"name": "regex", "version": "1.10.0", "type": "rust-crate"},
]

# The registry each looked-up package is on (any other lookup returns None)
REGISTRY = {"requests": ("python", "2.32.0"), "lodash": ("npm", "4.17.21")}


class ScanTestCase(SqliteTestCase):
    """SBOMScanner.scan() of a local folder with Syft/Grype/report folder mocked."""

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        (self.dir / "project").mkdir()
        (self.dir / "reports").mkdir()
        self.lookups = []

        def fake_latest(name, kind):
            self.lookups.append((name, kind))
            registry, latest = REGISTRY.get(name, (None, None))
            return latest if kind == registry else None

        for patcher in (
            mock.patch.object(sbom.Config, "SYFT_PATH", Path(sys.executable)),
            mock.patch.object(sbom.Config, "GRYPE_PATH", Path(sys.executable)),
            mock.patch.object(sbom.Config, "REPORTS_DIR", self.dir / "reports"),
            mock.patch.object(sbom.SBOMScanner, "_generate_sbom",
                              lambda s, target: {"artifacts": ARTIFACTS}),
            mock.patch.object(sbom.SBOMScanner, "_scan_vulnerabilities",
                              lambda s, target: {"matches": []}),
            mock.patch.object(sbom, "get_db_storage", lambda: self.db),
            mock.patch.object(sbom, "get_latest_version", fake_latest),
            mock.patch.object(version_monitor, "get_latest_version", fake_latest),
            mock.patch.object(version_monitor, "get_package_release_info", lambda n: {}),
            mock.patch.object(version_monitor, "get_npm_release_info", lambda n: {}),
            mock.patch.object(version_monitor, "get_github_release_info", no_http),
            mock.patch.object(version_monitor, "get_commit_date", no_http),
            mock.patch.object(db_storage, "get_commit_date", no_http),
            mock.patch("requests.get", no_http),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan(self):
        with contextlib.redirect_stdout(io.StringIO()):
            sbom.SBOMScanner(use_cache=False).scan(str(self.dir / "project"))

    def packages(self):
        return {r["package_name"]: r["ecosystem"]
                for r in self.rows("SELECT package_name, ecosystem FROM packages")}

    def versions(self):
        return {r["package_name"]: r for r in self.rows("SELECT * FROM versions")}


class TestScanEcosystems(ScanTestCase):

    def test_stored_ecosystems(self):
        self.scan()
        self.assertEqual(self.packages(), {
            "requests": "python", "lodash": "npm", "serde": "none",
            "golang.org/x/text": "none", "actions/checkout": "none",
            ".github/workflows/ci.yml": "none", "regex": "none",
        })

    def test_only_pypi_and_npm_packages_are_looked_up(self):
        """Other types are asked for with kind None / "none", which the real
        get_latest_version answers without a request (next test)"""
        self.scan()
        looked_up = {(name, kind) for name, kind in self.lookups if kind not in (None, "none")}
        self.assertEqual(looked_up, {("requests", "python"), ("lodash", "npm")})

    def test_none_kinds_make_no_request(self):
        for kind in (None, "none"):
            self.assertIsNone(REAL_GET_LATEST_VERSION("serde", kind))   # requests.get fails the test

    def test_insert_version_gets_the_ecosystem(self):
        """lodash is checked on npm (on PyPI it would come back unknown)"""
        self.scan()
        rows = self.versions()
        self.assertEqual((rows["lodash"]["status"], rows["lodash"]["latest_version"]),
                         ("outdated", "4.17.21"))
        self.assertEqual((rows["requests"]["status"], rows["requests"]["latest_version"]),
                         ("outdated", "2.32.0"))
        for name in ("serde", "actions/checkout", "golang.org/x/text"):
            self.assertEqual((rows[name]["status"], rows[name]["latest_version"],
                              rows[name]["age_tier"]), ("unknown", None, None), name)

    def test_a_stored_pypi_package_is_not_switched_to_none(self):
        """A Rust crate named like a PyPI package keeps the PyPI package checked"""
        self.sqlite.execute("INSERT INTO packages (package_name, ecosystem) VALUES ('regex', 'pypi')")
        self.sqlite.commit()
        self.scan()
        self.assertEqual(self.packages()["regex"], "pypi")


class TestInsertPackageDowngrade(SqliteTestCase):

    def ecosystem(self, name):
        return self.rows("SELECT ecosystem FROM packages WHERE package_name = ?", (name,))[0]["ecosystem"]

    def test_uploads_can_still_mark_a_package_none(self):
        """keep_registry is off by default: a CSV saying not_found still wins"""
        self.db.insert_package("gone", "pypi")
        self.db.insert_package("gone", "none")
        self.assertEqual(self.ecosystem("gone"), "none")

    def test_keep_registry_blocks_only_the_downgrade(self):
        self.db.insert_package("regex", "npm")
        self.db.insert_package("regex", "none", keep_registry=True)
        self.assertEqual(self.ecosystem("regex"), "npm")

        self.db.insert_package("serde", "none", keep_registry=True)
        self.db.insert_package("serde", "python", keep_registry=True)   # upgrade still allowed
        self.assertEqual(self.ecosystem("serde"), "python")


if __name__ == "__main__":
    unittest.main()
