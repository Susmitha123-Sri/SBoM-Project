# sbom-tools/test_upload_pipeline.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# npm ecosystem handling, repeatable/resumable uploads with honest counts,
# upload progress, and the scheduled refresh never overwriting newer data.
# No MySQL (SQLite stand-in, see fake_mysql.py) and no network: requests.get
# is patched everywhere, and any unexpected HTTP call fails the test.

import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import db_storage
import target_files
import upload_jobs
import version_monitor
from db_storage import DEFAULT_SETTINGS, DatabaseStorage, compute_version_metrics
from fake_mysql import SqliteTestCase
from upload_jobs import UploadJobs, dedupe_packages, parse_upload, process_upload
from version_monitor import package_ecosystem, package_type

import ui_app


def no_http(url, *args, **kwargs):
    raise AssertionError(f"unexpected HTTP request: {url}")


# ============================================================
# 1. ECOSYSTEM RULES + NPM LOOKUPS (no GitHub for @scope/name)
# ============================================================
class TestPackageEcosystem(unittest.TestCase):

    def test_scoped_names_are_npm_whatever_the_hint(self):
        for hint in (None, "pypi", "github", "python"):
            self.assertEqual(package_ecosystem("@babel/core", hint), "npm")
        self.assertEqual(package_type("@babel/core"), "npm")

    def test_other_slash_names_are_github(self):
        self.assertEqual(package_ecosystem("actions/checkout"), "github")
        self.assertEqual(package_type("actions/checkout", "pypi"), "github-action")

    def test_plain_names_follow_the_hint(self):
        self.assertEqual(package_ecosystem("react", "npm"), "npm")
        self.assertEqual(package_ecosystem("requests", "pypi"), "pypi")
        self.assertEqual(package_ecosystem("requests", "python"), "pypi")   # sbom.py spelling

    def test_plain_names_default_to_pypi(self):
        for hint in (None, "", "pypi_or_npm", "not_found", "unknown"):
            self.assertEqual(package_ecosystem("requests", hint), "pypi")

    def test_detect_package_source_uses_the_same_rule(self):
        self.assertEqual(db_storage.detect_package_source("@types/node"), "npm")
        self.assertEqual(db_storage.detect_package_source("react", "npm"), "npm")


class FakeResponse:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data

    def json(self):
        return self._data


class TestNpmLookups(unittest.TestCase):
    """requests.get is faked: only registry.npmjs.org answers."""

    NPM_DOCS = {
        "https://registry.npmjs.org/@babel%2Fcore": {
            "dist-tags": {"latest": "7.25.0"},
            "time": {"created": "2017-01-01T00:00:00Z",
                     "modified": "2026-01-01T00:00:00Z",
                     "7.20.0": "2022-11-04T10:00:00Z",
                     "7.25.0": "2024-07-30T10:00:00Z"},
        },
        "https://registry.npmjs.org/react": {
            "dist-tags": {"latest": "19.0.0"},
            "time": {"18.2.0": "2022-06-14T00:00:00Z", "19.0.0": "2024-12-05T00:00:00Z"},
        },
    }

    def setUp(self):
        self.urls = []

        def fake_get(url, *args, **kwargs):
            self.urls.append(url)
            if url in self.NPM_DOCS:
                return FakeResponse(200, self.NPM_DOCS[url])
            return FakeResponse(404, {})

        for patcher in (
            mock.patch("requests.get", fake_get),
            mock.patch.dict(version_monitor.VERSION_CACHE, clear=True),
            mock.patch.dict(version_monitor.NPM_CACHE, clear=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def github_calls(self):
        return [u for u in self.urls if "github.com" in u]

    def test_latest_version_of_a_scoped_package_comes_from_npm(self):
        latest = version_monitor.get_latest_version("@babel/core", package_type("@babel/core"))

        self.assertEqual(latest, "7.25.0")
        self.assertEqual(self.urls, ["https://registry.npmjs.org/@babel%2Fcore"])

    def test_github_helpers_refuse_scoped_names_without_a_request(self):
        self.assertIsNone(version_monitor.get_commit_date("@babel/core", "7.20.0"))
        self.assertEqual(version_monitor.get_github_release_info("@babel/core"), {})
        self.assertIsNone(version_monitor.get_latest_github_action_version("@babel/core"))
        self.assertEqual(self.urls, [])

    def test_npm_release_dates(self):
        self.assertEqual(version_monitor.get_npm_release_info("@babel/core"),
                         {"7.20.0": "2022-11-04", "7.25.0": "2024-07-30"})

    def test_one_request_per_package(self):
        version_monitor.get_latest_npm_version("@babel/core")
        version_monitor.get_npm_release_info("@babel/core")
        self.assertEqual(len(self.urls), 1)

    def test_metrics_for_a_scoped_package_make_no_github_call(self):
        metrics = compute_version_metrics("@babel/core", "7.20.0", "outdated")

        self.assertEqual(self.github_calls(), [])
        self.assertEqual(metrics["latest_version"], "7.25.0")
        self.assertEqual(metrics["versions_behind"], "0.5.0")
        self.assertIsNotNone(metrics["days_since_release"])   # from npm "time"
        self.assertGreater(metrics["days_outdated"], 600)     # 2022-11-04 -> 2024-07-30

    def test_plain_npm_name_uses_npm_not_pypi(self):
        metrics = compute_version_metrics("react", "18.2.0", "outdated", ecosystem="npm")

        self.assertEqual(metrics["latest_version"], "19.0.0")
        self.assertFalse([u for u in self.urls if "pypi.org" in u])


# ============================================================
# 2 + 4. PARSING, REAL ECOSYSTEM, DE-DUPLICATION
# ============================================================
CSV = b"""repo_name,package_name,current_version,latest_version,ecosystem,registry_ecosystem
r,requests,2.31.0,,pypi_or_npm,pypi
r,@babel/core,7.20.0,,npm,npm
r,react,18.2.0,,pypi_or_npm,npm
r,requests,2.32.0,,pypi_or_npm,pypi
r,leftpad-gone,1.0.0,,pypi_or_npm,not_found
r,actions/checkout,v3,,pypi_or_npm,not_found
"""
CSV_ROWS, DISTINCT = 6, 5

LATEST = {
    "requests": "2.32.0",
    "@babel/core": "7.25.0",
    "react": "19.0.0",
    "leftpad-gone": "1.0.0",
    "actions/checkout": "v4",
}


class TestParseUpload(unittest.TestCase):

    def test_csv_ecosystems(self):
        eco = {p["name"]: p["ecosystem"] for p in parse_upload("deps.csv", CSV)}
        self.assertEqual(eco, {
            "requests": "pypi",
            "@babel/core": "npm",          # scoped name
            "react": "npm",                # registry_ecosystem = npm
            "leftpad-gone": "none",        # registry not_found: no lookups
            "actions/checkout": "none",    # not_found wins over owner/repo
        })

    def test_json_purl_type(self):
        sbom = b'{"packages": [{"name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},' \
               b' {"name": "flask", "version": "2.0.0", "type": "python"}]}'
        eco = {p["name"]: p["ecosystem"] for p in parse_upload("x.json", sbom)}
        self.assertEqual(eco, {"lodash": "npm", "flask": "pypi"})

    def test_other_file_types_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_upload("deps.txt", b"requests==1.0")

    def test_dedupe_keeps_last_occurrence_in_first_position(self):
        packages = dedupe_packages(parse_upload("deps.csv", CSV))

        self.assertEqual(len(packages), DISTINCT)
        self.assertEqual(packages[0]["name"], "requests")
        self.assertEqual(packages[0]["version"], "2.32.0")


# ============================================================
# 4. PROCESSING: inserted / updated / skipped, repeatable, resumable
# ============================================================
class UploadDbTestCase(SqliteTestCase):
    """SQLite database with scan 1, fake registry lookups, no HTTP."""

    def setUp(self):
        super().setUp()
        self.sqlite.execute("INSERT INTO scan (scan_id, target_name) VALUES (1, 'deps.csv')")
        self.sqlite.commit()
        self.lookups = []

        def fake_latest(name, kind):
            self.lookups.append((name, kind))
            return LATEST.get(name)

        for patcher in (
            mock.patch("requests.get", no_http),
            mock.patch.object(version_monitor, "get_latest_version", fake_latest),
            mock.patch.object(version_monitor, "get_package_release_info", lambda n: {}),
            mock.patch.object(version_monitor, "get_npm_release_info", lambda n: {}),
            mock.patch.object(version_monitor, "get_github_release_info", lambda n: {}),
            mock.patch.object(version_monitor, "get_commit_date", lambda n, v: None),
            mock.patch.object(db_storage, "get_commit_date", lambda n, v: None),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.jobs = UploadJobs()
        self.packages = dedupe_packages(parse_upload("deps.csv", CSV))

    def upload(self, packages=None):
        packages = self.packages if packages is None else packages
        self.jobs.start(1, target="deps.csv", csv_rows=CSV_ROWS, distinct=len(packages))
        with contextlib.redirect_stdout(io.StringIO()):
            process_upload(self.db, 1, packages, self.jobs)
        return self.jobs.get(1)

    def counts(self, job):
        return {k: job[k] for k in ("inserted", "updated", "skipped", "failed")}

    def stored(self):
        return {r["package_name"]: r for r in self.rows("""
            SELECT v.package_name, v.version_number, v.status, p.ecosystem
            FROM versions v LEFT JOIN packages p ON p.package_id = v.package_id
            WHERE v.scan_id = 1""")}


class TestProcessUpload(UploadDbTestCase):

    def test_first_upload_inserts_every_distinct_package(self):
        job = self.upload()

        self.assertEqual(job["state"], "done")
        self.assertEqual(self.counts(job), {"inserted": 5, "updated": 0, "skipped": 0, "failed": 0})
        self.assertEqual((job["csv_rows"], job["distinct"], job["processed"]), (6, 5, 5))

    def test_real_ecosystem_is_stored_and_used_for_lookups(self):
        self.upload()
        stored = self.stored()

        self.assertEqual(stored["@babel/core"]["ecosystem"], "npm")
        self.assertEqual(stored["react"]["ecosystem"], "npm")
        self.assertEqual(stored["requests"]["ecosystem"], "pypi")
        kinds = dict(self.lookups)
        self.assertEqual(kinds["@babel/core"], "npm")
        self.assertEqual(kinds["react"], "npm")
        self.assertEqual(kinds["requests"], "python")

    def test_repeated_name_stores_the_last_row(self):
        self.upload()
        self.assertEqual(self.stored()["requests"]["version_number"], "2.32.0")

    def test_same_file_again_skips_everything_without_duplicates(self):
        self.upload()
        self.lookups.clear()

        job = self.upload()

        self.assertEqual(self.counts(job), {"inserted": 0, "updated": 0, "skipped": 5, "failed": 0})
        self.assertEqual(self.lookups, [], "skipped packages need no registry lookup")
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM versions")[0]["n"], DISTINCT)

    def test_interrupted_upload_resumes_where_it_stopped(self):
        self.upload(self.packages[:2])           # stopped after 2 packages

        job = self.upload()                      # same file again

        self.assertEqual(self.counts(job), {"inserted": 3, "updated": 0, "skipped": 2, "failed": 0})
        self.assertEqual(len(self.stored()), DISTINCT)

    def test_changed_version_is_updated_in_place(self):
        self.upload()
        changed = [dict(p, version="2.33.0") if p["name"] == "requests" else p
                   for p in self.packages]

        job = self.upload(changed)

        self.assertEqual(self.counts(job), {"inserted": 0, "updated": 1, "skipped": 4, "failed": 0})
        self.assertEqual(self.stored()["requests"]["version_number"], "2.33.0")
        self.assertEqual(len(self.stored()), DISTINCT)

    def test_rows_from_the_old_upload_are_repaired(self):
        """A scoped package saved as 'pypi' with status unknown is updated"""
        self.sqlite.execute("INSERT INTO packages (package_id, package_name, ecosystem) VALUES (1, '@babel/core', 'pypi')")
        self.sqlite.execute("""INSERT INTO versions (scan_id, package_id, package_name,
            version_number, latest_version, status) VALUES (1, 1, '@babel/core',
            '7.20.0', '7.20.0', 'unknown')""")
        self.sqlite.commit()

        job = self.upload()

        self.assertEqual(self.counts(job), {"inserted": 4, "updated": 1, "skipped": 0, "failed": 0})
        babel = self.stored()["@babel/core"]
        self.assertEqual((babel["ecosystem"], babel["status"]), ("npm", "outdated"))

    def test_failures_are_counted_and_named(self):
        real = DatabaseStorage.insert_version

        def flaky(db_self, scan_id, package_id, name, *args, **kwargs):
            return None if name == "react" else real(db_self, scan_id, package_id, name, *args, **kwargs)

        with mock.patch.object(DatabaseStorage, "insert_version", flaky), \
                contextlib.redirect_stderr(io.StringIO()):
            job = self.upload()

        self.assertEqual(self.counts(job), {"inserted": 4, "updated": 0, "skipped": 0, "failed": 1})
        self.assertEqual(job["failed_names"], ["react"])


class TestUploadJobs(unittest.TestCase):

    def test_a_scan_is_never_processed_twice_at_once(self):
        jobs = UploadJobs()
        first, started = jobs.start(7, distinct=3)
        again, started_again = jobs.start(7, distinct=3)

        self.assertTrue(started)
        self.assertFalse(started_again)
        self.assertTrue(jobs.is_active(7))

        jobs.finish(7)
        self.assertFalse(jobs.is_active(7))
        self.assertTrue(jobs.start(7)[1], "a finished scan can be uploaded again")

    def test_record_counts(self):
        jobs = UploadJobs()
        jobs.start(1)
        for outcome in ("inserted", "updated", "skipped", None):
            jobs.record(1, "pkg", outcome)

        job = jobs.get(1)
        self.assertEqual((job["processed"], job["inserted"], job["updated"],
                          job["skipped"], job["failed"]), (4, 1, 1, 1, 1))


# ============================================================
# 3. SCHEDULED REFRESH NEVER OVERWRITES NEWER DATA
# ============================================================
class TestNoStaleOverwrite(UploadDbTestCase):

    def setUp(self):
        super().setUp()
        LATEST["pkg"] = "2.0.0"
        self.addCleanup(LATEST.pop, "pkg")
        # The upload already stored 2.0.0 (newer than the scan's copy)
        self.sqlite.execute("INSERT INTO packages (package_id, package_name, ecosystem) VALUES (1, 'pkg', 'pypi')")
        self.sqlite.execute("""INSERT INTO versions (version_id, scan_id, package_id,
            package_name, version_number, latest_version, status, baseline_status)
            VALUES (1, 1, 1, 'pkg', '2.0.0', '2.0.0', 'outdated', 'inactive')""")
        self.sqlite.commit()

    def row(self):
        return self.rows("SELECT * FROM versions WHERE version_id = 1")[0]

    def test_scheduled_job_keeps_the_newer_version(self):
        """recalculate_metrics_for_scan re-reads each row: computes for 2.0.0"""
        results = self.db.recalculate_metrics_for_scan(1)

        self.assertEqual(results["refreshed"], 1)
        row = self.row()
        self.assertEqual(row["version_number"], "2.0.0")
        self.assertEqual(row["status"], "up_to_date")          # computed for 2.0.0
        self.assertEqual(row["baseline_status"], "inactive")   # not touched

    def test_upload_during_the_lookup_wins(self):
        """The row changes while the refresh computes: nothing is written"""
        real = db_storage.compute_version_metrics

        def upload_meanwhile(*args, **kwargs):
            self.sqlite.execute("UPDATE versions SET version_number='3.0.0', "
                                "status='outdated' WHERE version_id=1")
            self.sqlite.commit()
            return real(*args, **kwargs)

        with mock.patch.object(db_storage, "compute_version_metrics", upload_meanwhile):
            result = self.db.refresh_version(1, "pkg")

        self.assertEqual(result, "changed")
        self.assertEqual((self.row()["version_number"], self.row()["status"]),
                         ("3.0.0", "outdated"))

    def test_recalculation_skips_a_row_changed_meanwhile(self):
        self.sqlite.execute("UPDATE versions SET version_number='1.0.0' WHERE version_id=1")
        self.sqlite.commit()

        def upload_meanwhile(name):
            self.sqlite.execute("UPDATE versions SET version_number='2.0.0', "
                                "status='up_to_date' WHERE version_id=1")
            self.sqlite.commit()
            return {}

        with mock.patch.object(version_monitor, "get_package_release_info", upload_meanwhile):
            self.db.recalculate_metrics_for_scan(1)

        # recalculation computed "outdated" for 1.0.0, but must not write it
        self.assertEqual(self.row()["status"], "up_to_date")

    def test_auto_monitor_refreshes_through_the_safe_path(self):
        with mock.patch.object(DatabaseStorage, "insert_version") as insert, \
                contextlib.redirect_stdout(io.StringIO()):
            ui_app.auto_monitor_versions()

        insert.assert_not_called()   # the old path rewrote version_number
        self.assertEqual(self.row()["status"], "up_to_date")


# ============================================================
# 4 + 5. UPLOAD ROUTE, STATUS API, PROGRESS BOX
# ============================================================
class RouteTestCase(UploadDbTestCase):
    """Flask test client on the SQLite database; background work runs inline."""

    def setUp(self):
        super().setUp()
        self.sqlite.execute("DELETE FROM scan")   # the route creates its own scan
        self.sqlite.commit()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.background = mock.MagicMock(side_effect=lambda target, *args: target(*args))

        for patcher in (
            mock.patch.object(target_files, "UPLOAD_DIR", Path(tmp.name)),
            mock.patch.object(upload_jobs, "JOBS", self.jobs),
            mock.patch.object(ui_app, "run_in_background", self.background),
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(DatabaseStorage, "get_settings", lambda s: dict(DEFAULT_SETTINGS)),
            mock.patch.object(db_storage, "ensure_schema", lambda: None),
            mock.patch.object(ui_app, "BackgroundScheduler", mock.MagicMock()),
            mock.patch.object(ui_app, "threading", mock.MagicMock()),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        with contextlib.redirect_stdout(io.StringIO()):
            self.client = ui_app.create_app().test_client()

    def post(self, content=CSV, name="deps.csv"):
        """POST an upload (processed inline); returns the response."""
        with contextlib.redirect_stdout(io.StringIO()):
            return self.client.post("/upload-sbom", content_type="multipart/form-data",
                                    data={"file": (io.BytesIO(content), name)})

    def status(self, scan_id):
        return self.client.get(f"/api/upload-status/{scan_id}").get_json()


class TestUploadRoute(RouteTestCase):

    def test_upload_redirects_at_once_and_reports_counts(self):
        response = self.post()

        self.assertEqual(response.status_code, 302)
        scan_id = int(response.headers["Location"].rsplit("/", 1)[1])
        status = self.status(scan_id)
        self.assertEqual(status["state"], "done")
        self.assertEqual((status["csv_rows"], status["distinct"], status["inserted"]), (6, 5, 5))

    def test_same_file_again_reuses_the_scan_and_skips(self):
        first = self.post().headers["Location"]
        second = self.post().headers["Location"]

        self.assertEqual(first, second)
        scan_id = int(second.rsplit("/", 1)[1])
        status = self.status(scan_id)
        self.assertEqual((status["inserted"], status["skipped"]), (0, 5))
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM versions")[0]["n"], DISTINCT)

    def test_upload_already_processing_is_not_started_twice(self):
        scan_id = int(self.post().headers["Location"].rsplit("/", 1)[1])
        self.jobs.start(scan_id, distinct=5)   # pretend it is still running
        self.background.reset_mock()

        self.post()

        self.background.assert_not_called()

    def test_monitor_page_shows_the_progress_box(self):
        location = self.post().headers["Location"]
        with contextlib.redirect_stdout(io.StringIO()):
            html = self.client.get(location).get_data(as_text=True)

        self.assertIn('id="uploadStatus"', html)
        self.assertRegex(html, r'"state":\s*"done"')
        self.assertRegex(html, r'"distinct":\s*5')

    def test_monitor_page_never_recalculates(self):
        """No registry lookups on a page load, during an upload or not"""
        self.sqlite.execute("INSERT INTO scan (scan_id, target_name) VALUES (5, 'big.csv')")
        self.sqlite.commit()
        self.jobs.start(5, target="big.csv", csv_rows=975, distinct=833)

        with mock.patch.object(DatabaseStorage, "recalculate_metrics_for_scan") as recalc, \
                contextlib.redirect_stdout(io.StringIO()):
            html = self.client.get("/monitor/5").get_data(as_text=True)

        recalc.assert_not_called()
        self.assertIn("Upload in progress", html)
        self.assertRegex(html, r'"state":\s*"running"')

        self.jobs.finish(5)
        with mock.patch.object(DatabaseStorage, "recalculate_metrics_for_scan") as recalc, \
                contextlib.redirect_stdout(io.StringIO()):
            self.client.get("/monitor/5")
        recalc.assert_not_called()

    def test_status_of_a_scan_without_upload(self):
        self.assertEqual(self.status(999)["state"], "none")


# ============================================================
# D. NO REGISTRY ("none"): never looked up
# ============================================================
class TestNoRegistry(UploadDbTestCase):

    NOT_FOUND = {"leftpad-gone", "actions/checkout"}   # registry not_found in CSV

    def test_upload_never_looks_up_none_packages(self):
        self.upload()

        looked_up = {name for name, kind in self.lookups}
        self.assertFalse(looked_up & self.NOT_FOUND)
        for name in self.NOT_FOUND:
            row = self.stored()[name]
            self.assertEqual((row["ecosystem"], row["status"]), ("none", "unknown"))
        row = self.rows("SELECT * FROM versions WHERE package_name = 'leftpad-gone'")[0]
        self.assertEqual((row["latest_version"], row["age_tier"]), (None, None))

    def test_metrics_for_none_make_no_lookup(self):
        metrics = compute_version_metrics("bitflags", "2.11.1", ecosystem="none")

        self.assertEqual(self.lookups, [])
        self.assertEqual((metrics["status"], metrics["latest_version"], metrics["age_tier"]),
                         ("unknown", None, None))

    def test_scheduled_job_never_looks_up_none_packages(self):
        self.sqlite.execute("INSERT INTO packages (package_id, package_name, ecosystem) VALUES (9, 'bitflags', 'none')")
        self.sqlite.execute("""INSERT INTO versions (scan_id, package_id, package_name,
            version_number, latest_version, status) VALUES (1, 9, 'bitflags',
            '2.11.1', '1.2.0', 'outdated')""")
        self.sqlite.commit()

        self.db.recalculate_metrics_for_scan(1)

        self.assertEqual(self.lookups, [])
        self.assertEqual(self.stored()["bitflags"]["status"], "unknown")


# ============================================================
# A + C. STATUS AND TIER ALWAYS AGREE
# ============================================================
def days_ago(n):
    from datetime import date, timedelta
    return (date.today() - timedelta(days=n)).isoformat()


class TestStatusAndTierAgree(UploadDbTestCase):

    def releases(self, dates):
        return mock.patch.object(version_monitor, "get_package_release_info",
                                 lambda name: dict(dates))

    def test_failed_lookup_is_unknown_not_up_to_date(self):
        """A row stored with latest == installed (old behaviour) whose lookup
        fails becomes unknown, with no latest version and no tier"""
        self.sqlite.execute("INSERT INTO packages (package_id, package_name, ecosystem) VALUES (1, 'block-buffer', 'pypi')")
        self.sqlite.execute("""INSERT INTO versions (scan_id, package_id, package_name,
            version_number, latest_version, status, age_tier) VALUES (1, 1,
            'block-buffer', '0.10.4', '0.10.4', 'up_to_date', 'Stale')""")
        self.sqlite.commit()

        self.db.recalculate_metrics_for_scan(1)

        row = self.rows("SELECT * FROM versions WHERE package_name = 'block-buffer'")[0]
        self.assertEqual((row["status"], row["latest_version"], row["age_tier"]),
                         ("unknown", None, None))

    def test_up_to_date_is_fresh_even_if_old(self):
        """installed == latest, released 800 days ago -> up_to_date + Fresh"""
        with self.releases({"2.31.0": days_ago(900), "2.32.0": days_ago(800)}):
            m = compute_version_metrics("requests", "2.32.0", ecosystem="pypi")
        self.assertEqual((m["status"], m["age_tier"]), ("up_to_date", "Fresh"))

    def test_up_to_date_with_an_old_latest_release_is_abandoned(self):
        with self.releases({"2.32.0": days_ago(1200)}):
            m = compute_version_metrics("requests", "2.32.0", ecosystem="pypi")
        self.assertEqual((m["status"], m["age_tier"]), ("up_to_date", "Abandoned"))

    def test_outdated_tier_is_days_behind_latest(self):
        """2.31.0 released 400 days before 2.32.0 -> Stale"""
        with self.releases({"2.31.0": days_ago(410), "2.32.0": days_ago(10)}):
            m = compute_version_metrics("requests", "2.31.0", ecosystem="pypi")
        self.assertEqual((m["status"], m["age_tier"]), ("outdated", "Stale"))

    def test_up_to_date_is_never_stale_or_aging(self):
        """Whatever the dates, an up-to-date row is Fresh or Abandoned"""
        for age in (0, 31, 200, 366, 1000, 1094, 1095, 3000):
            with self.releases({"2.32.0": days_ago(age)}):
                m = compute_version_metrics("requests", "2.32.0", ecosystem="pypi")
            self.assertEqual(m["status"], "up_to_date")
            self.assertIn(m["age_tier"], ("Fresh", "Abandoned"), age)

    def test_upload_and_scheduled_job_store_the_same_values(self):
        query = ("SELECT package_name, status, latest_version, age_tier, "
                 "days_since_release FROM versions ORDER BY package_name")
        with self.releases({"2.31.0": days_ago(410), "2.32.0": days_ago(10)}):
            self.upload()
            after_upload = self.rows(query)
            self.db.recalculate_metrics_for_scan(1)
            after_job = self.rows(query)
        self.assertEqual(after_upload, after_job)


# ============================================================
# 1 + 3. PAGES: N/A for missing values, no registry lookups
# ============================================================
class TestPages(RouteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("""
            INSERT INTO scan (scan_id, target_name) VALUES (1, 'deps.csv');
            INSERT INTO packages (package_id, package_name, ecosystem) VALUES (1, 'gone', 'none'), (2, 'requests', 'pypi'),
                                        (3, 'flask', 'pypi');
            INSERT INTO versions (scan_id, package_id, package_name, version_number,
                latest_version, status, release_date, days_outdated, versions_behind,
                days_since_release, age_tier)
            VALUES (1, 1, 'gone', '1.0.0', NULL, 'unknown', '2026-10-14 10:00:00',
                    0, '0.0.0', NULL, NULL),
                   (1, 2, 'requests', '2.31.0', '2.32.0', 'outdated',
                    '2026-10-14 10:00:00', 400, '0.1.0', 410, 'Stale'),
                   (1, 3, 'flask', '3.0.0', '3.0.0', 'up_to_date',
                    '2026-10-14 10:00:00', 0, '0.0.0', 300, 'Fresh');
        """)
        self.sqlite.commit()

        def no_lookup(*args, **kwargs):
            raise AssertionError("registry lookup during a page load")

        for name in ("get_latest_version", "get_package_release_info",
                     "get_npm_release_info", "get_github_release_info"):
            patcher = mock.patch.object(version_monitor, name, no_lookup)
            patcher.start()
            self.addCleanup(patcher.stop)

    def page(self, url):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.get_data(as_text=True)

    def test_every_page_loads_without_lookups(self):
        for url in ("/dashboard", "/monitor/1", "/monitor/1?outdated=1",
                    "/packages", "/packages?tier=unknown", "/packages?sort=tier",
                    "/repos", "/api/monitored"):
            self.page(url)

    def test_monitor_shows_na_and_unknown(self):
        html = self.page("/monitor/1")
        row = html.split("<td>gone</td>", 1)[1].split("</tr>", 1)[0]

        self.assertIn('<span class="na">N/A</span>', row)
        self.assertIn("Unknown", row)
        self.assertNotIn("None", row)
        self.assertNotIn("Outdated", row)

    def test_monitor_outdated_filter_excludes_unknown(self):
        html = self.page("/monitor/1?outdated=1")
        self.assertIn("<td>requests</td>", html)
        self.assertNotIn("<td>gone</td>", html)

    def test_packages_shows_na_for_missing_latest(self):
        html = self.page("/packages")
        row = html.split("<td>gone</td>", 1)[1].split("</tr>", 1)[0]
        self.assertIn("N/A", row)
        self.assertNotIn("None", row)

    def test_api_returns_null_latest(self):
        data = self.client.get("/api/monitored").get_json()
        gone = next(r for r in data if r["package_name"] == "gone")
        self.assertIsNone(gone["latest_version"])

    def test_dashboard_tier_captions_say_days_behind(self):
        html = self.page("/dashboard")
        self.assertIn("days behind the latest release", html)
        self.assertNotIn("Installed version &gt; 365 days old", html)

    def test_run_monitor_starts_the_job_in_the_background(self):
        background = mock.MagicMock()
        with mock.patch.object(ui_app, "run_in_background", background):
            html = self.page("/run-monitor")

        background.assert_called_once_with(ui_app.auto_monitor_versions)
        self.assertIn("started in the background", html)


if __name__ == "__main__":
    unittest.main()
