# sbom-tools/test_version_matching.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# PyPI versions match by PEP 440 (26 == 26.0, 0.8 == 0.8.0); dev/local builds,
# unparseable versions and npm only match exactly. No network, no database:
# registry lookups are patched and any HTTP request fails the test.

import os
import sys
import unittest
from datetime import date, timedelta
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import version_monitor                                 # noqa: E402
from db_storage import compute_version_metrics         # noqa: E402
from version_monitor import compare_versions, match_release, same_version  # noqa: E402


def days_ago(n):
    return (date.today() - timedelta(days=n)).isoformat()


def no_http(url, *args, **kwargs):
    raise AssertionError(f"unexpected HTTP request: {url}")


class TestSameVersion(unittest.TestCase):

    def test_pypi_matches_by_pep440(self):
        self.assertTrue(same_version("26", "26.0", "pypi"))
        self.assertTrue(same_version("0.8", "0.8.0", "pypi"))
        self.assertTrue(same_version("2", "2.0", "pypi"))

    def test_npm_is_exact(self):
        self.assertFalse(same_version("2", "2.0.0", "npm"))
        self.assertTrue(same_version("2.0.0", "2.0.0", "npm"))

    def test_no_ecosystem_is_exact(self):
        self.assertFalse(same_version("26", "26.0"))

    def test_dev_and_local_builds_are_never_approximated(self):
        self.assertFalse(same_version("3.7.1.dev24+g2b4372bd6", "3.7.1", "pypi"))
        self.assertFalse(same_version("3.7.1+local", "3.7.1", "pypi"))
        self.assertFalse(same_version("3.7.1", "3.7.1.dev24+g2b4372bd6", "pypi"))
        self.assertTrue(same_version("3.7.1.dev24+g2b4372bd6", "3.7.1.dev24+g2b4372bd6", "pypi"))

    def test_unparseable_falls_back_to_exact(self):
        self.assertTrue(same_version("not a version", "not a version", "pypi"))
        self.assertFalse(same_version("not a version", "1.0", "pypi"))
        self.assertFalse(same_version(None, "1.0", "pypi"))

    def test_match_release(self):
        releases = {"26.0": "2026-01-20", "26.3": "2026-09-01"}
        self.assertEqual(match_release(releases, "26", "pypi"), "26.0")
        self.assertEqual(match_release(releases, "26.3", "pypi"), "26.3")
        self.assertIsNone(match_release(releases, "26", "npm"))
        self.assertIsNone(match_release({"2.0.0": "2020-01-01"}, "2", "npm"))

    def test_compare_versions(self):
        self.assertEqual(compare_versions("0.8", "0.8.0", "pypi"), "up_to_date")
        self.assertEqual(compare_versions("0.8", "0.8.0"), "outdated")   # other callers: exact
        self.assertEqual(compare_versions("2", "2.0.0", "npm"), "outdated")
        self.assertEqual(compare_versions("2", None, "pypi"), "unknown")


class TestComputeVersionMetrics(unittest.TestCase):
    """compute_version_metrics end to end, on fake registry answers."""

    def metrics(self, name, version, ecosystem, latest, releases):
        with mock.patch("requests.get", no_http), \
             mock.patch.object(version_monitor, "get_latest_version", lambda n, kind: latest), \
             mock.patch.object(version_monitor, "get_package_release_info", lambda n: dict(releases)), \
             mock.patch.object(version_monitor, "get_npm_release_info", lambda n: dict(releases)):
            return compute_version_metrics(name, version, ecosystem=ecosystem)

    def test_pypi_short_version_finds_its_release_date(self):
        """packaging 26 matches the 26.0 release: real dates, not the 90-day guess"""
        m = self.metrics("packaging", "26", "pypi", "26.3",
                         {"26.0": days_ago(300), "26.3": days_ago(20)})
        self.assertEqual(m["status"], "outdated")
        self.assertEqual(m["days_since_release"], 300)
        self.assertEqual(m["days_outdated"], 280)
        self.assertEqual(m["age_tier"], "Aging")

    def test_pypi_equal_versions_are_up_to_date(self):
        """0.8 installed, latest 0.8.0: same release"""
        m = self.metrics("gradio-client", "0.8", "pypi", "0.8.0", {"0.8.0": days_ago(400)})
        self.assertEqual(m["status"], "up_to_date")
        self.assertEqual(m["days_outdated"], 0)
        self.assertEqual(m["versions_behind"], "0.0.0")
        self.assertEqual(m["days_since_release"], 400)
        self.assertEqual(m["age_tier"], "Fresh")

    def test_dev_build_is_unchanged(self):
        m = self.metrics("somepkg", "3.7.1.dev24+g2b4372bd6", "pypi", "3.7.1",
                         {"3.7.1": days_ago(50)})
        self.assertEqual(m["status"], "outdated")
        self.assertIsNone(m["days_since_release"])
        self.assertIsNone(m["age_tier"])

    def test_npm_is_unchanged(self):
        m = self.metrics("leftpad", "2", "npm", "2.0.0", {"2.0.0": days_ago(50)})
        self.assertEqual(m["status"], "outdated")
        self.assertIsNone(m["days_since_release"])
        self.assertIsNone(m["age_tier"])


if __name__ == "__main__":
    unittest.main()
