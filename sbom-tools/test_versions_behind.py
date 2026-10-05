# sbom-tools/test_versions_behind.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# No network or database access.

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_storage import calculate_versions_behind, compute_severity_from_string


class TestCalculateVersionsBehind(unittest.TestCase):
    """Only the first differing part (major, then minor, then patch) counts."""

    def test_major_differs(self):
        """1.26.5 -> 2.8.0 is 1.0.0 (was 0.-9.5)"""
        self.assertEqual(calculate_versions_behind("1.26.5", "2.8.0"), "1.0.0")

    def test_minor_differs(self):
        """1.2.9 -> 1.5.0 is 0.3.0 (was 0.2.1)"""
        self.assertEqual(calculate_versions_behind("1.2.9", "1.5.0"), "0.3.0")

    def test_major_differs_ignores_minor_and_patch(self):
        """3.0.0 -> 6.8.3 is 3.0.0 (was 3.8.3)"""
        self.assertEqual(calculate_versions_behind("3.0.0", "6.8.3"), "3.0.0")

    def test_patch_differs(self):
        """1.2.3 -> 1.2.7 is 0.0.4"""
        self.assertEqual(calculate_versions_behind("1.2.3", "1.2.7"), "0.0.4")

    def test_installed_newer_than_latest_is_zero(self):
        """3.8.20 -> 3.8.3 is 0.0.0, never negative (was -1.9.-7)"""
        self.assertEqual(calculate_versions_behind("3.8.20", "3.8.3"), "0.0.0")

    def test_same_version_is_zero(self):
        """2.0.0 -> 2.0.0 is 0.0.0"""
        self.assertEqual(calculate_versions_behind("2.0.0", "2.0.0"), "0.0.0")

    def test_unparseable_version_is_na(self):
        """"main" -> 1.0.0 is N/A (not 0.0.0)"""
        self.assertEqual(calculate_versions_behind("main", "1.0.0"), "N/A")

    def test_missing_latest_is_na(self):
        """Missing latest version is N/A"""
        self.assertEqual(calculate_versions_behind("1.0.0", None), "N/A")

    def test_leading_v_and_short_versions(self):
        """v1.2 -> v1.10 is 0.8.0"""
        self.assertEqual(calculate_versions_behind("v1.2", "v1.10"), "0.8.0")

    def test_never_negative(self):
        """No part is ever negative, across a grid of version pairs"""
        nums = (0, 1, 3, 9, 10, 26)
        versions = [f"{a}.{b}.{c}" for a in nums for b in nums for c in nums]
        for cur in versions[::7]:
            for lat in versions[::5]:
                gap = calculate_versions_behind(cur, lat)
                self.assertNotIn("-", gap, f"{cur} -> {lat} gave {gap}")
                self.assertLessEqual(sum(int(x) > 0 for x in gap.split(".")), 1)


class TestRiskLevelUsesCorrectedGap(unittest.TestCase):

    def test_major_gap_counts(self):
        """1.26.5 -> 2.8.0 (gap 1.0.0) is medium risk"""
        gap = calculate_versions_behind("1.26.5", "2.8.0")
        self.assertEqual(compute_severity_from_string(gap, 0), "medium")

    def test_na_gap_still_uses_time_risk(self):
        """N/A gap, 1500 days outdated is still high risk (time-based)"""
        self.assertEqual(compute_severity_from_string("N/A", 1500), "high")

    def test_na_gap_recent_is_low(self):
        """N/A gap, 10 days outdated is low risk"""
        self.assertEqual(compute_severity_from_string("N/A", 10), "low")


if __name__ == "__main__":
    unittest.main(verbosity=2)
