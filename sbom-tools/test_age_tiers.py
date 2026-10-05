# sbom-tools/test_age_tiers.py
#
# Run from the project root:
#   python -m unittest -v sbom-tools/test_age_tiers.py
# or from sbom-tools/:
#   python -m unittest -v test_age_tiers
#
# No network or database access: compute_age_tier() only uses the release
# dates passed in, and importing db_storage doesn't open a connection.

import os
import sys
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from age_tiers import (
    AgeTier,
    classify_age,
    FRESH_MAX_DAYS,
    AGING_MAX_DAYS,
    ABANDONED_MIN_DAYS_SINCE_LAST_RELEASE,
)
from db_storage import compute_age_tier

THREE_YEARS = ABANDONED_MIN_DAYS_SINCE_LAST_RELEASE   # 1095 days
RECENT = 10   # latest release 10 days ago: package is clearly not abandoned


def days_ago(n):
    """YYYY-MM-DD date string n days before today (format the APIs return)."""
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d")


class TestTierNames(unittest.TestCase):

    def test_enum_values_are_exact_tier_names(self):
        """Enum values are exactly Fresh, Aging, Stale, Abandoned"""
        self.assertEqual(
            [t.value for t in AgeTier],
            ["Fresh", "Aging", "Stale", "Abandoned"],
        )

    def test_thresholds(self):
        """Thresholds: Fresh <= 30, Aging <= 365, Abandoned >= 1095 days"""
        self.assertEqual(FRESH_MAX_DAYS, 30)
        self.assertEqual(AGING_MAX_DAYS, 365)
        self.assertEqual(ABANDONED_MIN_DAYS_SINCE_LAST_RELEASE, 3 * 365)


class TestClassifyAgeBoundaries(unittest.TestCase):
    """Installed-version age boundaries, on a package that still releases."""

    def assertTier(self, days_since_release, expected):
        self.assertEqual(classify_age(days_since_release, RECENT), expected)

    def test_0_days_is_fresh(self):
        """0 days -> Fresh"""
        self.assertTier(0, AgeTier.FRESH)

    def test_30_days_is_fresh(self):
        """30 days -> Fresh (upper boundary)"""
        self.assertTier(30, AgeTier.FRESH)

    def test_31_days_is_aging(self):
        """31 days -> Aging (lower boundary)"""
        self.assertTier(31, AgeTier.AGING)

    def test_365_days_is_aging(self):
        """365 days -> Aging (upper boundary)"""
        self.assertTier(365, AgeTier.AGING)

    def test_366_days_is_stale(self):
        """366 days -> Stale (lower boundary)"""
        self.assertTier(366, AgeTier.STALE)

    def test_requires_attention_is_never_fresh(self):
        """Every age > 365 days (Requires attention) is never Fresh"""
        for days in range(366, 5000):
            for last_release in (None, 0, RECENT, THREE_YEARS):
                self.assertNotEqual(classify_age(days, last_release), AgeTier.FRESH)


class TestClassifyAgeAbandoned(unittest.TestCase):
    """Abandoned: the package's latest release is 3+ years old; wins over age."""

    def test_one_day_under_three_years_is_not_abandoned(self):
        """Latest release 1094 days old -> not Abandoned (Stale by age)"""
        self.assertEqual(classify_age(1094, THREE_YEARS - 1), AgeTier.STALE)

    def test_exactly_three_years_is_abandoned(self):
        """Latest release 1095 days old -> Abandoned"""
        self.assertEqual(classify_age(1095, THREE_YEARS), AgeTier.ABANDONED)

    def test_one_day_over_three_years_is_abandoned(self):
        """Latest release 1096 days old -> Abandoned"""
        self.assertEqual(classify_age(1096, THREE_YEARS + 1), AgeTier.ABANDONED)

    def test_abandoned_wins_over_fresh_age(self):
        """Abandoned beats the installed version's own age"""
        self.assertEqual(classify_age(0, THREE_YEARS + 1), AgeTier.ABANDONED)


class TestUnknown(unittest.TestCase):
    """No release date -> None, stored as NULL and shown as "unknown"."""

    def test_classify_age_without_dates_is_unknown(self):
        """classify_age(None, None) -> unknown (None)"""
        self.assertIsNone(classify_age(None, None))

    def test_classify_age_without_installed_date_is_unknown(self):
        """No installed-version date, recent package -> unknown (None)"""
        self.assertIsNone(classify_age(None, RECENT))

    def test_compute_age_tier_no_releases_is_unknown(self):
        """compute_age_tier({}, None) -> unknown (None)"""
        self.assertIsNone(compute_age_tier({}, None))

    def test_compute_age_tier_dates_missing_is_unknown(self):
        """compute_age_tier with tags but no dates -> unknown (None)"""
        self.assertIsNone(compute_age_tier({"v1.0": None, "v1.1": None}, None))


class TestComputeAgeTierExamples(unittest.TestCase):
    """One end-to-end example per tier, from a releases dict like the APIs give."""

    def test_example_fresh(self):
        """Fresh: installed 2.1.0 released 12 days ago"""
        releases = {"2.0.0": days_ago(200), "2.1.0": days_ago(12)}
        self.assertEqual(compute_age_tier(releases, 12), "Fresh")

    def test_example_aging(self):
        """Aging: installed 2.0.0 released 200 days ago, 2.1.0 out 12 days ago"""
        releases = {"2.0.0": days_ago(200), "2.1.0": days_ago(12)}
        self.assertEqual(compute_age_tier(releases, 200), "Aging")

    def test_example_stale(self):
        """Stale: installed 1.0.0 released 800 days ago, 2.1.0 out 12 days ago"""
        releases = {"1.0.0": days_ago(800), "2.1.0": days_ago(12)}
        self.assertEqual(compute_age_tier(releases, 800), "Stale")

    def test_example_abandoned(self):
        """Abandoned: newest release (1.4.0) is 1200 days old"""
        releases = {"1.3.0": days_ago(1500), "1.4.0": days_ago(1200)}
        self.assertEqual(compute_age_tier(releases, 1500), "Abandoned")


if __name__ == "__main__":
    unittest.main(verbosity=2)
