# sbom-tools/test_age_tiers.py
#
# Run from the project root:
#   python -m unittest -v sbom-tools/test_age_tiers.py
# or from sbom-tools/:
#   python -m unittest -v test_age_tiers
#
# No network or database access: compute_age_tier() only uses the release
# dates passed in, and importing db_storage doesn't open a connection.
#
# Tier = how far the installed version's release date is BEHIND the latest
# version's release date (Abandoned: latest release 3+ years old).

import os
import sys
import unittest
from datetime import date, datetime, timedelta

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
TODAY = date(2026, 10, 14)
LATEST = TODAY - timedelta(days=10)   # latest release 10 days ago: not abandoned


def days_ago(n):
    """YYYY-MM-DD date string n days before today (format the APIs return)."""
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d")


def behind(days):
    """Tier of an installed release `days` before a recent latest release."""
    return classify_age(LATEST - timedelta(days=days), LATEST, TODAY)


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


class TestDaysBehindBoundaries(unittest.TestCase):
    """Days behind the latest release, on a package that still releases."""

    def test_0_days_behind_is_fresh(self):
        """Installed == latest release date -> Fresh"""
        self.assertEqual(behind(0), AgeTier.FRESH)

    def test_30_days_behind_is_fresh(self):
        self.assertEqual(behind(30), AgeTier.FRESH)

    def test_31_days_behind_is_aging(self):
        self.assertEqual(behind(31), AgeTier.AGING)

    def test_365_days_behind_is_aging(self):
        self.assertEqual(behind(365), AgeTier.AGING)

    def test_366_days_behind_is_stale(self):
        self.assertEqual(behind(366), AgeTier.STALE)

    def test_installed_newer_than_latest_is_fresh(self):
        """A pre-release newer than the latest stable is 0 days behind"""
        self.assertEqual(behind(-40), AgeTier.FRESH)

    def test_old_but_up_to_date_is_fresh(self):
        """The installed version's own age doesn't matter, only the gap:
        installed == latest, both released 2 years ago -> Fresh"""
        two_years = TODAY - timedelta(days=730)
        self.assertEqual(classify_age(two_years, two_years, TODAY), AgeTier.FRESH)


class TestAbandoned(unittest.TestCase):
    """Abandoned: the latest release is 3+ years old; wins over the gap."""

    def tier(self, latest_age, gap=0):
        latest = TODAY - timedelta(days=latest_age)
        return classify_age(latest - timedelta(days=gap), latest, TODAY)

    def test_one_day_under_three_years_is_not_abandoned(self):
        self.assertEqual(self.tier(THREE_YEARS - 1), AgeTier.FRESH)

    def test_exactly_three_years_is_abandoned(self):
        self.assertEqual(self.tier(THREE_YEARS), AgeTier.ABANDONED)

    def test_abandoned_wins_over_stale_gap(self):
        self.assertEqual(self.tier(THREE_YEARS + 1, gap=900), AgeTier.ABANDONED)


class TestInputs(unittest.TestCase):

    def test_accepts_strings_dates_and_datetimes(self):
        self.assertEqual(classify_age("2026-01-01", date(2026, 3, 1), TODAY), AgeTier.AGING)
        self.assertEqual(
            classify_age(datetime(2026, 9, 1, 12), "2026-09-20T08:00:00Z", TODAY),
            AgeTier.FRESH,
        )

    def test_today_defaults_to_the_real_date(self):
        self.assertEqual(classify_age(days_ago(100), days_ago(50)), AgeTier.AGING)


class TestUnknown(unittest.TestCase):
    """A missing date -> None, stored as NULL and shown as "unknown"."""

    def test_no_dates(self):
        self.assertIsNone(classify_age(None, None))

    def test_no_installed_date(self):
        self.assertIsNone(classify_age(None, LATEST, TODAY))

    def test_no_latest_date_even_if_installed_is_old(self):
        self.assertIsNone(classify_age(TODAY - timedelta(days=4000), None, TODAY))

    def test_invalid_date(self):
        self.assertIsNone(classify_age("not a date", LATEST, TODAY))

    def test_compute_age_tier_no_releases(self):
        self.assertIsNone(compute_age_tier({}, "1.0.0", "2.0.0"))

    def test_compute_age_tier_no_latest_version(self):
        """Lookup failed (latest unknown) -> no tier"""
        self.assertIsNone(compute_age_tier({"1.0.0": days_ago(10)}, "1.0.0", None))

    def test_compute_age_tier_tags_without_dates(self):
        self.assertIsNone(compute_age_tier({"v1.0": None, "v1.1": None}, "v1.0", "v1.1"))


class TestComputeAgeTierExamples(unittest.TestCase):
    """One example per tier, from a releases dict like the registries give."""

    def test_example_fresh(self):
        """2.0.0 released 20 days before latest 2.1.0"""
        releases = {"2.0.0": days_ago(32), "2.1.0": days_ago(12)}
        self.assertEqual(compute_age_tier(releases, "2.0.0", "2.1.0"), "Fresh")

    def test_example_up_to_date_is_fresh(self):
        """Installed is the latest, released 800 days ago -> Fresh (0 behind)"""
        releases = {"1.0.0": days_ago(900), "1.1.0": days_ago(800)}
        self.assertEqual(compute_age_tier(releases, "1.1.0", "1.1.0"), "Fresh")

    def test_example_aging(self):
        releases = {"2.0.0": days_ago(212), "2.1.0": days_ago(12)}
        self.assertEqual(compute_age_tier(releases, "2.0.0", "2.1.0"), "Aging")

    def test_example_stale(self):
        releases = {"1.0.0": days_ago(800), "2.1.0": days_ago(12)}
        self.assertEqual(compute_age_tier(releases, "1.0.0", "2.1.0"), "Stale")

    def test_example_abandoned(self):
        """Latest release (1.4.0) is 1200 days old"""
        releases = {"1.3.0": days_ago(1500), "1.4.0": days_ago(1200)}
        self.assertEqual(compute_age_tier(releases, "1.3.0", "1.4.0"), "Abandoned")

    def test_v_prefixed_tags(self):
        releases = {"v1.0.0": days_ago(400), "v1.2.0": days_ago(5)}
        self.assertEqual(compute_age_tier(releases, "1.0.0", "v1.2.0"), "Stale")


if __name__ == "__main__":
    unittest.main(verbosity=2)
