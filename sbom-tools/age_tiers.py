# sbom-tools/age_tiers.py
#
# Age tier of an installed package version: how far its release is BEHIND
# the latest release (not how old it is). Both dates come from the registry:
#
#   installed_release = release date of the installed version
#   latest_release    = release date of the latest version (the same latest
#                       version the status compares against)
#
#   Abandoned  latest release is 3+ years old
#   Fresh      installed release is at most 30 days behind the latest one
#              (an up-to-date package is 0 days behind, so always Fresh or
#              Abandoned)
#   Aging      31-365 days behind
#   Stale      more than 365 days behind
#   unknown    either date is missing (stored as NULL)
#
# The installed version's own age (days_since_release) is a separate measure,
# used for "Requires attention" on /packages.
#
# data-prep/add_release_dates.py imports classify_age, so the CSV tiers and
# the app's tiers always use this one definition.

from datetime import date, datetime
from enum import Enum

# ============================
# THRESHOLDS (days)
# ============================
FRESH_MAX_DAYS = 30                 # Fresh: <= 30 days behind the latest release
AGING_MAX_DAYS = 365                # Aging: 31-365 days behind
                                    # Stale: more than 365 days behind
ABANDONED_MIN_DAYS_SINCE_LAST_RELEASE = 3 * 365   # Abandoned: latest release 3+ years old

# Shown when there is no release date to classify from (stored as NULL)
UNKNOWN_TIER = "unknown"


class AgeTier(str, Enum):
    FRESH = "Fresh"
    AGING = "Aging"
    STALE = "Stale"
    ABANDONED = "Abandoned"


# Display / sort order: Abandoned first, unknown last
TIER_ORDER = [AgeTier.ABANDONED, AgeTier.STALE, AgeTier.AGING, AgeTier.FRESH]
TIER_NAMES = [t.value for t in TIER_ORDER]


def to_date(value):
    """date from a date, datetime or "YYYY-MM-DD..." string; None if missing/invalid."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def classify_age(installed_release, latest_release, today=None):
    """
    AgeTier from the installed version's and the latest version's release
    dates (date, datetime or "YYYY-MM-DD"), or None when either is missing.

    Abandoned when the latest release is 3+ years before today; otherwise
    by days behind = latest_release - installed_release (an installed
    version newer than latest counts as 0): Fresh <= 30, Aging 31-365,
    Stale > 365.
    """
    installed, latest = to_date(installed_release), to_date(latest_release)
    if installed is None or latest is None:
        return None

    today = to_date(today) or date.today()
    if (today - latest).days >= ABANDONED_MIN_DAYS_SINCE_LAST_RELEASE:
        return AgeTier.ABANDONED

    days_behind = max((latest - installed).days, 0)

    if days_behind <= FRESH_MAX_DAYS:
        return AgeTier.FRESH
    if days_behind <= AGING_MAX_DAYS:
        return AgeTier.AGING
    return AgeTier.STALE


def tier_label(tier):
    """String to store in versions.age_tier (None stays None -> NULL)."""
    return tier.value if tier else None
