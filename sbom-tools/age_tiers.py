# sbom-tools/age_tiers.py
#
# Age tiers for an installed package version, based on:
#
#   days_since_release      = age of the installed version (the "Days Since
#                             Release" column on /packages)
#   days_since_last_release = age of the package's most recent release of
#                             any version (including pre-releases)

from enum import Enum

# ============================
# THRESHOLDS (days)
# ============================
FRESH_MAX_DAYS = 30                 # Fresh: installed version 0-30 days old
AGING_MAX_DAYS = 365                # Aging: 31-365 days old
                                    # Stale: more than 365 days old
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


def classify_age(days_since_release, days_since_last_release):
    """
    Return the AgeTier for a package, or None when it can't be determined.

    days_since_release:      age in days of the installed version, or None
    days_since_last_release: age in days of the package's latest release, or None

    Abandoned (latest release 3+ years old) wins over the others; otherwise
    the tier is the installed version's age: Fresh <= 30 days,
    Aging 31-365 days, Stale > 365 days. Anything over 365 days is therefore
    never Fresh (matches the default "Requires attention" threshold).
    """
    if (days_since_last_release is not None
            and days_since_last_release >= ABANDONED_MIN_DAYS_SINCE_LAST_RELEASE):
        return AgeTier.ABANDONED

    if days_since_release is None:
        return None

    days_since_release = max(days_since_release, 0)

    if days_since_release <= FRESH_MAX_DAYS:
        return AgeTier.FRESH
    if days_since_release <= AGING_MAX_DAYS:
        return AgeTier.AGING
    return AgeTier.STALE


def tier_label(tier):
    """String to store in versions.age_tier (None stays None -> NULL)."""
    return tier.value if tier else None
