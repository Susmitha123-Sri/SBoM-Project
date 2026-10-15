# sbom-tools/risk.py
#
# Version risk of a package, from signals already stored on its versions row
# (see db_storage.update_package_risk_for_scan for where they come from):
#
#   age_tier     Fresh / Aging / Stale / Abandoned, or None when a release
#                date is missing (see age_tiers.py)
#   days_behind  versions.days_outdated: days the installed release is behind
#                the latest release. Only trusted when age_tier is known;
#                without dates it holds an estimate.
#   vuln_count   distinct vulnerabilities in scan_results for the row, or
#                None when there are none. "No rows" can't be told apart
#                from "never scanned", so it is never shown as 0.
#                Note: scan_results rows stay attached when a row's version
#                is upgraded in place, so this can overcount after upgrades.
#
# score_risk() is the one scoring function. Change RISK_MODEL_VERSION
# whenever points or cut-offs change, so stored scores from different models
# can be told apart (packages.risk_model_version).

from age_tiers import TIER_NAMES, AgeTier, FRESH_MAX_DAYS, AGING_MAX_DAYS

RISK_MODEL_VERSION = "v1"

# ============================
# POINTS (score is capped at 100)
# ============================
# Days behind the latest release: (upper bound in days, points)
DAYS_BEHIND_POINTS = [
    (FRESH_MAX_DAYS, 0),          # 0-30 days
    (AGING_MAX_DAYS, 15),         # 31-365 days
    (2 * 365, 30),                # 366-730 days
]
DAYS_BEHIND_MAX_POINTS = 40       # more than 730 days

ABANDONED_POINTS = 25             # latest release 3+ years old

# Known vulnerabilities: (minimum count, points), checked highest first
VULN_POINTS = [(5, 45), (2, 30), (1, 20)]

MAX_SCORE = 100

# ============================
# LEVELS (minimum score), checked highest first
# ============================
LEVEL_CUTOFFS = [(70, "Critical"), (45, "High"), (20, "Medium"), (0, "Low")]

RISK_LEVELS = [name for _, name in LEVEL_CUTOFFS]   # Critical first
UNKNOWN_RISK = "Unknown"          # age unknown and no known vulnerabilities


def days_behind_points(days):
    for max_days, points in DAYS_BEHIND_POINTS:
        if days <= max_days:
            return points
    return DAYS_BEHIND_MAX_POINTS


def vuln_points(count):
    for min_count, points in VULN_POINTS:
        if count >= min_count:
            return points
    return 0


def level_for(score):
    for min_score, name in LEVEL_CUTOFFS:
        if score >= min_score:
            return name
    return LEVEL_CUTOFFS[-1][1]


def describe_days(days):
    """'up to date', '12 days behind', '5 months behind', '2 years behind'."""
    if days <= 0:
        return "up to date"
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} behind"
    if days < 2 * 365:
        return f"{days // 30} months behind"
    return f"{days // 365} years behind"


def score_risk(age_tier, days_behind, vuln_count):
    """
    Risk of one package from its latest-scan row. Returns a dict:

        score          0-100, or None when the level is Unknown
        level          Critical / High / Medium / Low / Unknown
        reasons        short readable text, e.g. "Stale; 2 years behind; ..."
        tier           the age tier used, or None when unknown
        days_behind    the days used, or None when not trusted
        vuln_count     known vulnerability count, or None (no data)
        is_abandoned   True/False, or None when the age is unknown
        model_version  RISK_MODEL_VERSION

    Unknown age is neither safe nor risky: level Unknown with no score,
    unless known vulnerabilities give a score on their own.
    """
    tier = age_tier if age_tier in TIER_NAMES else None
    vulns = int(vuln_count) if vuln_count else None

    reasons = []
    score = 0

    if tier is None:
        days = None
        is_abandoned = None
        reasons.append("Age unknown (no release dates)")
    else:
        days = max(int(days_behind or 0), 0)
        is_abandoned = tier == AgeTier.ABANDONED.value
        reasons.append("Abandoned (no release in 3+ years)" if is_abandoned else tier)
        reasons.append(describe_days(days))
        score += days_behind_points(days)
        if is_abandoned:
            score += ABANDONED_POINTS

    if vulns:
        reasons.append(f"{vulns} vulnerabilit{'ies' if vulns != 1 else 'y'}")
        score += vuln_points(vulns)
    else:
        reasons.append("no vulnerability data")

    if tier is None and not vulns:
        final_score, level = None, UNKNOWN_RISK
    else:
        final_score = min(score, MAX_SCORE)
        level = level_for(final_score)

    return {
        "score": final_score,
        "level": level,
        "reasons": "; ".join(reasons),
        "tier": tier,
        "days_behind": days,
        "vuln_count": vulns,
        "is_abandoned": is_abandoned,
        "model_version": RISK_MODEL_VERSION,
    }
