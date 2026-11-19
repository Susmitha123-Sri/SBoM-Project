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
# score_risk() is the one scoring function. Its points and cut-offs are
# parameters stored in the settings table (Settings page, "Risk formula");
# every distinct set of parameters is a model version (risk_models table,
# packages.risk_model_version), so stored scores from different formulas can
# be told apart. DEFAULT_RISK_PARAMS (model v1) is only the seed / reset value.

from age_tiers import TIER_NAMES, AgeTier

DEFAULT_RISK_MODEL_VERSION = "v1"

# Model v1. Days-behind bands: up to band1 / band2 / band3 days -> points,
# more than band3 -> risk_over_points. Vulnerabilities: at least vulnN_min
# known vulnerabilities -> vulnN_points (highest band that applies). The score
# is capped at risk_max_score. Levels: Critical / High / Medium from their
# minimum score, otherwise Low (minimum 0).
DEFAULT_RISK_PARAMS = {
    "risk_band1_max_days": 30,
    "risk_band1_points": 0,
    "risk_band2_max_days": 365,
    "risk_band2_points": 15,
    "risk_band3_max_days": 730,
    "risk_band3_points": 30,
    "risk_over_points": 40,
    "risk_abandoned_points": 25,
    "risk_vuln1_min": 1,
    "risk_vuln1_points": 20,
    "risk_vuln2_min": 2,
    "risk_vuln2_points": 30,
    "risk_vuln3_min": 5,
    "risk_vuln3_points": 45,
    "risk_max_score": 100,
    "risk_medium_min": 20,
    "risk_high_min": 45,
    "risk_critical_min": 70,
}

# (key, group, label) in form order
RISK_PARAM_FIELDS = [
    ("risk_band1_max_days", "Days behind the latest release", "Band 1: up to (days)"),
    ("risk_band1_points", "Days behind the latest release", "Band 1 points"),
    ("risk_band2_max_days", "Days behind the latest release", "Band 2: up to (days)"),
    ("risk_band2_points", "Days behind the latest release", "Band 2 points"),
    ("risk_band3_max_days", "Days behind the latest release", "Band 3: up to (days)"),
    ("risk_band3_points", "Days behind the latest release", "Band 3 points"),
    ("risk_over_points", "Days behind the latest release", "More than band 3: points"),
    ("risk_abandoned_points", "Abandoned", "Abandoned penalty (points)"),
    ("risk_vuln1_min", "Known vulnerabilities", "At least (count) 1"),
    ("risk_vuln1_points", "Known vulnerabilities", "Points 1"),
    ("risk_vuln2_min", "Known vulnerabilities", "At least (count) 2"),
    ("risk_vuln2_points", "Known vulnerabilities", "Points 2"),
    ("risk_vuln3_min", "Known vulnerabilities", "At least (count) 3"),
    ("risk_vuln3_points", "Known vulnerabilities", "Points 3"),
    ("risk_max_score", "Cap", "Maximum score"),
    ("risk_medium_min", "Level thresholds (minimum score)", "Medium"),
    ("risk_high_min", "Level thresholds (minimum score)", "High"),
    ("risk_critical_min", "Level thresholds (minimum score)", "Critical"),
]

MAX_POINTS = 999          # packages.risk_score is DECIMAL(5,2)
MAX_BAND_DAYS = 36500

RISK_LEVELS = ["Critical", "High", "Medium", "Low"]   # Critical first
UNKNOWN_RISK = "Unknown"          # age unknown and no known vulnerabilities


def validate_risk_params(raw):
    """
    Risk formula parameters from the form or the settings table.
    Returns (params as ints, errors); params is only complete when errors is empty.
    """
    params, errors = {}, []
    labels = {key: f"{group}: {label}" for key, group, label in RISK_PARAM_FIELDS}
    for key, _, _ in RISK_PARAM_FIELDS:
        value = raw.get(key)
        text = "" if value is None else str(value).strip()
        try:
            value = int(text)
        except ValueError:
            errors.append(f"{labels[key]} must be a whole number (got '{text}').")
            continue
        if value < 0:
            errors.append(f"{labels[key]} must not be negative.")
            continue
        params[key] = value
    if errors:
        return params, errors

    p = params
    if not 1 <= p["risk_max_score"] <= MAX_POINTS:
        errors.append(f"Maximum score must be between 1 and {MAX_POINTS}.")
    for key, _, _ in RISK_PARAM_FIELDS:
        if key.endswith("_points") and p[key] > MAX_POINTS:
            errors.append(f"{labels[key]} must be at most {MAX_POINTS}.")
    if not p["risk_band1_max_days"] < p["risk_band2_max_days"] < p["risk_band3_max_days"]:
        errors.append("Days-behind bands must be in ascending order (band 1 < band 2 < band 3).")
    if p["risk_band3_max_days"] > MAX_BAND_DAYS:
        errors.append(f"Band 3 must be at most {MAX_BAND_DAYS} days.")
    if p["risk_vuln1_min"] < 1:
        errors.append("The first vulnerability count must be at least 1.")
    if not p["risk_vuln1_min"] < p["risk_vuln2_min"] < p["risk_vuln3_min"]:
        errors.append("Vulnerability counts must be in ascending order (1 < 2 < 3).")
    if not 0 < p["risk_medium_min"] < p["risk_high_min"] < p["risk_critical_min"]:
        errors.append("Level thresholds must be in ascending order (Low 0 < Medium < High < Critical).")
    if p["risk_critical_min"] > p["risk_max_score"]:
        errors.append("The Critical threshold must not be above the maximum score.")
    return params, errors


def days_behind_points(days, params=DEFAULT_RISK_PARAMS):
    for n in (1, 2, 3):
        if days <= params[f"risk_band{n}_max_days"]:
            return params[f"risk_band{n}_points"]
    return params["risk_over_points"]


def vuln_points(count, params=DEFAULT_RISK_PARAMS):
    for n in (3, 2, 1):
        if count >= params[f"risk_vuln{n}_min"]:
            return params[f"risk_vuln{n}_points"]
    return 0


def level_for(score, params=DEFAULT_RISK_PARAMS):
    for key, name in (("risk_critical_min", "Critical"), ("risk_high_min", "High"),
                      ("risk_medium_min", "Medium")):
        if score >= params[key]:
            return name
    return "Low"


def describe_days(days):
    """'up to date', '12 days behind', '5 months behind', '2 years behind'."""
    if days <= 0:
        return "up to date"
    if days < 60:
        return f"{days} day{'s' if days != 1 else ''} behind"
    if days < 2 * 365:
        return f"{days // 30} months behind"
    return f"{days // 365} years behind"


def score_risk(age_tier, days_behind, vuln_count, params=DEFAULT_RISK_PARAMS,
               model_version=DEFAULT_RISK_MODEL_VERSION):
    """
    Risk of one package from its latest-scan row, with the formula params
    of model_version (the database passes the stored ones). Returns a dict:

        score          0-100, or None when the level is Unknown
        level          Critical / High / Medium / Low / Unknown
        reasons        short readable text, e.g. "Stale; 2 years behind; ..."
        tier           the age tier used, or None when unknown
        days_behind    the days used, or None when not trusted
        vuln_count     known vulnerability count, or None (no data)
        is_abandoned   True/False, or None when the age is unknown
        model_version  the model_version given

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
        score += days_behind_points(days, params)
        if is_abandoned:
            score += params["risk_abandoned_points"]

    if vulns:
        reasons.append(f"{vulns} vulnerabilit{'ies' if vulns != 1 else 'y'}")
        score += vuln_points(vulns, params)
    else:
        reasons.append("no vulnerability data")

    if tier is None and not vulns:
        final_score, level = None, UNKNOWN_RISK
    else:
        final_score = min(score, params["risk_max_score"])
        level = level_for(final_score, params)

    return {
        "score": final_score,
        "level": level,
        "reasons": "; ".join(reasons),
        "tier": tier,
        "days_behind": days,
        "vuln_count": vulns,
        "is_abandoned": is_abandoned,
        "model_version": model_version,
    }
