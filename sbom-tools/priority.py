# sbom-tools/priority.py
#
# Update priority of a package: which packages to update first, and why.
# Built from signals already stored (see db_storage.package_priority_rows for
# where they come from), all taken from the package's latest-scan row:
#
#   status        versions.status of that row (up_to_date / outdated / unknown)
#   risk_level    packages.risk_level / risk_score (see risk.py)
#   days_behind   packages.risk_days_behind (None when the age is unknown)
#   version_gap   calculate_versions_behind(installed, latest): "1.0.0" is a
#                 major jump, "0.3.0" minor, "0.0.4" patch, "N/A" unknown
#   repo_count    how many scans (uploaded repositories / SBOMs) use it
#   review        package_reviews.status (no row = Open)
#
# score_priority() scores one package; rank_priorities() orders them all
# (1 = update first). Change PRIORITY_MODEL_VERSION whenever points,
# penalties, cut-offs or the order change (packages.priority_model_version).

from risk import UNKNOWN_RISK, describe_days

PRIORITY_MODEL_VERSION = "p1"

# ============================
# POINTS (base score is at most 100)
# ============================
RISK_WEIGHT = 0.5                 # risk_score 0-100 -> 0-50 points

# Days behind the latest release: (upper bound in days, points)
DAYS_BEHIND_POINTS = [(30, 0), (180, 5), (365, 10), (730, 15)]
DAYS_BEHIND_MAX_POINTS = 20       # more than 730 days

# Size of the upgrade (a rough sign of breaking-change risk)
JUMP_POINTS = {"major": 15, "minor": 10, "patch": 5}

# Repositories using the package: (minimum count, points), highest first
REPO_POINTS = [(5, 15), (3, 10), (2, 5)]

# Management review lowers the score (floor 0); the package stays ranked
REVIEW_PENALTY = {
    "Open": 0,
    "Compensating Control": 25,
    "Reviewed - Accepted": 30,
    "Resolved": 40,
}

# ============================
# CATEGORIES
# ============================
UPDATE_NOW = "Update now"
PLAN_UPDATE = "Plan update"
MONITOR = "Monitor"
INVESTIGATE = "Investigate"       # risk or latest version unknown: ranked after scored
NO_ACTION = "No action"           # up to date: no rank

# (minimum score, category), checked highest first
CATEGORY_CUTOFFS = [(60, UPDATE_NOW), (35, PLAN_UPDATE), (0, MONITOR)]

PRIORITY_CATEGORIES = [UPDATE_NOW, PLAN_UPDATE, MONITOR, INVESTIGATE, NO_ACTION]

REASON_MAX_LENGTH = 500           # packages.priority_reason is VARCHAR(500)

# Queue groups: scored packages first, then Investigate; None = not ranked
SCORED, UNSCORED = 0, 1


def round_half_up(x):
    return int(x + 0.5)


def days_behind_points(days):
    for max_days, points in DAYS_BEHIND_POINTS:
        if days <= max_days:
            return points
    return DAYS_BEHIND_MAX_POINTS


def repo_points(count):
    for min_count, points in REPO_POINTS:
        if count >= min_count:
            return points
    return 0


def jump_kind(version_gap):
    """"major", "minor", "patch", or None (no gap, or not known)."""
    try:
        parts = [int(x) for x in str(version_gap).split(".")]
    except ValueError:
        return None
    parts = (parts + [0, 0, 0])[:3]
    for kind, part in zip(("major", "minor", "patch"), parts):
        if part > 0:
            return kind
    return None


def category_for(score):
    for min_score, name in CATEGORY_CUTOFFS:
        if score >= min_score:
            return name
    return CATEGORY_CUTOFFS[-1][1]


def describe_repos(count):
    return f"used in {count} repo{'s' if count != 1 else ''}"


def review_text(review_status, reviewer):
    by = f" by {reviewer}" if reviewer else ""
    return f"{review_status}{by}"


def trim(reason):
    if len(reason) <= REASON_MAX_LENGTH:
        return reason
    return reason[:REASON_MAX_LENGTH - 3] + "..."


def score_priority(status, risk_level, risk_score, days_behind, version_gap,
                   installed, latest, repo_count, review_status="Open", reviewer=None):
    """
    Priority of one package from its latest-scan row. Returns a dict:

        score          0-100 after the review penalty, or None (not scored)
        category       one of PRIORITY_CATEGORIES
        reason         readable text, at most REASON_MAX_LENGTH characters
        group          SCORED, UNSCORED (Investigate) or None (not ranked)
        model_version  PRIORITY_MODEL_VERSION

    Up to date: No action, no rank. Unknown risk, no risk yet, or an unknown
    latest version: Investigate, ranked after every scored package. Reviewed
    packages are scored lower, never removed.
    """
    repo_count = int(repo_count or 0)
    review_status = review_status or "Open"
    penalty = REVIEW_PENALTY.get(review_status, 0)

    def result(score, category, reason, group):
        return {
            "score": score,
            "category": category,
            "reason": trim(reason),
            "group": group,
            "model_version": PRIORITY_MODEL_VERSION,
        }

    if status == "up_to_date":
        return result(None, NO_ACTION, "Up to date: no update needed", None)

    if status != "outdated":
        cause = "latest version unknown"
    elif risk_level is None:
        cause = "risk not scored yet"
    elif risk_level == UNKNOWN_RISK or risk_score is None:
        cause = "risk unknown (no release dates)"
    else:
        cause = None

    if cause:
        parts = [f"Investigate: {cause}", describe_repos(repo_count)]
        if review_status != "Open":
            parts.append(review_text(review_status, reviewer))
        return result(None, INVESTIGATE, "; ".join(parts), UNSCORED)

    parts = []
    base = 0

    points = round_half_up(float(risk_score) * RISK_WEIGHT)
    parts.append(f"{risk_level} risk (+{points})")
    base += points

    if days_behind is None:
        parts.append("days behind unknown (+0)")
    else:
        days = max(int(days_behind), 0)
        points = days_behind_points(days)
        parts.append(f"{describe_days(days)} (+{points})")
        base += points

    kind = jump_kind(version_gap)
    points = JUMP_POINTS.get(kind, 0)
    if kind == "major":
        parts.append(f"major upgrade {installed} -> {latest}, may need code changes (+{points})")
    elif kind:
        parts.append(f"{kind} upgrade (+{points})")
    else:
        parts.append("upgrade size unknown (+0)")
    base += points

    points = repo_points(repo_count)
    parts.append(f"{describe_repos(repo_count)} (+{points})")
    base += points

    score = max(base - penalty, 0)
    if penalty:
        parts.append(f"{review_text(review_status, reviewer)}: ranked lower (-{penalty})")

    reason = f"Score {score}: " + "; ".join(parts)
    return result(score, category_for(score), reason, SCORED)


def rank_priorities(items):
    """
    Ranks (1 = update first) for items with keys package_id, package_name,
    risk_score, days_behind, repo_count, review_status and priority (the
    score_priority() result). Returns {package_id: rank}; items not ranked
    (up to date) are left out.

    Scored packages first: score, risk score, days behind and repos (all
    highest first), then name and package_id, so the order is the same on
    every run. Then Investigate: repos (most first), Open before reviewed,
    name, package_id.
    """
    def key(item):
        p = item["priority"]
        name = item.get("package_name") or ""
        repos = int(item.get("repo_count") or 0)
        if p["group"] == SCORED:
            return (SCORED, -p["score"], -float(item.get("risk_score") or 0),
                    -int(item.get("days_behind") or 0), -repos, name, item["package_id"])
        reviewed = 0 if (item.get("review_status") or "Open") == "Open" else 1
        return (UNSCORED, -repos, reviewed, 0, 0, name, item["package_id"])

    ranked = sorted((i for i in items if i["priority"]["group"] is not None), key=key)
    return {item["package_id"]: n for n, item in enumerate(ranked, start=1)}
