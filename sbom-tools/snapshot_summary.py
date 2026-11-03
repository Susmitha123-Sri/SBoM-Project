# sbom-tools/snapshot_summary.py
#
# Daily-snapshot trends (Step 9). package_snapshots grows by one row per
# versions row per day (millions after a few weeks), so grouping it on every
# page load would be slow. Instead each finished run is summarised ONCE into
# the small tables of migration 005, and /trends reads only those and
# scan_runs. Snapshot rows never change (insert-only), so a summary never goes
# stale. package_snapshots is only ever read here.
#
#   eligible run      scan_runs.status completed or partial, finished; one per
#                     snapshot_date (the lowest run_id, like snapshot_done)
#   summarize_run()   counts per tier (repo rows) / risk / review (both repo
#                     rows and distinct packages) -> snapshot_summary(_runs)
#   summarize_pair()  tier of the same versions row in two consecutive runs,
#                     plus rows that are new or gone -> snapshot_transition(s)
#   trends_data()     everything /trends shows (read-only)
#
# Used by sbom-tools/summarize_snapshots.py (writes) and ui_app /trends (reads).

import re
from datetime import date, timedelta

from age_tiers import TIER_NAMES, UNKNOWN_TIER
import db_storage
from db_storage import REVIEW_STATUSES, RISK_FILTERS, RISK_NOT_SCORED

ELIGIBLE_STATUSES = ("completed", "partial")
NEW, GONE = "(new)", "(gone)"

# dimension -> SQL value (NULL shown like the rest of the app), display order
DIMENSIONS = {
    "tier": (f"COALESCE(age_tier, '{UNKNOWN_TIER}')", TIER_NAMES + [UNKNOWN_TIER]),
    "risk": (f"COALESCE(risk_level, '{RISK_NOT_SCORED}')", list(RISK_FILTERS)),
    "review": ("COALESCE(review_status, 'Open')", list(REVIEW_STATUSES)),
}

COUNT_LABELS = {
    "rows": "repo rows (one per package per repository)",
    "packages": "distinct packages",
}


class SummaryTablesMissing(RuntimeError):
    """Migration 005 is not applied."""


def _missing_table(error):
    text = str(error).lower()
    return "doesn't exist" in text or "no such table" in text or "1146" in text


def as_date(value):
    """date from a DATE column (date on MariaDB, text on SQLite)."""
    return value if isinstance(value, date) else date.fromisoformat(str(value)[:10])


def lookup_failed(notes):
    """N from scan_runs.notes 'lookup_failed=N; ...', or None."""
    match = re.search(r"lookup_failed=(\d+)", notes or "")
    return int(match.group(1)) if match else None


def _query(sql, params=()):
    conn = db_storage.get_new_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.fetchall()
    except Exception as e:
        if _missing_table(e):
            raise SummaryTablesMissing("migration 005 not applied") from e
        raise
    finally:
        conn.close()


# ============================
# RUNS AND PAIRS
# ============================
def eligible_runs():
    """
    One finished (completed / partial) run per snapshot_date, oldest first:
    [{"run_id", "snapshot_date", "status", "package_count", "summarized"}].
    """
    rows = _query(f"""
        SELECT r.run_id, r.snapshot_date, r.status, r.package_count,
               CASE WHEN m.run_id IS NULL THEN 0 ELSE 1 END AS summarized
        FROM scan_runs r
        LEFT JOIN snapshot_summary_runs m ON m.run_id = r.run_id
        WHERE r.status IN ({", ".join(f"'{s}'" for s in ELIGIBLE_STATUSES)})
          AND r.finished_at IS NOT NULL
        ORDER BY r.snapshot_date, r.run_id
    """)
    runs, seen = [], set()
    for row in rows:
        day = as_date(row["snapshot_date"])
        if day in seen:
            continue                     # a second finished run that day is ignored
        seen.add(day)
        runs.append({**row, "snapshot_date": day, "summarized": bool(row["summarized"])})
    return runs


def consecutive_pairs(runs=None):
    """[(prev_run, run, summarized)] for each eligible run and the one before it."""
    runs = eligible_runs() if runs is None else runs
    done = {(r["prev_run_id"], r["run_id"])
            for r in _query("SELECT prev_run_id, run_id FROM snapshot_transition_pairs")}
    return [(prev, run, (prev["run_id"], run["run_id"]) in done)
            for prev, run in zip(runs, runs[1:])]


# ============================
# SUMMARISE (writes only the 005 tables)
# ============================
def _check_eligible(cursor, *run_ids):
    for run_id in run_ids:
        cursor.execute("SELECT status, finished_at FROM scan_runs WHERE run_id = %s", (run_id,))
        row = cursor.fetchone()
        if not row or row["status"] not in ELIGIBLE_STATUSES or row["finished_at"] is None:
            raise ValueError(f"run {run_id} is not a finished completed/partial run")


def summarize_run(run_id):
    """Replace run_id's summary in one transaction. Returns (rows_n, packages_n)."""
    conn = db_storage.get_new_connection()
    try:
        with conn.cursor() as cursor:
            _check_eligible(cursor, run_id)
            cursor.execute("DELETE FROM snapshot_summary WHERE run_id = %s", (run_id,))
            cursor.execute("DELETE FROM snapshot_summary_runs WHERE run_id = %s", (run_id,))
            cursor.execute("""
                INSERT INTO snapshot_summary_runs
                    (run_id, snapshot_date, run_status, rows_n, packages_n)
                SELECT r.run_id, r.snapshot_date, r.status,
                       COUNT(s.snapshot_id), COUNT(DISTINCT s.package_id)
                FROM scan_runs r
                LEFT JOIN package_snapshots s ON s.run_id = r.run_id
                WHERE r.run_id = %s
                GROUP BY r.run_id, r.snapshot_date, r.status
            """, (run_id,))
            for dimension, (expr, _) in DIMENSIONS.items():
                cursor.execute(f"""
                    INSERT INTO snapshot_summary (run_id, dimension, value, rows_n, packages_n)
                    SELECT %s, '{dimension}', {expr}, COUNT(*), COUNT(DISTINCT package_id)
                    FROM package_snapshots
                    WHERE run_id = %s
                    GROUP BY {expr}
                """, (run_id, run_id))
            cursor.execute("SELECT rows_n, packages_n FROM snapshot_summary_runs WHERE run_id = %s",
                           (run_id,))
            marker = cursor.fetchone()
        conn.commit()
        return marker["rows_n"], marker["packages_n"]
    except Exception as e:
        conn.rollback()
        if _missing_table(e):
            raise SummaryTablesMissing("migration 005 not applied") from e
        raise
    finally:
        conn.close()


def summarize_pair(prev_run_id, run_id):
    """
    Replace the tier transitions between two runs in one transaction.
    Returns {"rows_both", "rows_changed", "rows_new", "rows_gone"}.
    """
    tier_a, tier_b = (f"COALESCE({t}.age_tier, '{UNKNOWN_TIER}')" for t in ("a", "b"))
    conn = db_storage.get_new_connection()
    try:
        with conn.cursor() as cursor:
            _check_eligible(cursor, prev_run_id, run_id)
            pair = (prev_run_id, run_id)
            cursor.execute("DELETE FROM snapshot_transitions WHERE prev_run_id = %s AND run_id = %s",
                           pair)
            cursor.execute("DELETE FROM snapshot_transition_pairs "
                           "WHERE prev_run_id = %s AND run_id = %s", pair)
            cursor.execute("""
                INSERT INTO snapshot_transition_pairs
                    (prev_run_id, run_id, rows_both, rows_changed, rows_new, rows_gone)
                VALUES (%s, %s, 0, 0, 0, 0)
            """, pair)
            # Same versions row in both runs
            cursor.execute(f"""
                INSERT INTO snapshot_transitions (prev_run_id, run_id, from_tier, to_tier, rows_n)
                SELECT %s, %s, {tier_a}, {tier_b}, COUNT(*)
                FROM package_snapshots a
                JOIN package_snapshots b ON b.run_id = %s AND b.version_id = a.version_id
                WHERE a.run_id = %s
                GROUP BY {tier_a}, {tier_b}
            """, (prev_run_id, run_id, run_id, prev_run_id))
            # Only in the later run (new) / only in the earlier one (gone)
            cursor.execute(f"""
                INSERT INTO snapshot_transitions (prev_run_id, run_id, from_tier, to_tier, rows_n)
                SELECT %s, %s, '{NEW}', {tier_b}, COUNT(*)
                FROM package_snapshots b
                LEFT JOIN package_snapshots a ON a.run_id = %s AND a.version_id = b.version_id
                WHERE b.run_id = %s AND a.snapshot_id IS NULL
                GROUP BY {tier_b}
            """, (prev_run_id, run_id, prev_run_id, run_id))
            cursor.execute(f"""
                INSERT INTO snapshot_transitions (prev_run_id, run_id, from_tier, to_tier, rows_n)
                SELECT %s, %s, {tier_a}, '{GONE}', COUNT(*)
                FROM package_snapshots a
                LEFT JOIN package_snapshots b ON b.run_id = %s AND b.version_id = a.version_id
                WHERE a.run_id = %s AND b.snapshot_id IS NULL
                GROUP BY {tier_a}
            """, (prev_run_id, run_id, run_id, prev_run_id))
            cursor.execute("SELECT from_tier, to_tier, rows_n FROM snapshot_transitions "
                           "WHERE prev_run_id = %s AND run_id = %s", pair)
            counts = pair_counts(cursor.fetchall())
            cursor.execute("""
                UPDATE snapshot_transition_pairs
                SET rows_both = %s, rows_changed = %s, rows_new = %s, rows_gone = %s
                WHERE prev_run_id = %s AND run_id = %s
            """, (counts["rows_both"], counts["rows_changed"], counts["rows_new"],
                  counts["rows_gone"], prev_run_id, run_id))
        conn.commit()
        return counts
    except Exception as e:
        conn.rollback()
        if _missing_table(e):
            raise SummaryTablesMissing("migration 005 not applied") from e
        raise
    finally:
        conn.close()


def pair_counts(transitions):
    counts = {"rows_both": 0, "rows_changed": 0, "rows_new": 0, "rows_gone": 0}
    for t in transitions:
        n = int(t["rows_n"])
        if t["from_tier"] == NEW:
            counts["rows_new"] += n
        elif t["to_tier"] == GONE:
            counts["rows_gone"] += n
        else:
            counts["rows_both"] += n
            if t["from_tier"] != t["to_tier"]:
                counts["rows_changed"] += n
    return counts


# ============================
# PAGE DATA (read-only)
# ============================
def _date_range(first, last):
    return [first + timedelta(days=i) for i in range((last - first).days + 1)]


def _series(order, by_day, days, field):
    """Chart.js datasets: one per value (display order first, then any others)."""
    seen = {value for counts in by_day.values() for value in counts}
    names = [v for v in order if v in seen] + sorted(seen - set(order))
    return [{"name": name,
             "data": [by_day[d].get(name, {}).get(field, 0) if d in by_day else None
                      for d in days]}
            for name in names]


def trends_data():
    """
    Everything /trends shows, from scan_runs and the 005 tables only.
    {"error"} if migration 005 is missing.
    """
    try:
        return _trends_data()
    except SummaryTablesMissing:
        return {"error": "Migration 005 is not applied: the summary tables do not exist. "
                         "Run migrations/005_snapshot_summary.sql first."}


def _trends_data():
    all_runs = _query("""
        SELECT run_id, snapshot_date, started_at, finished_at, status, package_count,
               trigger_source, notes
        FROM scan_runs ORDER BY snapshot_date, run_id
    """)
    runs = eligible_runs()
    pairs = consecutive_pairs(runs)
    chosen = {r["run_id"]: r for r in runs}
    summarized_ids = {r["run_id"] for r in runs if r["summarized"]}

    # ---- runs table: every date from the first run to the last ----
    by_date = {}
    for r in all_runs:
        by_date.setdefault(as_date(r["snapshot_date"]), []).append(r)
    table = []
    if by_date:
        for day in _date_range(min(by_date), max(by_date)):
            day_runs = by_date.get(day)
            if not day_runs:
                table.append({"date": day.isoformat(), "status": "missing", "run_id": None})
                continue
            for r in day_runs:
                table.append({
                    "date": day.isoformat(), "status": r["status"], "run_id": r["run_id"],
                    "trigger_source": r["trigger_source"], "rows": r["package_count"],
                    "lookup_failed": lookup_failed(r["notes"]),
                    "started_at": str(r["started_at"] or ""),
                    "finished_at": str(r["finished_at"] or ""),
                    "summarized": r["run_id"] in summarized_ids,
                    "used": r["run_id"] in chosen,
                    "notes": r["notes"] or "",
                })

    # ---- per-day charts: summarised eligible runs, missing days as gaps ----
    summarized_runs = [r for r in runs if r["summarized"]]
    days = (_date_range(summarized_runs[0]["snapshot_date"], summarized_runs[-1]["snapshot_date"])
            if summarized_runs else [])
    run_of_day = {r["snapshot_date"]: r for r in summarized_runs}
    labels = [d.isoformat() + (" (partial)" if run_of_day.get(d, {}).get("status") == "partial"
                               else "" if d in run_of_day else " (no data)")
              for d in days]

    counts = {dim: {} for dim in DIMENSIONS}       # dim -> day -> value -> row
    if summarized_runs:
        ids = ", ".join(str(int(r["run_id"])) for r in summarized_runs)
        for row in _query(f"SELECT run_id, dimension, value, rows_n, packages_n "
                          f"FROM snapshot_summary WHERE run_id IN ({ids})"):
            day = chosen[row["run_id"]]["snapshot_date"]
            counts[row["dimension"]].setdefault(day, {})[row["value"]] = {
                "rows": int(row["rows_n"]), "packages": int(row["packages_n"])}

    def chart(dim, field):
        return {"counts": COUNT_LABELS[field],
                "series": _series(DIMENSIONS[dim][1], counts[dim], days, field)}

    # ---- crossings between consecutive runs ----
    done_pairs = [(p, r) for p, r, done in pairs if done]
    crossings = {"counts": COUNT_LABELS["rows"], "labels": [], "series": [], "new": [],
                 "gone": [], "both": [], "changed": [], "table": []}
    if done_pairs:
        wanted = {(p["run_id"], r["run_id"]) for p, r in done_pairs}
        ids = ", ".join(str(int(r["run_id"])) for _, r in done_pairs)
        transitions = [t for t in _query(
            "SELECT prev_run_id, run_id, from_tier, to_tier, rows_n FROM snapshot_transitions "
            f"WHERE run_id IN ({ids})") if (t["prev_run_id"], t["run_id"]) in wanted]
        by_pair = {}
        for t in transitions:
            by_pair.setdefault((t["prev_run_id"], t["run_id"]), []).append(t)
        order = TIER_NAMES + [UNKNOWN_TIER]
        moves = sorted({(t["from_tier"], t["to_tier"]) for t in transitions
                        if t["from_tier"] != NEW and t["to_tier"] != GONE
                        and t["from_tier"] != t["to_tier"]},
                       key=lambda m: (order.index(m[0]) if m[0] in order else len(order),
                                      order.index(m[1]) if m[1] in order else len(order)))
        for prev, run in done_pairs:
            rows = by_pair.get((prev["run_id"], run["run_id"]), [])
            label = f"{prev['snapshot_date'].isoformat()} -> {run['snapshot_date'].isoformat()}"
            crossings["labels"].append(label)
            c = pair_counts(rows)
            for key in ("new", "gone", "both", "changed"):
                crossings[key].append(c[f"rows_{key}"])
            for t in rows:
                if t["from_tier"] != t["to_tier"]:
                    crossings["table"].append({"pair": label, "from": t["from_tier"],
                                               "to": t["to_tier"], "rows": int(t["rows_n"])})
        for move in moves:
            crossings["series"].append({
                "name": f"{move[0]} -> {move[1]}",
                "data": [sum(int(t["rows_n"]) for t in by_pair.get((p["run_id"], r["run_id"]), [])
                             if (t["from_tier"], t["to_tier"]) == move)
                         for p, r in done_pairs]})

    return {
        "error": None,
        "runs_table": table,
        "missing_days": sum(1 for t in table if t["status"] == "missing"),
        "unsummarized": sum(1 for r in runs if not r["summarized"]),
        "pairs_pending": sum(1 for _, _, done in pairs if not done),
        "labels": labels,
        "tier": chart("tier", "rows"),
        "risk": chart("risk", "packages"),
        "review": chart("review", "packages"),
        "crossings": crossings,
    }
