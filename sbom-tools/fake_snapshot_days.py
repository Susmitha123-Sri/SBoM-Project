# sbom-tools/fake_snapshot_days.py
#
# TEST DATA FOR THE COPY DATABASE ONLY. Writes a few back-dated snapshot days
# (trigger_source 'fake_test') so /trends has something to show, changing some
# rows between days: Aging -> Stale and Fresh -> Aging tiers, then risk and
# priority recomputed with the app's own functions, and some review statuses.
# Snapshot runs, snapshot rows and review history can never be deleted, so
# the only way back is rebuilding the copy.
#
# Refuses (exit 2, before writing anything):
#   - any --database except sbom_test_copy (checked before connecting)
#   - a connection that is not to that database (in-memory guard, and
#     SELECT DATABASE())
#   - a copy that already has fake_test runs (runs once per copy)
#   - fake dates on or after the earliest existing snapshot date
#
# Preview (default):
#     python sbom-tools/fake_snapshot_days.py --database sbom_test_copy
# Write the days:
#     python sbom-tools/fake_snapshot_days.py --database sbom_test_copy --apply

import argparse
import random
import sys
from datetime import date, timedelta

import db_storage

ALLOWED = {"sbom_test_copy"}
TRIGGER = "fake_test"
REVIEWER = "fake-test"
NOTE = "fake snapshot test"
MOVES = (("Aging", "Stale", 30), ("Fresh", "Aging", 50))   # applied in this order
REVIEWS_PER_DAY = 20


def query(sql, params=()):
    conn = db_storage.get_new_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            rows = cursor.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


def current_database():
    return query("SELECT DATABASE() AS d")[0]["d"]


def move_tiers(rng, old, new, count):
    """Set age_tier of up to count random rows with tier old to new; returns the number."""
    ids = sorted(r["version_id"] for r in query(
        "SELECT version_id FROM versions WHERE age_tier = %s", (old,)))
    chosen = rng.sample(ids, min(count, len(ids)))
    if chosen:
        query(f"UPDATE versions SET age_tier = %s WHERE version_id IN "
              f"({', '.join(['%s'] * len(chosen))})", (new, *chosen))
    return len(chosen)


def change_day(db, rng, package_ids):
    """One day's changes; returns a short description."""
    moved = [f"{old}->{new} {move_tiers(rng, old, new, n)}" for old, new, n in MOVES]
    for row in query("SELECT scan_id FROM scan ORDER BY scan_id"):
        db.update_package_risk_for_scan(row["scan_id"])
    db.update_package_priorities()
    statuses = [s for s in db_storage.REVIEW_STATUSES if s != "Open"]
    reviewed = rng.sample(package_ids, min(REVIEWS_PER_DAY, len(package_ids)))
    for package_id in reviewed:
        db.save_review(package_id, rng.choice(statuses), REVIEWER, NOTE)
    return ", ".join(moved) + f", {len(reviewed)} reviews"


def install_guard(database):
    """Refuse any pymysql connection that does not name database; returns an undo function."""
    real_connect = db_storage.pymysql.connect
    old_name = db_storage.DB_CONFIG["database"]

    def guarded_connect(*args, **kwargs):
        if kwargs.get("database") != database:
            raise RuntimeError(f"blocked connection to {kwargs.get('database')!r}")
        return real_connect(*args, **kwargs)

    db_storage.DB_CONFIG["database"] = database
    db_storage.pymysql.connect = guarded_connect

    def undo():
        db_storage.pymysql.connect = real_connect
        db_storage.DB_CONFIG["database"] = old_name
    return undo


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Write fake back-dated snapshot days to the COPY database (preview by default).")
    parser.add_argument("--database", required=True, help="must be sbom_test_copy")
    parser.add_argument("--days", type=int, default=5)
    parser.add_argument("--start", type=date.fromisoformat, default=date(2026, 10, 1))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    if args.database not in ALLOWED:
        print(f"Refused: --database must be one of {sorted(ALLOWED)} (got {args.database!r}). "
              "Nothing was connected or written.")
        return 2
    if args.days < 1:
        print("Error: --days must be at least 1.")
        return 2

    undo = install_guard(args.database)
    try:
        actual = current_database()
        if actual != args.database:
            print(f"Refused: connected to {actual!r}, not {args.database!r}.")
            return 2
        if query("SELECT COUNT(*) AS n FROM scan_runs WHERE trigger_source = %s",
                 (TRIGGER,))[0]["n"]:
            print(f"Refused: this database already has {TRIGGER} runs (rebuild the copy to rerun).")
            return 2
        days = [args.start + timedelta(days=i) for i in range(args.days)]
        first = query("SELECT MIN(snapshot_date) AS d FROM scan_runs")[0]["d"]
        if first is not None and days[-1] >= date.fromisoformat(str(first)[:10]):
            print(f"Refused: fake dates {days[0]}..{days[-1]} must be before the earliest "
                  f"snapshot date {str(first)[:10]}.")
            return 2

        package_ids = sorted(r["package_id"] for r in query(
            "SELECT DISTINCT package_id FROM versions WHERE package_id IS NOT NULL"))
        print(f"Database {args.database}: {len(package_ids)} packages; fake days "
              f"{days[0]} .. {days[-1]} ({args.days}), seed {args.seed}")
        if not args.apply:
            print("Preview only. Nothing was written. Re-run with --apply "
                  "(permanent in this database).")
            return 0

        db = db_storage.get_db_storage()
        db.reset_connection()            # any earlier connection was made before the guard
        rng = random.Random(args.seed)
        for i, day in enumerate(days):
            change = change_day(db, rng, package_ids) if i else "no changes (first day)"
            result = db.write_daily_snapshot(snapshot_date=day, trigger_source=TRIGGER)
            print(f"{day}: {change}; snapshot run {result['run_id']} {result['status']}, "
                  f"{result['rows']} rows")
            if result["status"] == "failed":
                print(f"Snapshot failed: {result.get('error')}")
                return 1
        print("Done. Next: python sbom-tools/summarize_snapshots.py --apply (on the copy).")
        return 0
    finally:
        undo()


if __name__ == "__main__":
    sys.exit(main())
