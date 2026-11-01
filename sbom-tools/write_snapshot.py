# sbom-tools/write_snapshot.py
#
# Write today's daily snapshot by hand: one package_snapshots row per versions
# row (repo + package) under a new scan_runs row, at most once per date
# (DatabaseStorage.write_daily_snapshot, the same call the monitor job makes).
# Needs migration 004. There is no --date option: a snapshot is always of
# today's state, never back-dated.
#
# Preview (default): prints how many rows it would write; writes nothing.
#     python sbom-tools/write_snapshot.py
# Write it:
#     python sbom-tools/write_snapshot.py --apply

import argparse
import sys
from datetime import date


def main(argv=None, today=None):
    parser = argparse.ArgumentParser(
        description="Write today's package snapshot (preview by default)."
    )
    parser.add_argument("--apply", action="store_true",
                        help="Write the snapshot. Without this flag only a preview is shown.")
    args = parser.parse_args(argv)

    from db_storage import get_db_storage
    db = get_db_storage()
    today = today or date.today()

    done = db.snapshot_done(today)
    rows, without_package = db.count_snapshot_rows()
    print(f"Snapshot date: {today.isoformat()}")
    if done:
        print(f"Today's snapshot already exists (run {done}); nothing to do.")
        return 0
    print(f"Rows to copy: {rows} (versions rows without a package_id, skipped: {without_package})")

    if not args.apply:
        print("\nPreview only. Nothing was written. Re-run with --apply to write it.")
        return 0

    result = db.write_daily_snapshot(today, trigger_source="cli")
    if result["status"] == "failed":
        print(f"Snapshot failed (run {result['run_id']}): {result['error']}")
        return 1
    print(f"Run {result['run_id']} {result['status']}: {result['rows']} rows written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
