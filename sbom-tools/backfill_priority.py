# sbom-tools/backfill_priority.py
#
# One-off backfill of packages.priority_* (the update queue) for rows already
# in the database, using the same scoring, ranking and latest-scan rule as
# the monitor job (DatabaseStorage.update_package_priorities). Uses stored
# data only: no registry lookups. Writes only the priority_* columns, so it
# is safe to rerun. Priority reads packages.risk_*, so run backfill_risk.py
# first if risk has not been filled yet.
#
# Needs migrations/003_priority.sql applied. Back up first, e.g.:
#     mysqldump -u root -p sbom_common --result-file=sbom_backup_before_priority.sql
# Preview (default, changes nothing):
#     python sbom-tools/backfill_priority.py
# Write for real:
#     python sbom-tools/backfill_priority.py --apply
# Undo (or restore the backup):
#     UPDATE packages SET priority_score=NULL, priority_rank=NULL,
#       priority_reason=NULL, priority_category=NULL, priority_version_id=NULL,
#       priority_model_version=NULL, priority_computed_at=NULL;

import argparse
from collections import Counter

from db_storage import get_db_storage
from priority import PRIORITY_CATEGORIES, PRIORITY_MODEL_VERSION

TOP_TO_SHOW = 10


def main():
    parser = argparse.ArgumentParser(
        description="Fill packages.priority_* (the update queue) from each package's latest scan."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write the priority columns. Without this flag only a preview is shown."
    )
    args = parser.parse_args()

    db = get_db_storage()
    print(f"Priority model {PRIORITY_MODEL_VERSION}")

    rows = db.package_priority_rows()
    ranked = sorted((r for r in rows if r["rank"] is not None), key=lambda r: r["rank"])

    categories = Counter(r["priority"]["category"] for r in rows)
    print(f"\n{len(rows)} packages would get a priority ({len(ranked)} ranked):")
    for category in PRIORITY_CATEGORIES:
        print(f"  {category:<12} {categories.get(category, 0)}")

    print(f"\nTop {TOP_TO_SHOW} to update:")
    for r in ranked[:TOP_TO_SHOW]:
        p = r["priority"]
        print(f"  #{r['rank']} {r['package_name']}: {p['category']} - {p['reason']}")

    if not args.apply:
        print("\nPreview only. Nothing was changed. Re-run with --apply to write.")
        return

    written = db.update_package_priorities()
    print(f"\nWrote priority for {written} packages.")


if __name__ == "__main__":
    main()
