# sbom-tools/backfill_risk.py
#
# One-off backfill of packages.risk_* for rows already in the database, using
# the same scoring and latest-scan rule as the monitor job
# (DatabaseStorage.update_package_risk_for_scan). Uses stored data only: no
# registry lookups. Writes only the risk_* columns, so it is safe to rerun.
#
# Back up first, e.g.:
#     mysqldump -u root sbom_common > sbom_backup_before_risk.sql
# Preview (default, changes nothing):
#     python sbom-tools/backfill_risk.py
# Write for real:
#     python sbom-tools/backfill_risk.py --apply
# Undo (or restore the backup):
#     UPDATE packages SET risk_score=NULL, risk_level=NULL, risk_reasons=NULL,
#       risk_tier=NULL, risk_days_behind=NULL, risk_vuln_count=NULL,
#       risk_is_abandoned=NULL, risk_version_id=NULL, risk_model_version=NULL,
#       risk_computed_at=NULL;

import argparse
from collections import Counter

from db_storage import get_db_storage
from risk import RISK_LEVELS, RISK_MODEL_VERSION, UNKNOWN_RISK

EXAMPLES_TO_SHOW = 10


def main():
    parser = argparse.ArgumentParser(
        description="Fill packages.risk_* from each package's latest scan."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually write the risk columns. Without this flag only a preview is shown."
    )
    args = parser.parse_args()

    db = get_db_storage()
    scans = db.get_all_scans()
    print(f"Risk model {RISK_MODEL_VERSION}, {len(scans)} scans")

    rows = []
    for scan in scans:
        rows += db.package_risk_rows(scan["scan_id"])

    levels = Counter(r["risk"]["level"] for r in rows)
    print(f"\n{len(rows)} packages would be scored:")
    for level in RISK_LEVELS + [UNKNOWN_RISK]:
        print(f"  {level:<9} {levels.get(level, 0)}")

    print(f"\nFirst {EXAMPLES_TO_SHOW} examples:")
    for r in rows[:EXAMPLES_TO_SHOW]:
        risk = r["risk"]
        print(f"  {r['package_name']}: {risk['level']} "
              f"(score {risk['score']}) - {risk['reasons']}")

    if not args.apply:
        print("\nPreview only. Nothing was changed. Re-run with --apply to write.")
        return

    written = 0
    for scan in scans:
        written += db.update_package_risk_for_scan(scan["scan_id"])
    print(f"\nWrote risk for {written} packages.")


if __name__ == "__main__":
    main()
