# sbom-tools/cleanup_duplicate_versions.py
#
# One-off cleanup for duplicate rows in the versions table (left behind by
# rescans that used to insert a new row instead of updating the existing one).
#
# Keeps the OLDEST row (lowest version_id) per (scan_id, package_name) and
# deletes the rest. Any scan_results rows pointing at a deleted row are moved
# to the kept row first, so the ON DELETE CASCADE doesn't drop them.
#
# Preview (default, changes nothing):
#     python sbom-tools/cleanup_duplicate_versions.py
# Delete for real:
#     python sbom-tools/cleanup_duplicate_versions.py --apply

import argparse

from db_storage import get_new_connection

EXAMPLES_TO_SHOW = 5
BATCH_SIZE = 1000

DUPLICATES_QUERY = """
    SELECT v.version_id, v.scan_id, v.package_name, v.version_number, k.keep_id
    FROM versions v
    JOIN (
        SELECT scan_id, package_name, MIN(version_id) AS keep_id
        FROM versions
        WHERE scan_id IS NOT NULL AND package_name IS NOT NULL
        GROUP BY scan_id, package_name
        HAVING COUNT(*) > 1
    ) k
      ON v.scan_id = k.scan_id
     AND v.package_name = k.package_name
     AND v.version_id > k.keep_id
    ORDER BY v.scan_id, v.package_name, v.version_id
"""


def batches(items, size=BATCH_SIZE):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def find_duplicates(cursor):
    cursor.execute(DUPLICATES_QUERY)
    return cursor.fetchall()


def count_linked_scan_results(cursor, version_ids):
    total = 0
    for chunk in batches(version_ids):
        placeholders = ", ".join(["%s"] * len(chunk))
        cursor.execute(
            f"SELECT COUNT(*) AS cnt FROM scan_results WHERE version_id IN ({placeholders})",
            chunk
        )
        total += cursor.fetchone()["cnt"]
    return total


def print_preview(duplicates, linked_results):
    groups = {}
    for row in duplicates:
        key = (row["scan_id"], row["package_name"], row["keep_id"])
        groups[key] = groups.get(key, 0) + 1

    print(f"Duplicate rows to delete:        {len(duplicates)}")
    print(f"Packages (per scan) affected:    {len(groups)}")
    print(f"scan_results rows to move over:  {linked_results}")

    if not groups:
        return

    print(f"\nExamples (largest {min(EXAMPLES_TO_SHOW, len(groups))}):")
    top = sorted(groups.items(), key=lambda g: g[1], reverse=True)[:EXAMPLES_TO_SHOW]
    for (scan_id, package_name, keep_id), count in top:
        print(
            f"  scan {scan_id}  {package_name}: keep version_id {keep_id}, "
            f"delete {count} duplicate(s)"
        )


def apply_cleanup(conn, cursor, duplicates):
    # Group duplicate ids by the row they collapse into
    by_keep_id = {}
    for row in duplicates:
        by_keep_id.setdefault(row["keep_id"], []).append(row["version_id"])

    moved = deleted = 0
    try:
        for keep_id, dup_ids in by_keep_id.items():
            for chunk in batches(dup_ids):
                placeholders = ", ".join(["%s"] * len(chunk))
                cursor.execute(
                    f"UPDATE scan_results SET version_id = %s WHERE version_id IN ({placeholders})",
                    [keep_id, *chunk]
                )
                moved += cursor.rowcount

        all_ids = [row["version_id"] for row in duplicates]
        for chunk in batches(all_ids):
            placeholders = ", ".join(["%s"] * len(chunk))
            cursor.execute(
                f"DELETE FROM versions WHERE version_id IN ({placeholders})",
                chunk
            )
            deleted += cursor.rowcount

        conn.commit()
    except Exception:
        conn.rollback()
        print("Cleanup failed. All changes were rolled back.")
        raise

    print(f"\nDone. Deleted {deleted} duplicate rows, moved {moved} scan_results rows.")


def main():
    parser = argparse.ArgumentParser(
        description="Remove duplicate rows from the versions table (keeps the oldest per package and scan)."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete the duplicates. Without this flag only a preview is shown."
    )
    args = parser.parse_args()

    conn = get_new_connection()
    try:
        cursor = conn.cursor()

        duplicates = find_duplicates(cursor)
        linked = count_linked_scan_results(cursor, [r["version_id"] for r in duplicates])

        print_preview(duplicates, linked)

        if not duplicates:
            print("\nNo duplicates found. Nothing to do.")
            return

        if not args.apply:
            print("\nPreview only. Nothing was changed. Re-run with --apply to delete.")
            return

        apply_cleanup(conn, cursor, duplicates)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
