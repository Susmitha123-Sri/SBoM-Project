"""
Database Only Version Monitor
Uses Simran's sbom_monitor database
No GitHub scanning
"""

from version_monitor import get_latest_version, compare_versions
from db_storage import get_db_storage


def run_hybrid_monitor():

    print("\n======================================")
    print("DATABASE VERSION MONITOR STARTED")
    print("======================================")

    db = get_db_storage()

    if not db._connect():
        print("Database connection failed")
        return

    with db.connection.cursor() as cursor:
        cursor.execute("SHOW TABLES;")
        tables = cursor.fetchall()

    table_names = [list(t.values())[0] for t in tables]

    for table in table_names:

        if table in ("monitored_versions",):
            continue

        print(f"[MONITOR] Checking table: {table}")

        try:
            with db.connection.cursor() as cursor:
                cursor.execute(f"""
                    SELECT package, version, type
                    FROM `{table}`
                """)
                packages = cursor.fetchall()

            for pkg in packages:

                package = pkg.get("package")
                current = pkg.get("version")
                pkg_type = pkg.get("type", "python")

                if not package or not current:
                    continue

                latest = get_latest_version(package, pkg_type)
                status = compare_versions(current, latest)

                db.upsert_monitored_version(
                    scan_id=table,
                    package=package,
                    current=current,
                    latest=latest,
                    status=status
                )

        except Exception as e:
            print(f"Error reading table {table}: {e}")

    print("DATABASE VERSION MONITOR COMPLETED\n")