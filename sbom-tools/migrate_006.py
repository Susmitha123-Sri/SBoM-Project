# sbom-tools/migrate_006.py
#
# Apply or roll back migration 006 (risk formula settings: risk_models table,
# package_snapshots.risk_model_version) on ONE named database.
#
#   dry run (default)  shows the current state and the statements; runs nothing
#   --apply            runs the statements one by one
#   --database         required; the connection must report that database
#   checks             apply: needs migration 004 (package_snapshots.scan_id)
#                      rollback: refused while any package, snapshot or saved
#                      formula uses a version other than v1 (dropping
#                      risk_models would lose what that version means)
#
#     python sbom-tools/migrate_006.py --database sbom_test_copy
#     python sbom-tools/migrate_006.py --database sbom_test_copy --apply
#     python sbom-tools/migrate_006.py --database sbom_test_copy --rollback [--apply]

import argparse
import sys
from pathlib import Path

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"
APPLY_SQL = MIGRATIONS / "006_risk_models.sql"
ROLLBACK_SQL = MIGRATIONS / "006_rollback.sql"
DEFAULT_VERSION = "v1"


def split_sql(text):
    """Statements of a migration file: full-line -- comments dropped, split at a ; ending a line."""
    statements, current = [], []
    for line in text.splitlines():
        if not current and (not line.strip() or line.lstrip().startswith("--")):
            continue
        current.append(line)
        if line.rstrip().endswith(";"):
            statements.append("\n".join(current).strip().rstrip(";").strip())
            current = []
    if current:
        statements.append("\n".join(current).strip())
    return statements


def connect(database):
    """A pymysql connection to database (the app's DB_CONFIG with another database name)."""
    import pymysql
    import db_storage
    return pymysql.connect(**{**db_storage.DB_CONFIG, "database": database})


def query(conn, sql, params=()):
    with conn.cursor() as cursor:
        # None, not (): pymysql applies % formatting to any tuple, even an
        # empty one, which would break LIKE '..._%'
        cursor.execute(sql, params or None)
        return cursor.fetchall()


def state(conn):
    """What exists now and which risk model versions are in use."""
    def exists(sql, *params):
        return query(conn, sql, params)[0]["n"] > 0

    s = {
        "has_004": exists("SELECT COUNT(*) AS n FROM information_schema.COLUMNS WHERE "
                          "TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'package_snapshots' "
                          "AND COLUMN_NAME = 'scan_id'"),
        "risk_models": exists("SELECT COUNT(*) AS n FROM information_schema.TABLES WHERE "
                              "TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'risk_models'"),
        "snapshot_column": exists("SELECT COUNT(*) AS n FROM information_schema.COLUMNS WHERE "
                                  "TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'package_snapshots' "
                                  "AND COLUMN_NAME = 'risk_model_version'"),
        "triggers": [r["name"] for r in query(
            conn, "SELECT TRIGGER_NAME AS name FROM information_schema.TRIGGERS WHERE "
                  "TRIGGER_SCHEMA = DATABASE() AND TRIGGER_NAME LIKE 'trg_risk_models_%'")],
    }
    used = set()
    used |= {r["v"] for r in query(conn, "SELECT DISTINCT risk_model_version AS v FROM packages "
                                         "WHERE risk_model_version IS NOT NULL")}
    used |= {r["v"] for r in query(conn, "SELECT setting_value AS v FROM settings "
                                         "WHERE setting_key = 'risk_model_version'")}
    if s["risk_models"]:
        used |= {r["v"] for r in query(conn, "SELECT model_version AS v FROM risk_models")}
    if s["snapshot_column"]:
        used |= {r["v"] for r in query(conn, "SELECT DISTINCT risk_model_version AS v FROM "
                                             "package_snapshots WHERE risk_model_version IS NOT NULL")}
    s["versions"] = sorted(used)
    return s


def main(argv=None, connect=connect):
    parser = argparse.ArgumentParser(description="Migration 006 (dry run by default).")
    parser.add_argument("--database", required=True, help="database to migrate, named explicitly")
    parser.add_argument("--rollback", action="store_true", help="run 006_rollback.sql instead")
    parser.add_argument("--apply", action="store_true",
                        help="Run the statements. Without this flag nothing is executed.")
    args = parser.parse_args(argv)

    sql_file = ROLLBACK_SQL if args.rollback else APPLY_SQL
    statements = split_sql(sql_file.read_text(encoding="utf-8"))

    try:
        conn = connect(args.database)
    except Exception as e:
        print(f"Error: cannot connect to {args.database} ({type(e).__name__}: {e}). "
              "Is MySQL running?")
        return 2
    try:
        actual = query(conn, "SELECT DATABASE() AS d")[0]["d"]
        if actual != args.database:
            print(f"Refused: connected to {actual!r}, not {args.database!r}.")
            return 2
        s = state(conn)
        print(f"Database {actual}: migration 004 {'present' if s['has_004'] else 'MISSING'}; "
              f"risk_models {'exists' if s['risk_models'] else 'missing'}; "
              f"package_snapshots.risk_model_version "
              f"{'exists' if s['snapshot_column'] else 'missing'}; "
              f"triggers {s['triggers'] or 'none'}; versions in use {s['versions'] or 'none'}")

        if not args.rollback and not s["has_004"]:
            print("Refused: migration 004 is not applied (package_snapshots.scan_id missing).")
            return 2
        if args.rollback:
            other = [v for v in s["versions"] if v != DEFAULT_VERSION]
            if other:
                print(f"Refused: risk model versions other than {DEFAULT_VERSION} are in use "
                      f"({', '.join(other)}); rolling back would lose what they mean. "
                      "Restore a backup instead.")
                return 2

        print(f"\n{sql_file.name}: {len(statements)} statements")
        for i, statement in enumerate(statements, 1):
            print(f"[{i}] {statement}")
        if not args.apply:
            print("\nDry run. Nothing was executed. Re-run with --apply to run them.")
            return 0

        for i, statement in enumerate(statements, 1):
            with conn.cursor() as cursor:
                cursor.execute(statement)
            print(f"[{i}/{len(statements)}] ok: {statement.splitlines()[0][:80]}")
        conn.commit()
        s = state(conn)
        print(f"\nDone. risk_models {'exists' if s['risk_models'] else 'missing'}; "
              f"package_snapshots.risk_model_version "
              f"{'exists' if s['snapshot_column'] else 'missing'}; triggers {s['triggers'] or 'none'}")
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
