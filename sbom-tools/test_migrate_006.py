# sbom-tools/test_migrate_006.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Migration 006 and sbom-tools/migrate_006.py: the files split into the
# expected statements, the v1 row in the migration equals risk.py's defaults,
# the dry run executes nothing, --apply runs every statement in order,
# --database is required and must match the connection, apply needs 004, and
# rollback is refused while a version other than v1 is in use. A fake
# connection records the SQL; no MySQL.

import contextlib
import io
import json
import os
import re
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)

import migrate_006                                   # noqa: E402
from risk import DEFAULT_RISK_PARAMS                 # noqa: E402


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        if params is not None:                       # like pymysql: % formatting for any tuple
            sql % tuple(params)
        self.conn.executed.append(sql)
        self.rows = self.conn.answer(sql)

    def fetchall(self):
        return self.rows


class FakeConnection:
    """Answers the runner's state queries from a few flags."""

    def __init__(self, database="sbom_test_copy", has_004=True, applied=False, versions=()):
        self.database, self.has_004, self.applied = database, has_004, applied
        self.versions = list(versions)
        self.executed, self.committed, self.closed = [], False, False

    def answer(self, sql):
        if "DATABASE() AS d" in sql:
            return [{"d": self.database}]
        if "COLUMN_NAME = 'scan_id'" in sql:
            return [{"n": int(self.has_004)}]
        if "TABLE_NAME = 'risk_models'" in sql or "COLUMN_NAME = 'risk_model_version'" in sql:
            return [{"n": int(self.applied)}]
        if "information_schema.TRIGGERS" in sql:
            return ([{"name": "trg_risk_models_no_delete"}, {"name": "trg_risk_models_no_update"}]
                    if self.applied else [])
        if "FROM packages" in sql:
            return [{"v": v} for v in self.versions]
        return []

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


def changes(conn):
    """Statements that are not the runner's own read-only queries."""
    return [s for s in conn.executed if not s.lstrip().upper().startswith("SELECT")]


class TestMigrate006(unittest.TestCase):

    def run_main(self, *argv, conn=None):
        conn = conn or FakeConnection()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = migrate_006.main(list(argv), connect=lambda database: conn)
        return code, out.getvalue(), conn

    def test_files_split_into_statements(self):
        apply = migrate_006.split_sql(migrate_006.APPLY_SQL.read_text(encoding="utf-8"))
        self.assertEqual([s.split()[0:3] for s in apply],
                         [["SET", "NAMES", "utf8mb4"], ["CREATE", "TABLE", "IF"],
                          ["INSERT", "IGNORE", "INTO"], ["CREATE", "TRIGGER", "IF"],
                          ["CREATE", "TRIGGER", "IF"], ["ALTER", "TABLE", "package_snapshots"]])
        rollback = migrate_006.split_sql(migrate_006.ROLLBACK_SQL.read_text(encoding="utf-8"))
        self.assertEqual(len(rollback), 5)
        self.assertTrue(rollback[-1].startswith("DROP TABLE IF EXISTS risk_models"))

    def test_seeded_v1_equals_the_defaults(self):
        text = migrate_006.APPLY_SQL.read_text(encoding="utf-8")
        seeded = json.loads(re.search(r"VALUES \('v1', '(\{.*?\})'", text).group(1))
        self.assertEqual(seeded, DEFAULT_RISK_PARAMS)

    def test_dry_run_executes_nothing(self):
        code, out, conn = self.run_main("--database", "sbom_test_copy")
        self.assertEqual(code, 0)
        self.assertEqual(changes(conn), [])
        self.assertFalse(conn.committed)
        self.assertTrue(conn.closed)
        self.assertIn("006_risk_models.sql: 6 statements", out)
        self.assertIn("Dry run. Nothing was executed.", out)

    def test_apply_runs_every_statement_in_order(self):
        code, out, conn = self.run_main("--database", "sbom_test_copy", "--apply")
        self.assertEqual(code, 0, out)
        statements = migrate_006.split_sql(migrate_006.APPLY_SQL.read_text(encoding="utf-8"))
        self.assertEqual(changes(conn), statements)
        self.assertTrue(conn.committed)
        self.assertIn("[6/6] ok: ALTER TABLE package_snapshots", out)

    def test_database_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as e:
            migrate_006.main([], connect=lambda database: FakeConnection())
        self.assertEqual(e.exception.code, 2)

    def test_connection_to_another_database_is_refused(self):
        code, out, conn = self.run_main("--database", "sbom_test_copy", "--apply",
                                        conn=FakeConnection(database="sbom_common"))
        self.assertEqual(code, 2)
        self.assertIn("Refused: connected to 'sbom_common'", out)
        self.assertEqual(changes(conn), [])

    def test_apply_needs_004(self):
        code, out, conn = self.run_main("--database", "sbom_test_copy", "--apply",
                                        conn=FakeConnection(has_004=False))
        self.assertEqual(code, 2)
        self.assertIn("migration 004 is not applied", out)
        self.assertEqual(changes(conn), [])

    def test_rollback_refused_when_another_version_is_used(self):
        conn = FakeConnection(applied=True, versions=["v1", "v2"])
        code, out, conn = self.run_main("--database", "sbom_test_copy", "--rollback", "--apply",
                                        conn=conn)
        self.assertEqual(code, 2)
        self.assertIn("versions other than v1 are in use (v2)", out)
        self.assertEqual(changes(conn), [])

    def test_rollback_with_only_v1(self):
        conn = FakeConnection(applied=True, versions=["v1"])
        code, out, conn = self.run_main("--database", "sbom_test_copy", "--rollback", "--apply",
                                        conn=conn)
        self.assertEqual(code, 0, out)
        self.assertEqual(len(changes(conn)), 5)


if __name__ == "__main__":
    unittest.main()
