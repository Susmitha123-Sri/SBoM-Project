# sbom-tools/fake_mysql.py
#
# Test helper (not a test module): an in-memory SQLite database behind the
# small part of the pymysql API that db_storage uses, so the real SQL runs
# in tests without MySQL.

import re
import sqlite3
import unittest
from datetime import datetime
from unittest import mock

import pymysql
import db_storage
from db_storage import DatabaseStorage

sqlite3.register_converter("DATETIME", lambda b: datetime.fromisoformat(b.decode()))
sqlite3.register_adapter(datetime, lambda d: d.isoformat(" "))

SCHEMA = """
    CREATE TABLE scan (
        scan_id INTEGER PRIMARY KEY,
        target_name TEXT,
        scan_timestamp TEXT
    );
    CREATE TABLE packages (
        package_id INTEGER PRIMARY KEY,
        package_name TEXT,
        ecosystem TEXT,
        risk_score REAL,
        risk_level TEXT,
        risk_reasons TEXT,
        risk_tier TEXT,
        risk_days_behind INTEGER,
        risk_vuln_count INTEGER,
        risk_is_abandoned INTEGER,
        risk_version_id INTEGER,
        risk_model_version TEXT,
        risk_computed_at DATETIME
    );
    CREATE TABLE scan_results (
        spr_id INTEGER PRIMARY KEY,
        scan_id INTEGER,
        version_id INTEGER,
        vulnerability_id TEXT,
        fixed_version TEXT,
        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE versions (
        version_id INTEGER PRIMARY KEY,
        scan_id INTEGER,
        package_id INTEGER,
        package_name TEXT,
        version_number TEXT,
        latest_version TEXT,
        status TEXT,
        baseline_status TEXT,
        release_date DATETIME,
        days_outdated INTEGER,
        versions_behind TEXT,
        severity_level TEXT,
        days_since_release INTEGER,
        age_tier TEXT
    );
    CREATE TABLE package_reviews (
        review_id INTEGER PRIMARY KEY,
        package_id INTEGER NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'Open',
        reviewer TEXT,
        reviewed_at DATETIME,
        note TEXT
    );
    CREATE TABLE package_review_history (
        history_id INTEGER PRIMARY KEY,
        package_id INTEGER NOT NULL,
        old_status TEXT,
        new_status TEXT NOT NULL,
        reviewer TEXT NOT NULL,
        note TEXT,
        changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
"""


class SqliteCursor:
    """The parts of a pymysql DictCursor that db_storage uses."""

    def __init__(self, db):
        self.cur = db.cursor()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=()):
        # MySQL's NOW() -> SQLite's CURRENT_TIMESTAMP
        sql = sql.replace("%s", "?").replace("NOW()", "CURRENT_TIMESTAMP")
        # Row locks don't exist in SQLite; ON DUPLICATE KEY UPDATE x = VALUES(x)
        # -> ON CONFLICT DO UPDATE SET x = excluded.x
        sql = sql.replace(" FOR UPDATE", "")
        if "ON DUPLICATE KEY UPDATE" in sql:
            sql = sql.replace("ON DUPLICATE KEY UPDATE", "ON CONFLICT DO UPDATE SET")
            sql = re.sub(r"VALUES\((\w+)\)", r"excluded.\1", sql)
        self.cur.execute(sql, tuple(params or ()))

    def _row(self, values):
        return dict(zip([d[0] for d in self.cur.description], values))

    def fetchall(self):
        return [self._row(r) for r in self.cur.fetchall()]

    def fetchone(self):
        r = self.cur.fetchone()
        return self._row(r) if r is not None else None

    @property
    def lastrowid(self):
        return self.cur.lastrowid

    @property
    def rowcount(self):
        return self.cur.rowcount

    def close(self):
        pass


class SqliteConnection:
    def __init__(self, db):
        self.db = db

    def cursor(self, *args):
        return SqliteCursor(self.db)

    def ping(self, reconnect=False):
        pass

    def commit(self):
        self.db.commit()

    def rollback(self):
        self.db.rollback()

    def close(self):
        pass   # keep the shared in-memory database alive


def make_sqlite():
    db = sqlite3.connect(":memory:", detect_types=sqlite3.PARSE_DECLTYPES,
                         check_same_thread=False)
    db.executescript(SCHEMA)
    return db


class SqliteTestCase(unittest.TestCase):
    """self.db is a DatabaseStorage whose connections all use self.sqlite."""

    def setUp(self):
        self.sqlite = make_sqlite()
        self.addCleanup(self.sqlite.close)
        conn = SqliteConnection(self.sqlite)

        for patcher in (
            mock.patch.object(db_storage, "get_new_connection", lambda: conn),
            mock.patch.object(pymysql, "connect", lambda **kw: conn),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.db = DatabaseStorage()

    def rows(self, sql, params=()):
        cur = self.sqlite.execute(sql, params)
        return [dict(zip([d[0] for d in cur.description], r)) for r in cur.fetchall()]
