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
        normalized_name TEXT,
        matched_name TEXT,
        match_ecosystem TEXT,
        match_method TEXT,
        match_score REAL,
        match_status TEXT,
        matched_at DATETIME,
        risk_score REAL,
        risk_level TEXT,
        risk_reasons TEXT,
        risk_tier TEXT,
        risk_days_behind INTEGER,
        risk_vuln_count INTEGER,
        risk_is_abandoned INTEGER,
        risk_version_id INTEGER,
        risk_model_version TEXT,
        risk_computed_at DATETIME,
        priority_score REAL,
        priority_rank INTEGER,
        priority_reason TEXT,
        priority_category TEXT,
        priority_version_id INTEGER,
        priority_model_version TEXT,
        priority_computed_at DATETIME
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
    CREATE TABLE labeled_pairs (
        pair_id INTEGER PRIMARY KEY,
        name_a TEXT NOT NULL,
        ecosystem_a TEXT,
        name_b TEXT NOT NULL,
        ecosystem_b TEXT,
        label TEXT NOT NULL,
        labeled_by TEXT NOT NULL,
        labeled_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        source TEXT NOT NULL DEFAULT 'manual',
        package_id INTEGER,
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
    -- 002b + 004: one snapshot row per versions row per run, insert-only
    CREATE TABLE scan_runs (
        run_id INTEGER PRIMARY KEY,
        snapshot_date TEXT NOT NULL,
        started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        finished_at DATETIME,
        status TEXT NOT NULL DEFAULT 'running',
        package_count INTEGER,
        trigger_source TEXT,
        notes TEXT
    );
    CREATE TABLE package_snapshots (
        snapshot_id INTEGER PRIMARY KEY,
        run_id INTEGER NOT NULL,
        package_id INTEGER NOT NULL,
        version_id INTEGER NOT NULL,
        scan_id INTEGER,
        snapshot_date TEXT NOT NULL,
        package_name TEXT,
        ecosystem TEXT,
        installed_version TEXT,
        latest_version TEXT,
        version_status TEXT,
        age_tier TEXT,
        days_behind INTEGER,
        days_since_release INTEGER,
        versions_behind TEXT,
        installed_release_date TEXT,
        latest_release_date TEXT,
        is_abandoned INTEGER,
        vuln_count INTEGER,
        normalized_name TEXT,
        match_status TEXT,
        match_score REAL,
        risk_score REAL,
        risk_level TEXT,
        priority_score REAL,
        priority_rank INTEGER,
        review_status TEXT,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (run_id, version_id)
    );
    CREATE TRIGGER trg_snap_no_update BEFORE UPDATE ON package_snapshots
        BEGIN SELECT RAISE(ABORT, 'package_snapshots is insert-only'); END;
    CREATE TRIGGER trg_snap_no_delete BEFORE DELETE ON package_snapshots
        BEGIN SELECT RAISE(ABORT, 'package_snapshots is insert-only'); END;
    CREATE TRIGGER trg_runs_no_delete BEFORE DELETE ON scan_runs
        BEGIN SELECT RAISE(ABORT, 'scan_runs rows are never deleted'); END;
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
