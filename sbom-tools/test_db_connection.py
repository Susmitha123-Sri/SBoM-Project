# sbom-tools/test_db_connection.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# No database or network: pymysql.connect is patched to return fake
# connections, so nothing ever reaches MySQL.

import contextlib
import io
import os
import sys
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pymysql
import db_storage
from db_storage import DatabaseStorage, write_packages


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.executed.append(sql)
        if self.conn.fail_next:
            self.conn.fail_next -= 1
            # What pymysql raises when the socket was closed by another thread
            raise pymysql.err.InterfaceError(0, "")

    def fetchone(self):
        return {"version_id": 1}


class FakeConnection:
    """Stands in for a pymysql connection; can fail its next N queries."""
    count = 0

    def __init__(self, fail_next=0):
        FakeConnection.count += 1
        self.id = FakeConnection.count
        self.fail_next = fail_next
        self.executed = []
        self.closed = False

    def ping(self, reconnect=False):
        if self.closed:
            raise pymysql.err.InterfaceError(0, "")

    def cursor(self, *args):
        return FakeCursor(self)

    def commit(self):
        pass

    def close(self):
        self.closed = True


@contextlib.contextmanager
def quiet():
    """Hide the expected "connection lost" prints and tracebacks."""
    sink = io.StringIO()
    with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
        yield


class TestReconnectAndRetry(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch.object(db_storage.pymysql, "connect",
                                    side_effect=lambda **kw: FakeConnection())
        self.connect = patcher.start()
        self.addCleanup(patcher.stop)
        self.db = DatabaseStorage()

    def write(self, pkg):
        """Like insert_version: connect, query, return an id."""
        self.db._connect()
        with self.db.connection.cursor() as cursor:
            cursor.execute("SELECT version_id FROM versions WHERE package_name=%s",
                           (pkg["name"],))
        return 42

    def test_interface_error_once_then_retry_succeeds(self):
        """InterfaceError once -> reconnect on a new connection -> retry succeeds"""
        broken = FakeConnection(fail_next=1)
        self.db.connection = broken

        with quiet():
            result = self.db.with_reconnect(self.write, {"name": "requests"})

        self.assertEqual(result, 42)
        self.assertTrue(broken.closed, "broken connection should be closed")
        self.assertIsNot(self.db.connection, broken, "should be on a new connection")
        self.assertEqual(self.connect.call_count, 1)

    def test_second_failure_is_raised_not_swallowed(self):
        """Fails again after the retry -> InterfaceError is raised"""
        self.connect.side_effect = lambda **kw: FakeConnection(fail_next=1)
        self.db.connection = FakeConnection(fail_next=1)

        with quiet(), self.assertRaises(pymysql.err.InterfaceError):
            self.db.with_reconnect(self.write, {"name": "requests"})

    def test_other_errors_are_not_retried(self):
        """A non-connection error (e.g. ValueError) is raised without retry"""
        calls = []

        def bad(pkg):
            calls.append(pkg)
            raise ValueError("bad data")

        with self.assertRaises(ValueError):
            self.db.with_reconnect(bad, {"name": "x"})
        self.assertEqual(len(calls), 1)


class TestWritePackagesCounts(unittest.TestCase):

    def setUp(self):
        patcher = mock.patch.object(db_storage.pymysql, "connect",
                                    side_effect=lambda **kw: FakeConnection())
        patcher.start()
        self.addCleanup(patcher.stop)
        self.db = DatabaseStorage()
        self.packages = [{"name": n, "version": "1.0"} for n in ("a", "b", "c", "d")]

    def test_one_dropped_connection_all_saved(self):
        """Connection drops once mid-upload -> retried, 4 of 4 saved"""
        self.db.connection = FakeConnection()
        self.db.connection.fail_next = 0
        state = {"dropped": False}

        def save(pkg):
            self.db._connect()
            if pkg["name"] == "b" and not state["dropped"]:
                state["dropped"] = True
                self.db.connection.fail_next = 1
            with self.db.connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            return 1

        with quiet():
            inserted, failed = write_packages(self.db, self.packages, save)

        self.assertEqual((inserted, failed), (4, []))

    def test_failures_are_counted(self):
        """b keeps failing, d writes nothing -> 2 saved, failed = [b, d]"""
        def save(pkg):
            if pkg["name"] == "b":
                raise pymysql.err.InterfaceError(0, "")
            if pkg["name"] == "d":
                return None
            return 1

        with quiet():
            inserted, failed = write_packages(self.db, self.packages, save)

        self.assertEqual(inserted, 2)
        self.assertEqual(failed, ["b", "d"])

    def test_failures_are_printed(self):
        """Each failure is printed with its package name and traceback"""
        def save(pkg):
            raise pymysql.err.InterfaceError(0, "")

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            write_packages(self.db, [{"name": "requests"}], save)

        self.assertIn("Failed to save package requests", out.getvalue())
        self.assertIn("InterfaceError", out.getvalue())


class TestConnectionPerThread(unittest.TestCase):

    def test_each_thread_gets_its_own_connection(self):
        """Request thread and background thread never share a connection"""
        with mock.patch.object(db_storage.pymysql, "connect",
                               side_effect=lambda **kw: FakeConnection()):
            db = DatabaseStorage()
            db._connect()
            main_conn = db.connection

            seen = {}

            def background():
                seen["before"] = db.connection
                db._connect()
                seen["after"] = db.connection
                db.reset_connection()   # closing ours must not touch main's

            t = threading.Thread(target=background)
            t.start()
            t.join()

        self.assertIsNone(seen["before"], "new thread starts with no connection")
        self.assertIsNotNone(seen["after"])
        self.assertIsNot(seen["after"], main_conn)
        self.assertIs(db.connection, main_conn)
        self.assertFalse(main_conn.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
