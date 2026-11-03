# sbom-tools/test_snapshot_summary.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# sbom-tools/snapshot_summary.py and the summarize_snapshots.py CLI: per-run
# counts (tiers as repo rows, risk and review also as distinct packages) equal
# a direct GROUP BY over package_snapshots, only finished completed / partial
# runs are summarised (one per date), reruns are idempotent, tier crossings
# between consecutive runs with new / gone rows, pairs follow the current runs,
# package_snapshots is only read, the page data (labels, gaps, missing days,
# the banner counts, migration 005 missing), and the CLI preview / --apply /
# --limit / errors. Snapshots are written with the real write_daily_snapshot.
# SQLite stand-in (fake_mysql.py); no network.

import contextlib
import io
import os
import sys
import unittest
from datetime import date

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)

import db_storage                                    # noqa: E402
import fake_mysql                                    # noqa: E402
import snapshot_summary as ss                        # noqa: E402
import summarize_snapshots                           # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402
from unittest import mock                            # noqa: E402

DAY1, DAY2, DAY3 = date(2026, 11, 3), date(2026, 11, 4), date(2026, 11, 6)   # 11-05 missing


class SummaryTestCase(SqliteTestCase):
    """
    Day 1: two repos, three packages, five snapshot rows (the orphan row has
    no package_id and is never snapshotted). Day 2: one row Fresh -> Aging,
    one row gone, one row new, lodash's risk and requests' review changed.
    """

    def setUp(self):
        super().setUp()
        self.sqlite.executescript("""
            INSERT INTO scan (scan_id, target_name) VALUES
                (1, 'https://github.com/a/one'), (2, 'https://github.com/b/two');
            INSERT INTO packages (package_id, package_name, ecosystem, risk_level) VALUES
                (1, 'requests', 'python', 'Medium'),
                (2, 'lodash', 'npm', NULL),
                (3, 'react', 'npm', 'Low');
            INSERT INTO versions (version_id, scan_id, package_id, package_name,
                                  version_number, status, age_tier) VALUES
                (10, 1, 1, 'requests', '2.31.0', 'outdated', 'Stale'),
                (11, 2, 1, 'requests', '2.32.0', 'up_to_date', NULL),
                (12, 2, 2, 'lodash', '4.17.20', 'outdated', 'Abandoned'),
                (13, 2, NULL, 'orphan', '1.0', 'unknown', NULL),
                (14, 1, 3, 'react', '17.0.0', 'outdated', 'Fresh'),
                (15, 2, 3, 'react', '18.0.0', 'outdated', 'Fresh');
            INSERT INTO package_reviews (package_id, status) VALUES (2, 'Resolved');
        """)
        self.sqlite.commit()
        self.run1 = self.db.write_daily_snapshot(DAY1)["run_id"]

    def day2(self, lookup_failed=0):
        self.sqlite.executescript("""
            UPDATE versions SET age_tier = 'Aging' WHERE version_id = 14;
            DELETE FROM versions WHERE version_id = 11;
            INSERT INTO versions (version_id, scan_id, package_id, package_name,
                                  version_number, status, age_tier)
                VALUES (16, 1, 2, 'lodash', '4.17.21', 'up_to_date', 'Aging');
            UPDATE packages SET risk_level = 'High' WHERE package_id = 2;
            INSERT INTO package_reviews (package_id, status) VALUES (1, 'Compensating Control');
        """)
        self.sqlite.commit()
        return self.db.write_daily_snapshot(DAY2, lookup_failed=lookup_failed)["run_id"]

    def summary(self, run_id, dimension, field="rows_n"):
        return {r["value"]: r[field] for r in self.rows(
            "SELECT value, rows_n, packages_n FROM snapshot_summary "
            "WHERE run_id = ? AND dimension = ?", (run_id, dimension))}

    def direct(self, run_id, expr, field="COUNT(*)"):
        return {r["v"]: r["n"] for r in self.rows(
            f"SELECT {expr} AS v, {field} AS n FROM package_snapshots "
            f"WHERE run_id = ? GROUP BY {expr}", (run_id,))}

    def transitions(self, prev, run):
        return {(r["from_tier"], r["to_tier"]): r["rows_n"] for r in self.rows(
            "SELECT from_tier, to_tier, rows_n FROM snapshot_transitions "
            "WHERE prev_run_id = ? AND run_id = ?", (prev, run))}

    def snapshot_rows(self):
        return self.rows("SELECT * FROM package_snapshots ORDER BY snapshot_id")

    def cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = summarize_snapshots.main(list(argv), clock=lambda: 0.0)
        return code, out.getvalue()


class TestSummarizeRun(SummaryTestCase):

    def test_counts(self):
        self.assertEqual(ss.summarize_run(self.run1), (5, 3))
        self.assertEqual(self.summary(self.run1, "tier"),
                         {"Stale": 1, "unknown": 1, "Abandoned": 1, "Fresh": 2})
        self.assertEqual(self.summary(self.run1, "risk", "packages_n"),
                         {"Medium": 1, "Not scored": 1, "Low": 1})
        self.assertEqual(self.summary(self.run1, "review", "packages_n"),
                         {"Open": 2, "Resolved": 1})
        self.assertEqual(self.summary(self.run1, "risk"),            # repo rows: requests twice
                         {"Medium": 2, "Not scored": 1, "Low": 2})
        marker = self.rows("SELECT * FROM snapshot_summary_runs")
        self.assertEqual([(m["run_id"], m["snapshot_date"], m["run_status"], m["rows_n"],
                           m["packages_n"]) for m in marker],
                         [(self.run1, "2026-11-03", "completed", 5, 3)])

    def test_equals_a_direct_group_by(self):
        run2 = self.day2()
        for run in (self.run1, run2):
            ss.summarize_run(run)
            for dim, (expr, _) in ss.DIMENSIONS.items():
                self.assertEqual(self.summary(run, dim), self.direct(run, expr), (run, dim))
                self.assertEqual(self.summary(run, dim, "packages_n"),
                                 self.direct(run, expr, "COUNT(DISTINCT package_id)"), (run, dim))

    def test_rerun_is_idempotent(self):
        ss.summarize_run(self.run1)
        first = self.rows("SELECT run_id, dimension, value, rows_n, packages_n "
                          "FROM snapshot_summary ORDER BY 1, 2, 3")
        ss.summarize_run(self.run1)
        self.assertEqual(self.rows("SELECT run_id, dimension, value, rows_n, packages_n "
                                   "FROM snapshot_summary ORDER BY 1, 2, 3"), first)
        self.assertEqual(len(self.rows("SELECT * FROM snapshot_summary_runs")), 1)

    def test_only_finished_completed_or_partial_runs(self):
        run2 = self.day2(lookup_failed=4)                         # partial
        failed = self.db.record_failed_run("monitor", "offline", DAY3)
        self.sqlite.execute("INSERT INTO scan_runs (snapshot_date, status) "
                            "VALUES ('2026-11-07', 'running')")
        self.sqlite.commit()
        runs = ss.eligible_runs()
        self.assertEqual([(r["run_id"], r["status"]) for r in runs],
                         [(self.run1, "completed"), (run2, "partial")])
        self.assertEqual(runs[0]["snapshot_date"], DAY1)
        with self.assertRaises(ValueError):
            ss.summarize_run(failed)
        self.assertEqual(self.rows("SELECT * FROM snapshot_summary_runs"), [])

    def test_one_run_per_date(self):
        self.sqlite.execute("INSERT INTO scan_runs (snapshot_date, finished_at, status) "
                            "VALUES ('2026-11-03', CURRENT_TIMESTAMP, 'completed')")
        self.sqlite.commit()
        self.assertEqual([r["run_id"] for r in ss.eligible_runs()], [self.run1])

    def test_failed_summary_rolls_back(self):
        real_execute = fake_mysql.SqliteCursor.execute

        def failing(cursor, sql, params=()):
            if "'review'" in sql:
                raise RuntimeError("disk full")
            return real_execute(cursor, sql, params)

        with mock.patch.object(fake_mysql.SqliteCursor, "execute", failing):
            with self.assertRaises(RuntimeError):
                ss.summarize_run(self.run1)
        self.assertEqual(self.rows("SELECT * FROM snapshot_summary"), [])
        self.assertEqual(self.rows("SELECT * FROM snapshot_summary_runs"), [])


class TestTransitions(SummaryTestCase):

    def test_crossings_new_and_gone(self):
        run2 = self.day2()
        counts = ss.summarize_pair(self.run1, run2)
        self.assertEqual(self.transitions(self.run1, run2), {
            ("Stale", "Stale"): 1, ("Abandoned", "Abandoned"): 1, ("Fresh", "Aging"): 1,
            ("Fresh", "Fresh"): 1, ("unknown", "(gone)"): 1, ("(new)", "Aging"): 1})
        self.assertEqual(counts, {"rows_both": 4, "rows_changed": 1, "rows_new": 1,
                                  "rows_gone": 1})
        pair = self.rows("SELECT * FROM snapshot_transition_pairs")[0]
        self.assertEqual((pair["rows_both"], pair["rows_changed"], pair["rows_new"],
                          pair["rows_gone"]), (4, 1, 1, 1))

    def test_unchanged_pair_is_still_marked_done(self):
        run2 = self.day2()
        run3 = self.db.write_daily_snapshot(DAY3)["run_id"]
        self.assertEqual(ss.summarize_pair(run2, run3)["rows_changed"], 0)
        self.assertEqual([(p["run_id"], r["run_id"], done) for p, r, done in ss.consecutive_pairs()],
                         [(self.run1, run2, False), (run2, run3, True)])

    def test_rerun_is_idempotent(self):
        run2 = self.day2()
        ss.summarize_pair(self.run1, run2)
        first = self.transitions(self.run1, run2)
        ss.summarize_pair(self.run1, run2)
        self.assertEqual(self.transitions(self.run1, run2), first)
        self.assertEqual(len(self.rows("SELECT * FROM snapshot_transition_pairs")), 1)

    def test_pairs_follow_the_current_runs(self):
        run2 = self.day2()
        ss.summarize_pair(self.run1, run2)
        run0 = self.db.write_daily_snapshot(date(2026, 11, 1))["run_id"]   # back-dated later
        self.assertEqual([(p["run_id"], r["run_id"], done) for p, r, done in ss.consecutive_pairs()],
                         [(run0, self.run1, False), (self.run1, run2, True)])

    def test_unfinished_run_is_refused(self):
        failed = self.db.record_failed_run("monitor", "offline", DAY3)
        with self.assertRaises(ValueError):
            ss.summarize_pair(self.run1, failed)
        self.assertEqual(self.rows("SELECT * FROM snapshot_transition_pairs"), [])


class TestSnapshotsOnlyRead(SummaryTestCase):

    def test_package_snapshots_unchanged(self):
        run2 = self.day2()
        before = self.snapshot_rows()
        executed = []
        real_execute = fake_mysql.SqliteCursor.execute

        def recording(cursor, sql, params=()):
            executed.append(" ".join(sql.split()).upper())
            return real_execute(cursor, sql, params)

        with mock.patch.object(fake_mysql.SqliteCursor, "execute", recording):
            ss.summarize_run(self.run1)
            ss.summarize_run(run2)
            ss.summarize_pair(self.run1, run2)
            ss.trends_data()
        self.assertEqual(self.snapshot_rows(), before)
        for sql in executed:
            for verb in ("INSERT INTO PACKAGE_SNAPSHOTS", "UPDATE PACKAGE_SNAPSHOTS",
                         "DELETE FROM PACKAGE_SNAPSHOTS", "INSERT INTO SCAN_RUNS",
                         "UPDATE SCAN_RUNS"):
                self.assertNotIn(verb, sql)


class TestTrendsData(SummaryTestCase):

    def setUp(self):
        super().setUp()
        self.run2 = self.day2(lookup_failed=2)                       # partial
        self.run3 = self.db.write_daily_snapshot(DAY3)["run_id"]     # after a missing day
        self.failed = self.db.record_failed_run("monitor", "offline", DAY3)

    def summarize_all(self):
        for r in ss.eligible_runs():
            ss.summarize_run(r["run_id"])
        for p, r, _ in ss.consecutive_pairs():
            ss.summarize_pair(p["run_id"], r["run_id"])

    def test_page_data(self):
        self.summarize_all()
        data = ss.trends_data()
        self.assertIsNone(data["error"])
        self.assertEqual(data["labels"], ["2026-11-03", "2026-11-04 (partial)",
                                          "2026-11-05 (no data)", "2026-11-06"])
        self.assertEqual(data["tier"]["counts"], "repo rows (one per package per repository)")
        self.assertEqual(data["risk"]["counts"], "distinct packages")
        self.assertEqual(data["review"]["counts"], "distinct packages")
        tiers = {s["name"]: s["data"] for s in data["tier"]["series"]}
        self.assertEqual([s["name"] for s in data["tier"]["series"]],
                         ["Abandoned", "Stale", "Aging", "Fresh", "unknown"])
        self.assertEqual(tiers["Aging"], [0, 2, None, 2])
        self.assertEqual(tiers["unknown"], [1, 0, None, 0])
        risk = {s["name"]: s["data"] for s in data["risk"]["series"]}
        self.assertEqual(risk["High"], [0, 1, None, 1])
        self.assertEqual(risk["Not scored"], [1, 0, None, 0])
        review = {s["name"]: s["data"] for s in data["review"]["series"]}
        self.assertEqual(review["Compensating Control"], [0, 1, None, 1])

        cross = data["crossings"]
        self.assertEqual(cross["counts"], "repo rows (one per package per repository)")
        self.assertEqual(cross["labels"], ["2026-11-03 -> 2026-11-04", "2026-11-04 -> 2026-11-06"])
        self.assertEqual(cross["series"], [{"name": "Fresh -> Aging", "data": [1, 0]}])
        self.assertEqual((cross["new"], cross["gone"], cross["changed"]), ([1, 0], [1, 0], [1, 0]))
        self.assertIn({"pair": "2026-11-03 -> 2026-11-04", "from": "unknown", "to": "(gone)",
                       "rows": 1}, cross["table"])

        self.assertEqual((data["unsummarized"], data["pairs_pending"], data["missing_days"]),
                         (0, 0, 1))
        table = [(t["date"], t["status"], t["run_id"]) for t in data["runs_table"]]
        self.assertEqual(table, [("2026-11-03", "completed", self.run1),
                                 ("2026-11-04", "partial", self.run2),
                                 ("2026-11-05", "missing", None),
                                 ("2026-11-06", "completed", self.run3),
                                 ("2026-11-06", "failed", self.failed)])
        partial = data["runs_table"][1]
        self.assertEqual((partial["lookup_failed"], partial["summarized"]), (2, True))

    def test_unsummarized_runs_are_counted_not_shown(self):
        ss.summarize_run(self.run1)
        data = ss.trends_data()
        self.assertEqual((data["unsummarized"], data["pairs_pending"]), (2, 2))
        self.assertEqual(data["labels"], ["2026-11-03"])
        self.assertEqual(data["crossings"]["labels"], [])

    def test_missing_migration(self):
        for table in ("snapshot_transitions", "snapshot_transition_pairs", "snapshot_summary",
                      "snapshot_summary_runs"):
            self.sqlite.execute(f"DROP TABLE {table}")
        self.assertIn("Migration 005 is not applied", ss.trends_data()["error"])

    def test_lookup_failed_from_notes(self):
        self.assertEqual(ss.lookup_failed("lookup_failed=7; skipped_without_package_id=0"), 7)
        self.assertIsNone(ss.lookup_failed("offline"))
        self.assertIsNone(ss.lookup_failed(None))


class TestCli(SummaryTestCase):

    def test_preview_writes_nothing(self):
        self.day2()
        code, out = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("Finished runs: 2 (summarised 0, pending 2); consecutive pairs: 1 (pending 1)",
                      out)
        self.assertIn("Preview only", out)
        self.assertEqual(self.rows("SELECT * FROM snapshot_summary_runs"), [])
        self.assertEqual(self.rows("SELECT * FROM snapshot_transition_pairs"), [])

    def test_apply_then_nothing_left(self):
        self.day2()
        code, out = self.cli("--apply")
        self.assertEqual(code, 0)
        self.assertIn("[1/3] run 1 (2026-11-03, completed): 5 rows, 3 packages, 0.0 s", out)
        self.assertIn("[3/3] pair 2026-11-03 -> 2026-11-04: 1 of 4 rows changed tier, "
                      "1 new, 1 gone, 0.0 s", out)
        code, out = self.cli("--apply")
        self.assertEqual(code, 0)
        self.assertIn("Nothing to summarise.", out)

    def test_limit(self):
        self.day2()
        code, out = self.cli("--apply", "--limit", "1")
        self.assertEqual(code, 0)
        self.assertEqual(len(self.rows("SELECT * FROM snapshot_summary_runs")), 1)
        self.assertEqual(self.rows("SELECT * FROM snapshot_transition_pairs"), [])
        self.assertEqual(self.cli("--limit", "0")[0], 2)

    def test_one_failure_does_not_stop_the_rest(self):
        self.day2()
        real = ss.summarize_run

        def flaky(run_id):
            if run_id == self.run1:
                raise RuntimeError("boom")
            return real(run_id)

        with mock.patch.object(ss, "summarize_run", flaky):
            code, out = self.cli("--apply")
        self.assertEqual(code, 1)
        self.assertIn("run failed (RuntimeError: boom)", out)
        self.assertIn("Done: 2 summarised, 1 failed.", out)
        self.assertEqual([r["run_id"] for r in self.rows("SELECT run_id FROM snapshot_summary_runs")],
                         [self.run1 + 1])

    def test_database_down(self):
        def broken():
            raise ConnectionError("refused")

        with mock.patch.object(db_storage, "get_new_connection", broken):
            code, out = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("Is MySQL running?", out)

    def test_missing_migration(self):
        self.sqlite.execute("DROP TABLE snapshot_summary_runs")
        code, out = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("migration 005 is not applied", out)


if __name__ == "__main__":
    unittest.main()
