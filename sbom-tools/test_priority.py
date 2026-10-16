# sbom-tools/test_priority.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Update priority (priority.py, packages.priority_*): points, categories,
# review penalty, stable ranking, the latest-scan rule, the monitor job and
# the pages. No network; SQLite stand-in for MySQL (see fake_mysql.py).

import contextlib
import io
import os
import random
import sys
import unittest
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import priority                                     # noqa: E402
from priority import (                              # noqa: E402
    INVESTIGATE, MONITOR, NO_ACTION, PLAN_UPDATE, PRIORITY_MODEL_VERSION, REASON_MAX_LENGTH,
    UPDATE_NOW, category_for, days_behind_points, jump_kind, rank_priorities, repo_points,
    score_priority,
)
from fake_mysql import SqliteTestCase               # noqa: E402
from db_storage import DatabaseStorage, PRIORITY_FILTERS, PRIORITY_NOT_SET  # noqa: E402
import test_upload_pipeline   # RouteTestCase (module import, so its tests aren't re-run here)


def outdated(risk_score=40, days=400, gap="1.0.0", repos=1, review="Open", reviewer=None,
             risk_level="Medium", installed="1.0.0", latest="2.0.0"):
    """score_priority() for an outdated package with known risk."""
    return score_priority("outdated", risk_level, risk_score, days, gap,
                          installed, latest, repos, review, reviewer)


class TestPoints(unittest.TestCase):

    def test_days_behind_bands(self):
        self.assertEqual([days_behind_points(d) for d in (0, 30, 31, 180, 181, 365, 366, 730, 731)],
                         [0, 0, 5, 5, 10, 10, 15, 15, 20])

    def test_repo_bands(self):
        self.assertEqual([repo_points(n) for n in (0, 1, 2, 3, 4, 5, 50)],
                         [0, 0, 5, 10, 10, 15, 15])

    def test_jump_kind(self):
        self.assertEqual(jump_kind("1.0.0"), "major")
        self.assertEqual(jump_kind("0.12.0"), "minor")
        self.assertEqual(jump_kind("0.0.4"), "patch")
        self.assertIsNone(jump_kind("0.0.0"))
        self.assertIsNone(jump_kind("N/A"))

    def test_category_cutoffs(self):
        self.assertEqual([category_for(s) for s in (100, 60, 59, 35, 34, 0)],
                         [UPDATE_NOW, UPDATE_NOW, PLAN_UPDATE, PLAN_UPDATE, MONITOR, MONITOR])


class TestScorePriority(unittest.TestCase):

    def test_points_add_up(self):
        p = outdated(risk_score=100, days=1200, gap="2.0.0", repos=1)
        self.assertEqual((p["score"], p["category"]), (85, UPDATE_NOW))   # 50+20+15+0
        self.assertEqual(p["model_version"], PRIORITY_MODEL_VERSION)
        self.assertTrue(p["reason"].startswith("Score 85: "))
        self.assertIn("may need code changes (+15)", p["reason"])

    def test_bigger_jump_ranks_higher(self):
        major, minor, patch = (outdated(gap=g)["score"] for g in ("1.0.0", "0.1.0", "0.0.1"))
        self.assertGreater(major, minor)
        self.assertGreater(minor, patch)
        self.assertEqual(major - minor, 5)

    def test_up_to_date_needs_no_update(self):
        p = score_priority("up_to_date", "Low", 0, 0, "0.0.0", "1.0", "1.0", 3)
        self.assertEqual((p["score"], p["category"], p["group"]), (None, NO_ACTION, None))
        self.assertEqual(p["reason"], "Up to date: no update needed")

    def test_unknowns_are_investigate(self):
        cases = {
            "risk unknown": ("outdated", "Unknown", None),
            "risk not scored yet": ("outdated", None, None),
            "latest version unknown": ("unknown", "Low", 10),
        }
        for cause, (status, level, score) in cases.items():
            p = score_priority(status, level, score, None, "N/A", "1.0", None, 2)
            self.assertEqual((p["score"], p["category"], p["group"]),
                             (None, INVESTIGATE, priority.UNSCORED), cause)
            self.assertIn(cause, p["reason"])
            self.assertIn("used in 2 repos", p["reason"])

    def test_review_lowers_the_score_and_says_so(self):
        base = outdated(risk_score=100, days=1200)["score"]          # 85
        for status, penalty in priority.REVIEW_PENALTY.items():
            p = outdated(risk_score=100, days=1200, review=status, reviewer="alice")
            self.assertEqual(p["score"], base - penalty, status)
            self.assertEqual(p["group"], priority.SCORED, status)    # still in the queue
            if penalty:
                self.assertIn(f"{status} by alice: ranked lower (-{penalty})", p["reason"])
            else:
                self.assertNotIn("ranked lower", p["reason"])

    def test_review_penalty_never_goes_below_zero(self):
        p = outdated(risk_score=0, days=0, gap="0.0.1", review="Resolved")
        self.assertEqual((p["score"], p["category"]), (0, MONITOR))

    def test_reason_is_trimmed(self):
        p = outdated(installed="1." + "9" * 400, latest="2." + "9" * 400,
                     review="Resolved", reviewer="x" * 100)
        self.assertLessEqual(len(p["reason"]), REASON_MAX_LENGTH)
        self.assertTrue(p["reason"].endswith("..."))


class TestRankPriorities(unittest.TestCase):

    def items(self):
        def item(package_id, name, p, risk_score=40, days=400, repos=1, review="Open"):
            return {"package_id": package_id, "package_name": name, "priority": p,
                    "risk_score": risk_score, "days_behind": days, "repo_count": repos,
                    "review_status": review}
        investigate = score_priority("outdated", "Unknown", None, None, "N/A", "1", "2", 1)
        return [
            item(1, "zeta", outdated(risk_score=40)),
            item(2, "alpha", outdated(risk_score=40)),           # same score: name decides
            item(3, "top", outdated(risk_score=100, days=1200), risk_score=100, days=1200),
            item(4, "uptodate", score_priority("up_to_date", "Low", 0, 0, "0.0.0", "1", "1", 1)),
            item(5, "unk-busy", investigate, repos=4),
            item(6, "unk-quiet", investigate),
            item(7, "unk-reviewed", investigate, repos=4, review="Resolved"),
            item(8, "low", outdated(risk_score=0, days=10, gap="0.0.1"), risk_score=0, days=10),
        ]

    def test_order_and_tie_break(self):
        ranks = rank_priorities(self.items())
        order = sorted(ranks, key=ranks.get)
        # scored first (score, then name), then Investigate (repos, Open first, name)
        self.assertEqual(order, [3, 2, 1, 8, 5, 7, 6])
        self.assertNotIn(4, ranks)                          # up to date: no rank
        self.assertEqual(sorted(ranks.values()), list(range(1, 8)))   # no gaps

    def test_same_ranks_whatever_the_input_order(self):
        expected = rank_priorities(self.items())
        rng = random.Random(42)
        for _ in range(20):
            shuffled = self.items()
            rng.shuffle(shuffled)
            self.assertEqual(rank_priorities(shuffled), expected)


SEED = """
    INSERT INTO scan (scan_id, target_name) VALUES (1, 'repo-a'), (2, 'repo-b');
    INSERT INTO packages (package_id, package_name, ecosystem) VALUES
        (1, 'requests', 'pypi'), (2, 'oldlib', 'pypi'), (3, 'bigjump', 'pypi'),
        (4, 'unknownage', 'pypi'), (5, 'never-scanned', 'pypi'), (6, 'abandoned-vuln', 'pypi');
    INSERT INTO versions (version_id, scan_id, package_id, package_name, version_number,
        latest_version, status, days_outdated, age_tier)
    VALUES
        -- requests is in both scans (2 repos): scan 2 (the latest) wins.
        -- risk 40 -> 20, 800 days -> 20, minor -> 10, 2 repos -> 5: 55 Plan update
        (10, 1, 1, 'requests', '2.32.0', '2.32.0', 'up_to_date', 0, 'Fresh'),
        (20, 2, 1, 'requests', '2.20.0', '2.32.0', 'outdated', 800, 'Stale'),
        -- up to date: No action, no rank
        (11, 1, 2, 'oldlib', '1.0.0', '1.0.0', 'up_to_date', 0, 'Fresh'),
        -- risk 30 -> 15, 400 days -> 15, major -> 15: 45 Plan update
        (13, 1, 3, 'bigjump', '1.0.0', '3.0.0', 'outdated', 400, 'Stale'),
        -- no release dates: risk Unknown -> Investigate, ranked last
        (14, 1, 4, 'unknownage', '0.5', '0.9', 'outdated', 30, NULL),
        -- risk 100 -> 50, 1200 days -> 20, major -> 15: 85 Update now
        (21, 2, 6, 'abandoned-vuln', '0.1.0', '2.0.0', 'outdated', 1200, 'Abandoned'),
        -- no package_id: never prioritized
        (12, 1, NULL, 'loose', '0.1', NULL, 'unknown', 30, NULL);
    INSERT INTO scan_results (scan_id, version_id, vulnerability_id) VALUES
        (2, 21, 'CVE-1'), (2, 21, 'CVE-2'), (2, 21, 'CVE-3'), (2, 21, 'CVE-4'), (2, 21, 'CVE-5');
"""


def score_everything(db):
    db.update_package_risk_for_scan(2)
    db.update_package_risk_for_scan(1)
    return db.update_package_priorities()


class TestPackagePriorityDb(SqliteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript(SEED)
        self.sqlite.commit()

    def packages(self):
        return {r["package_name"]: r for r in self.rows("SELECT * FROM packages")}

    def test_queue(self):
        self.assertEqual(score_everything(self.db), 5)       # every package with a row
        p = self.packages()

        expected = {
            "abandoned-vuln": (1, 85, UPDATE_NOW),
            "requests": (2, 55, PLAN_UPDATE),
            "bigjump": (3, 45, PLAN_UPDATE),
            "unknownage": (4, None, INVESTIGATE),
            "oldlib": (None, None, NO_ACTION),
            "never-scanned": (None, None, None),
        }
        for name, values in expected.items():
            row = p[name]
            self.assertEqual((row["priority_rank"], row["priority_score"],
                              row["priority_category"]), values, name)

        self.assertEqual(p["requests"]["priority_version_id"], 20)   # latest scan's row
        self.assertIn("used in 2 repos (+5)", p["requests"]["priority_reason"])
        self.assertEqual(p["requests"]["priority_model_version"], PRIORITY_MODEL_VERSION)
        self.assertIsNotNone(p["requests"]["priority_computed_at"])
        self.assertIsNone(p["never-scanned"]["priority_computed_at"])

    def test_preview_writes_nothing(self):
        self.db.update_package_risk_for_scan(2)
        self.db.update_package_risk_for_scan(1)
        rows = self.db.package_priority_rows()
        self.assertEqual(len(rows), 5)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM packages "
                                   "WHERE priority_category IS NOT NULL")[0]["n"], 0)

    def test_rerun_gives_the_same_queue(self):
        score_everything(self.db)
        first = self.rows("SELECT package_id, priority_rank, priority_score, priority_category, "
                          "priority_reason FROM packages ORDER BY package_id")
        score_everything(self.db)
        again = self.rows("SELECT package_id, priority_rank, priority_score, priority_category, "
                          "priority_reason FROM packages ORDER BY package_id")
        self.assertEqual(first, again)

    def test_resolved_review_ranks_lower_but_stays(self):
        self.sqlite.execute("INSERT INTO package_reviews (package_id, status, reviewer) "
                            "VALUES (6, 'Resolved', 'alice')")
        self.sqlite.commit()
        score_everything(self.db)
        p = self.packages()["abandoned-vuln"]
        self.assertEqual((p["priority_rank"], p["priority_score"], p["priority_category"]),
                         (2, 45, PLAN_UPDATE))        # 85 - 40; ties bigjump, higher risk wins
        self.assertIn("Resolved by alice: ranked lower (-40)", p["priority_reason"])
        self.assertEqual(self.packages()["requests"]["priority_rank"], 1)

    def test_monitor_job_updates_priority(self):
        self.db.update_package_risk_for_scan(1)
        with mock.patch.object(DatabaseStorage, "refresh_version", return_value="refreshed"):
            results = self.db.recalculate_metrics_for_scan(2)
        self.assertEqual(results["priority_updated"], 5)
        self.assertEqual(self.packages()["abandoned-vuln"]["priority_rank"], 1)

    def test_priority_failure_does_not_stop_the_monitor_job(self):
        with mock.patch.object(DatabaseStorage, "refresh_version", return_value="refreshed"), \
                mock.patch.object(DatabaseStorage, "update_package_priorities",
                                  side_effect=RuntimeError("boom")), \
                contextlib.redirect_stdout(io.StringIO()):
            results = self.db.recalculate_metrics_for_scan(2)
        self.assertEqual(results["refreshed"], 2)
        self.assertEqual(results["risk_updated"], 2)
        self.assertEqual(results["priority_error"], 1)

    def test_top_priorities(self):
        score_everything(self.db)
        top = self.db.get_top_priorities(3)
        self.assertEqual([t["package_name"] for t in top],
                         ["abandoned-vuln", "requests", "bigjump"])
        self.assertEqual(top[0]["review_status"], "Open")

    def test_list_and_total_agree_under_priority_filters(self):
        score_everything(self.db)
        cases = [
            ({"priority_category": UPDATE_NOW}, 1),
            ({"priority_category": PLAN_UPDATE}, 3),           # both requests rows + bigjump
            ({"priority_category": MONITOR}, 0),
            ({"priority_category": INVESTIGATE}, 1),
            ({"priority_category": NO_ACTION}, 1),
            ({"priority_category": PRIORITY_NOT_SET}, 1),      # the unlinked row
            ({"priority_category": PLAN_UPDATE, "risk_level": "Medium"}, 3),
            ({"priority_category": PLAN_UPDATE, "review_status": "Resolved"}, 0),
            ({"priority_category": "Bogus"}, 7),               # ignored
        ]
        for filters, expected in cases:
            listed = self.db.get_packages_paginated(limit=50, offset=0, **filters)
            self.assertEqual(len(listed), expected, filters)
            self.assertEqual(self.db.get_total_packages(**filters), expected, filters)

    def test_sort_by_priority(self):
        score_everything(self.db)
        listed = self.db.get_packages_paginated(limit=50, offset=0, sort_by_priority=True)
        self.assertEqual([r["package_name"] for r in listed],
                         ["abandoned-vuln", "requests", "requests", "bigjump", "unknownage",
                          "oldlib", "loose"])

    def test_filters_listed_in_queue_order(self):
        self.assertEqual(PRIORITY_FILTERS,
                         [UPDATE_NOW, PLAN_UPDATE, MONITOR, INVESTIGATE, NO_ACTION,
                          PRIORITY_NOT_SET])


class TestPriorityPages(test_upload_pipeline.RouteTestCase):

    def setUp(self):
        super().setUp()
        self.sqlite.executescript(SEED)
        self.sqlite.commit()
        score_everything(self.db)

    def page(self, url):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.get_data(as_text=True)

    def test_packages_page_shows_priority_filter_and_sort(self):
        html = self.page("/packages")
        self.assertIn(">Priority</th>", html)
        self.assertIn("#1 · Update now", html)
        self.assertIn('class="risk-badge risk-critical"', html)     # risk column intact
        self.assertIn("not prioritized", html)

        html = self.page("/packages?priority=Update%20now")
        self.assertIn("<td>abandoned-vuln</td>", html)
        self.assertNotIn("<td>requests</td>", html)
        self.assertIn('name="next" value="/packages?priority=Update%20now"', html)

        html = self.page("/packages?sort=priority")
        self.assertLess(html.index("<td>abandoned-vuln</td>"), html.index("<td>bigjump</td>"))
        self.assertIn('<option value="priority" selected>', html)

        self.page("/packages?sort=tier")                 # the old sort still works

    def test_review_save_reranks(self):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.client.post("/packages/6/review", data={
                "status": "Resolved", "reviewer": "alice", "next": "/packages?sort=priority"})
        self.assertEqual(response.status_code, 302)
        row = self.rows("SELECT priority_rank, priority_reason FROM packages "
                        "WHERE package_id = 6")[0]
        self.assertEqual(row["priority_rank"], 2)
        self.assertIn("Resolved by alice: ranked lower (-40)", row["priority_reason"])

    def test_review_is_saved_even_if_reranking_fails(self):
        with mock.patch.object(DatabaseStorage, "update_package_priorities",
                               side_effect=RuntimeError("boom")), \
                contextlib.redirect_stdout(io.StringIO()):
            response = self.client.post("/packages/6/review",
                                        data={"status": "Resolved", "reviewer": "alice"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.rows("SELECT status FROM package_reviews WHERE package_id = 6"),
                         [{"status": "Resolved"}])

    def test_dashboard_shows_top_10(self):
        html = self.page("/dashboard")
        self.assertIn("Top 10 to Update", html)
        self.assertLess(html.index("abandoned-vuln"), html.index("bigjump"))
        self.assertIn('href="/packages?sort=priority"', html)

    def test_dashboard_without_priorities(self):
        self.sqlite.execute("UPDATE packages SET priority_rank = NULL")
        self.sqlite.commit()
        self.assertIn("No update priorities yet", self.page("/dashboard"))


if __name__ == "__main__":
    unittest.main()
