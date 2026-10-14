# sbom-tools/test_reviews.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Management review check mark: validation, the one-transaction save
# (upsert + history row), the Packages filter, history page and dashboard
# counts. SQLite stand-in for MySQL (see fake_mysql.py).

import contextlib
import inspect
import io
import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, os.path.dirname(TESTS_DIR))   # project root, for ui_app

import test_upload_pipeline   # RouteTestCase (module import, so its tests aren't re-run here)
import ui_app
from db_storage import REVIEW_STATUSES, DatabaseStorage


class TestValidateReview(unittest.TestCase):

    def test_valid_review(self):
        cleaned, errors = ui_app.validate_review(
            {"status": "Resolved", "reviewer": " alice ", "note": "  "})
        self.assertEqual(errors, [])
        self.assertEqual(cleaned, {"status": "Resolved", "reviewer": "alice", "note": None})

    def test_unknown_status_is_rejected(self):
        _, errors = ui_app.validate_review({"status": "Hacked", "reviewer": "alice"})
        self.assertEqual(len(errors), 1)

    def test_reviewer_is_required_and_limited(self):
        _, errors = ui_app.validate_review({"status": "Open", "reviewer": "  "})
        self.assertEqual(len(errors), 1)
        _, errors = ui_app.validate_review({"status": "Open", "reviewer": "x" * 101})
        self.assertEqual(len(errors), 1)

    def test_next_url_stays_on_packages(self):
        self.assertEqual(ui_app.safe_packages_url("/packages?page=2&review=Open"),
                         "/packages?page=2&review=Open")
        for bad in ("http://evil.example", "//evil.example", "/settings", None, ""):
            self.assertEqual(ui_app.safe_packages_url(bad), "/packages")


class TestReviews(test_upload_pipeline.RouteTestCase):

    def setUp(self):
        super().setUp()
        # package 1 has a review row, package 2 has none (must still be reviewable)
        self.sqlite.executescript("""
            INSERT INTO scan (scan_id, target_name) VALUES (1, 'deps.csv');
            INSERT INTO packages VALUES (1, 'requests', 'pypi'), (2, 'flask', 'pypi');
            INSERT INTO versions (scan_id, package_id, package_name, version_number,
                latest_version, status, release_date, days_outdated, versions_behind,
                days_since_release, age_tier)
            VALUES (1, 1, 'requests', '2.31.0', '2.32.0', 'outdated',
                    '2026-10-14 10:00:00', 400, '0.1.0', 410, 'Stale'),
                   (1, 2, 'flask', '3.0.0', '3.0.0', 'up_to_date',
                    '2026-10-14 10:00:00', 0, '0.0.0', 300, 'Fresh');
            INSERT INTO package_reviews (package_id, status) VALUES (1, 'Open');
        """)
        self.sqlite.commit()

    def save(self, package_id, **form):
        with contextlib.redirect_stdout(io.StringIO()):
            return self.client.post(f"/packages/{package_id}/review", data=form)

    def page(self, url):
        with contextlib.redirect_stdout(io.StringIO()):
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        return response.get_data(as_text=True)

    def history(self, package_id):
        return self.rows("SELECT old_status, new_status, reviewer, note "
                         "FROM package_review_history WHERE package_id = ? "
                         "ORDER BY history_id", (package_id,))

    def test_save_updates_the_review_and_logs_it(self):
        response = self.save(1, status="Reviewed - Accepted", reviewer="alice",
                             note="ok", next="/packages?page=1&review=Open")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/packages?page=1&review=Open")

        review = self.rows("SELECT status, reviewer, note, reviewed_at "
                           "FROM package_reviews WHERE package_id = 1")[0]
        self.assertEqual((review["status"], review["reviewer"], review["note"]),
                         ("Reviewed - Accepted", "alice", "ok"))
        self.assertIsNotNone(review["reviewed_at"])
        self.assertEqual(self.history(1), [
            {"old_status": "Open", "new_status": "Reviewed - Accepted",
             "reviewer": "alice", "note": "ok"}])

    def test_first_save_inserts_the_review_row(self):
        self.save(2, status="Resolved", reviewer="bob")
        self.assertEqual(
            self.rows("SELECT status FROM package_reviews WHERE package_id = 2"),
            [{"status": "Resolved"}])
        self.assertEqual(self.history(2), [
            {"old_status": None, "new_status": "Resolved",
             "reviewer": "bob", "note": None}])

    def test_note_only_change_is_still_logged(self):
        self.save(1, status="Resolved", reviewer="alice", note="first")
        self.save(1, status="Resolved", reviewer="alice", note="second")
        history = self.history(1)
        self.assertEqual(len(history), 2)
        self.assertEqual((history[1]["old_status"], history[1]["new_status"],
                          history[1]["note"]), ("Resolved", "Resolved", "second"))
        self.assertEqual(len(self.rows("SELECT * FROM package_reviews WHERE package_id = 1")), 1)

    def test_invalid_input_writes_nothing(self):
        self.assertEqual(self.save(1, status="Hacked", reviewer="alice").status_code, 400)
        self.assertEqual(self.save(1, status="Resolved", reviewer="").status_code, 400)
        self.assertEqual(self.save(999, status="Resolved", reviewer="alice").status_code, 404)
        self.assertEqual(self.rows("SELECT * FROM package_review_history"), [])
        self.assertEqual(self.rows("SELECT status FROM package_reviews"), [{"status": "Open"}])

    def test_failed_history_insert_rolls_back_the_review(self):
        self.sqlite.execute("DROP TABLE package_review_history")
        self.assertEqual(self.save(1, status="Resolved", reviewer="alice").status_code, 500)
        self.assertEqual(self.rows("SELECT status FROM package_reviews"), [{"status": "Open"}])

    def test_open_redirect_is_refused(self):
        response = self.save(1, status="Resolved", reviewer="alice",
                             next="http://evil.example/")
        self.assertEqual(response.headers["Location"], "/packages")

    def test_reviewed_packages_stay_visible_and_filter_works(self):
        self.save(1, status="Resolved", reviewer="alice")

        html = self.page("/packages")
        self.assertIn("<td>requests</td>", html)
        self.assertIn("<td>flask</td>", html)

        html = self.page("/packages?review=Resolved")
        self.assertIn("<td>requests</td>", html)
        self.assertNotIn("<td>flask</td>", html)

        # no review row counts as Open
        html = self.page("/packages?review=Open")
        self.assertIn("<td>flask</td>", html)
        self.assertNotIn("<td>requests</td>", html)

        # an unknown filter value is ignored
        html = self.page("/packages?review=Bogus")
        self.assertIn("<td>requests</td>", html)
        self.assertIn("<td>flask</td>", html)

    def test_history_page_is_newest_first(self):
        self.save(1, status="Reviewed - Accepted", reviewer="alice", note="first note")
        self.save(1, status="Resolved", reviewer="bob", note="second note")
        html = self.page("/packages/1/history")
        self.assertLess(html.index("second note"), html.index("first note"))

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.client.get("/packages/999/history").status_code, 404)

    def test_dashboard_counts_every_status(self):
        self.save(1, status="Compensating Control", reviewer="alice")
        self.assertEqual(self.db.get_review_status_counts(),
                         {"Open": 1, "Reviewed - Accepted": 0,
                          "Compensating Control": 1, "Resolved": 0})
        html = self.page("/dashboard")
        for status in REVIEW_STATUSES:
            self.assertIn(status, html)

    def test_no_review_sql_deletes_rows(self):
        for name in ("save_review", "get_review", "get_review_history",
                     "get_review_status_counts"):
            source = inspect.getsource(getattr(DatabaseStorage, name))
            self.assertNotIn("DELETE", source.upper(), name)


if __name__ == "__main__":
    unittest.main()
