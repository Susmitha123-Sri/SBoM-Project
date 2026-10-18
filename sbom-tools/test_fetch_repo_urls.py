# sbom-tools/test_fetch_repo_urls.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# fetch_repo_urls.py: which names are looked up, preview makes no request,
# URL extraction from PyPI / npm responses, statuses, User-Agent / timeout /
# rate limit, stopping on 429 or repeated errors, resuming, and no database
# or labeled_pairs writes. Every network call is mocked: a real request
# fails the test.

import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests                                      # noqa: E402

import db_storage                                    # noqa: E402
import fake_mysql                                    # noqa: E402
import fetch_repo_urls                               # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402
from fetch_repo_urls import (                        # noqa: E402
    ERROR, NO_REPO_URL, NON_GITHUB, NOT_FOUND, OK, USER_AGENT, Fetcher, append_result,
    expand_npm_shorthand, load_results, npm_repo_url, pypi_repo_url, registry_url,
)


class FakeResponse:
    def __init__(self, status_code=200, data=None, headers=None, bad_json=False):
        self.status_code = status_code
        self._data = data
        self.headers = headers or {}
        self.bad_json = bad_json

    def json(self):
        if self.bad_json:
            raise ValueError("not json")
        return self._data


class FakeSession:
    """Answers from a {url: FakeResponse | Exception} map; records every call."""

    def __init__(self, answers=None, default=None):
        self.answers = answers or {}
        self.default = default or FakeResponse(404)
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "timeout": timeout})
        answer = self.answers.get(url, self.default)
        if isinstance(answer, Exception):
            raise answer
        return answer


class FakeClock:
    """time.monotonic / time.sleep stand-ins: sleeping moves the clock."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def no_network(*args, **kwargs):
    raise AssertionError("a real network request was attempted")


def pypi(urls=None, home_page=None):
    return FakeResponse(200, {"info": {"project_urls": urls, "home_page": home_page}})


def npm(repository):
    return FakeResponse(200, {"name": "x", "repository": repository})


# ============================================================
# URL extraction (no I/O)
# ============================================================
class TestExtraction(unittest.TestCase):

    def test_pypi_prefers_source_over_homepage(self):
        data = {"info": {"project_urls": {"Homepage": "https://requests.readthedocs.io",
                                          "Source": "https://github.com/psf/requests"},
                         "home_page": "https://example.org"}}
        self.assertEqual(pypi_repo_url(data), ("https://github.com/psf/requests", OK))

    def test_pypi_any_label_with_a_github_url(self):
        data = {"info": {"project_urls": {"Docs": "https://docs.x.org",
                                          "Tracker": "https://github.com/a/b/issues"}}}
        self.assertEqual(pypi_repo_url(data), ("https://github.com/a/b/issues", OK))

    def test_pypi_home_page_only_when_nothing_better(self):
        self.assertEqual(pypi_repo_url({"info": {"project_urls": None,
                                                 "home_page": "https://github.com/a/b"}}),
                         ("https://github.com/a/b", OK))

    def test_pypi_non_github_and_missing(self):
        self.assertEqual(pypi_repo_url({"info": {"project_urls": {"Source": "https://gitlab.com/a/b"}}}),
                         ("https://gitlab.com/a/b", NON_GITHUB))
        self.assertEqual(pypi_repo_url({"info": {"home_page": "UNKNOWN"}}), ("", NO_REPO_URL))
        self.assertEqual(pypi_repo_url({}), ("", NO_REPO_URL))

    def test_npm_repository_forms(self):
        self.assertEqual(npm_repo_url({"repository": {"type": "git",
                                                      "url": "git+https://github.com/a/b.git"}}),
                         ("git+https://github.com/a/b.git", OK))
        self.assertEqual(npm_repo_url({"repository": "https://github.com/a/b"}),
                         ("https://github.com/a/b", OK))
        self.assertEqual(npm_repo_url({"repository": "a/b"}), ("https://github.com/a/b", OK))
        self.assertEqual(npm_repo_url({"repository": "github:a/b"}), ("https://github.com/a/b", OK))
        self.assertEqual(npm_repo_url({"repository": "gitlab:a/b"}),
                         ("https://gitlab.com/a/b", NON_GITHUB))
        self.assertEqual(npm_repo_url({"repository": None}), ("", NO_REPO_URL))
        self.assertEqual(npm_repo_url({}), ("", NO_REPO_URL))

    def test_shorthand_leaves_urls_alone(self):
        self.assertEqual(expand_npm_shorthand("https://github.com/a/b"), "https://github.com/a/b")

    def test_registry_urls(self):
        self.assertEqual(registry_url("pypi", "PyYAML"), "https://pypi.org/pypi/PyYAML/json")
        self.assertEqual(registry_url("npm", "lodash"), "https://registry.npmjs.org/lodash/latest")


# ============================================================
# Rate limit, headers, timeout
# ============================================================
class TestFetcher(unittest.TestCase):

    def test_requests_start_at_least_one_second_apart(self):
        clock, session = FakeClock(), FakeSession()
        f = Fetcher(session, clock=clock.monotonic, sleep=clock.sleep)
        starts = []
        for _ in range(4):
            f.get("https://x")
            starts.append(clock.now)
            clock.now += 0.2                  # the request itself took 0.2 s
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        self.assertTrue(all(g >= 1.0 - 1e-9 for g in gaps), gaps)

    def test_no_wait_when_enough_time_passed(self):
        clock, session = FakeClock(), FakeSession()
        f = Fetcher(session, clock=clock.monotonic, sleep=clock.sleep)
        f.get("https://x")
        clock.now += 5
        f.get("https://x")
        self.assertEqual(clock.slept, [])

    def test_interval_never_below_one_second(self):
        self.assertEqual(Fetcher(FakeSession(), min_interval=0.1).min_interval, 1.0)
        self.assertEqual(Fetcher(FakeSession(), min_interval=2.5).min_interval, 2.5)

    def test_user_agent_and_timeout_on_every_request(self):
        session = FakeSession()
        f = Fetcher(session, user_agent="UA/1", timeout=7, clock=FakeClock().monotonic,
                    sleep=lambda s: None)
        f.get("https://a")
        f.get("https://b")
        for call in session.calls:
            self.assertEqual(call["headers"]["User-Agent"], "UA/1")
            self.assertEqual(call["timeout"], 7)


# ============================================================
# The CLI against the SQLite stand-in, with a fake session
# ============================================================
class FetchCliTestCase(SqliteTestCase):

    PACKAGES = [
        (1, "requests", "pypi"), (2, "semver", "none"), (3, "bitflags", "none"),
        (4, "lodash", "npm"), (5, "pyyaml", "pypi"), (6, "only-pypi", "pypi"),
        (7, "maven-only-both", "maven"), (8, "@babel/core", "npm"),
    ]
    CACHE = {
        "pypi:requests": {}, "npm:requests": {}, "pypi:semver": {}, "npm:semver": {},
        "pypi:bitflags": {}, "npm:bitflags": {}, "npm:lodash": {}, "pypi:PyYAML": {},
        "npm:pyyaml": {}, "pypi:only-pypi": {}, "npm:only-pypi-gone": None,
        "pypi:maven-only-both": {}, "npm:maven-only-both": {}, "npm:@babel/core": {},
    }
    EXPECTED = [("npm", "bitflags"), ("npm", "pyyaml"), ("npm", "requests"), ("npm", "semver"),
                ("pypi", "PyYAML"), ("pypi", "bitflags"), ("pypi", "requests"), ("pypi", "semver")]

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.cache = self.dir / "release_cache.json"
        self.cache.write_text(json.dumps(self.CACHE), encoding="utf-8")
        self.reference = self.dir / "reference_names.csv"      # absent unless a test writes it
        self.out = self.dir / "repo_urls.csv"

        self.sqlite.executemany(
            "INSERT INTO packages (package_id, package_name, ecosystem) VALUES (?, ?, ?)",
            self.PACKAGES)
        self.sqlite.executescript("""
            INSERT INTO labeled_pairs (name_a, name_b, label, labeled_by)
            VALUES ('a', 'b', 'match', 'tester');
            CREATE TRIGGER lp_no_insert BEFORE INSERT ON labeled_pairs
                BEGIN SELECT RAISE(ABORT, 'labeled_pairs must not be written'); END;
            CREATE TRIGGER lp_no_update BEFORE UPDATE ON labeled_pairs
                BEGIN SELECT RAISE(ABORT, 'labeled_pairs must not be written'); END;
            CREATE TRIGGER lp_no_delete BEFORE DELETE ON labeled_pairs
                BEGIN SELECT RAISE(ABORT, 'labeled_pairs must not be written'); END;
        """)
        self.sqlite.commit()

        self.executed = []
        real_execute = fake_mysql.SqliteCursor.execute

        def recording_execute(cursor, sql, params=()):
            self.executed.append(sql)
            return real_execute(cursor, sql, params)

        for patcher in (
            mock.patch.object(db_storage, "get_db_storage", lambda: self.db),
            mock.patch.object(fake_mysql.SqliteCursor, "execute", recording_execute),
            # any real HTTP request fails the test
            mock.patch.object(requests.Session, "request", no_network),
            mock.patch.object(requests, "get", no_network),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.clock = FakeClock()

    def run_cli(self, *args, session=None):
        argv = ["--reference-names", str(self.reference), "--release-cache", str(self.cache),
                "--out", str(self.out), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = fetch_repo_urls.main(argv, session=session, clock=self.clock.monotonic,
                                        sleep=self.clock.sleep)
        return code, out.getvalue()

    def results(self):
        with open(self.out, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    @staticmethod
    def answers(ok=True):
        """A response for every expected lookup."""
        base = {
            registry_url("pypi", "requests"): pypi({"Source": "https://github.com/psf/requests"}),
            registry_url("npm", "requests"): npm({"url": "git+https://github.com/request/request.git"}),
            registry_url("pypi", "semver"): pypi({"Source": "https://github.com/python-semver/python-semver"}),
            registry_url("npm", "semver"): npm("npm/node-semver"),
            registry_url("pypi", "bitflags"): pypi(None, "https://gitlab.com/x/bitflags"),
            registry_url("npm", "bitflags"): npm(None),
            registry_url("pypi", "PyYAML"): FakeResponse(404),
            registry_url("npm", "pyyaml"): requests.Timeout("slow"),
        }
        return base


class TestSelection(FetchCliTestCase):

    def test_names_on_both_registries_with_registry_spelling(self):
        from fetch_repo_urls import known_names, select_names
        known, source = known_names(self.reference, self.cache)
        self.assertEqual(source, str(self.cache))
        names = select_names(self.db.package_match_rows(), known)
        self.assertEqual(names, self.EXPECTED)

    def test_reference_names_preferred_over_release_cache(self):
        from fetch_repo_urls import known_names, select_names
        self.reference.write_text("name,ecosystem\nlodash,pypi\nlodash,npm\n", encoding="utf-8")
        known, source = known_names(self.reference, self.cache)
        self.assertEqual(source, str(self.reference))
        self.assertEqual(select_names(self.db.package_match_rows(), known),
                         [("npm", "lodash"), ("pypi", "lodash")])

    def test_no_known_names_exits_2(self):
        code, out = self.run_cli("--release-cache", str(self.dir / "nope.json"))
        self.assertEqual(code, 2)
        self.assertIn("no known names", out)


class TestPreview(FetchCliTestCase):

    def test_preview_lists_names_and_makes_no_request(self):
        session = FakeSession()
        code, out = self.run_cli(session=session)

        self.assertEqual(code, 0)
        self.assertEqual(session.calls, [])
        self.assertFalse(self.out.exists())
        self.assertIn("8 lookups", out)
        self.assertIn("to look up: 8", out)
        for eco, name in self.EXPECTED:
            self.assertRegex(out, rf"\n  {eco}\s+{re.escape(name)}\n")
        self.assertIn("No request was made", out)

    def test_show_limits_the_list(self):
        _, out = self.run_cli("--show", "3")
        self.assertIn("... and 5 more", out)


class TestApply(FetchCliTestCase):

    def test_statuses_and_saved_rows(self):
        session = FakeSession(self.answers())
        code, out = self.run_cli("--apply", session=session)

        self.assertEqual(code, 0)
        rows = {(r["ecosystem"], r["name"]): r for r in self.results()}
        self.assertEqual(len(rows), 8)
        self.assertEqual((rows[("pypi", "requests")]["status"],
                          rows[("pypi", "requests")]["repository_url"]),
                         (OK, "https://github.com/psf/requests"))
        self.assertEqual(rows[("npm", "semver")]["repository_url"], "https://github.com/npm/node-semver")
        self.assertEqual(rows[("pypi", "bitflags")]["status"], NON_GITHUB)
        self.assertEqual(rows[("npm", "bitflags")]["status"], NO_REPO_URL)
        self.assertEqual(rows[("pypi", "PyYAML")]["status"], NOT_FOUND)
        self.assertEqual(rows[("npm", "pyyaml")]["status"], ERROR)
        self.assertIn("Requests made: 8", out)

    def test_user_agent_contact_timeout_and_urls(self):
        session = FakeSession(self.answers())
        self.run_cli("--apply", "--contact", "me@example.org", "--timeout", "9", session=session)

        self.assertEqual(sorted(c["url"] for c in session.calls),
                         sorted(registry_url(e, n) for e, n in self.EXPECTED))
        for call in session.calls:
            self.assertEqual(call["headers"]["User-Agent"], f"{USER_AGENT} (+me@example.org)")
            self.assertEqual(call["timeout"], 9.0)

    def test_default_user_agent_has_no_contact(self):
        session = FakeSession(self.answers())
        self.run_cli("--apply", session=session)
        self.assertEqual({c["headers"]["User-Agent"] for c in session.calls}, {USER_AGENT})

    def test_one_request_per_second(self):
        session = FakeSession(self.answers())
        self.run_cli("--apply", session=session)
        self.assertEqual(len(self.clock.slept), 7)           # before each request but the first
        self.assertTrue(all(s >= 1.0 - 1e-9 for s in self.clock.slept))

    def test_429_stops_and_keeps_progress(self):
        answers = self.answers()
        answers[registry_url("npm", "pyyaml")] = FakeResponse(429, headers={"Retry-After": "120"})
        session = FakeSession(answers)
        code, out = self.run_cli("--apply", session=session)

        self.assertEqual(code, 1)
        self.assertIn("Retry-After: 120", out)
        self.assertEqual(len(session.calls), 2)              # npm bitflags, then npm pyyaml
        self.assertEqual([(r["ecosystem"], r["name"]) for r in self.results()],
                         [("npm", "bitflags")])

    def test_errors_in_a_row_stop_the_run(self):
        session = FakeSession(default=requests.ConnectionError("offline"))
        code, out = self.run_cli("--apply", session=session)

        self.assertEqual(code, 1)
        self.assertEqual(len(session.calls), 5)
        self.assertIn("5 errors in a row", out)
        self.assertEqual({r["status"] for r in self.results()}, {ERROR})

    def test_server_error_and_bad_json_are_errors(self):
        answers = self.answers()
        answers[registry_url("pypi", "requests")] = FakeResponse(503)
        answers[registry_url("pypi", "semver")] = FakeResponse(200, bad_json=True)
        self.run_cli("--apply", session=FakeSession(answers))
        rows = {(r["ecosystem"], r["name"]): r["status"] for r in self.results()}
        self.assertEqual((rows[("pypi", "requests")], rows[("pypi", "semver")]), (ERROR, ERROR))


class TestResume(FetchCliTestCase):

    def test_rerun_skips_done_and_retries_errors(self):
        self.run_cli("--apply", session=FakeSession(self.answers()))   # npm pyyaml: error

        answers = self.answers()
        answers[registry_url("npm", "pyyaml")] = npm("yaml/pyyaml")
        session = FakeSession(answers)
        _, out = self.run_cli("--apply", session=session)

        self.assertEqual([c["url"] for c in session.calls], [registry_url("npm", "pyyaml")])
        final = load_results(self.out)
        self.assertEqual(final[("npm", "pyyaml")]["status"], OK)    # last row wins
        self.assertEqual(len(final), 8)

    def test_preview_counts_what_is_left(self):
        self.run_cli("--apply", session=FakeSession(self.answers()))
        _, out = self.run_cli()
        self.assertIn("Already done", out)
        self.assertIn("to look up: 1 (of which 1 earlier errors)", out)

    def test_interrupted_run_keeps_written_rows(self):
        class Boom(Exception):
            pass

        answers = self.answers()
        answers[registry_url("npm", "requests")] = Boom("killed")   # not a RequestException
        with self.assertRaises(Boom):
            self.run_cli("--apply", session=FakeSession(answers))
        self.assertEqual([(r["ecosystem"], r["name"]) for r in self.results()],
                         [("npm", "bitflags"), ("npm", "pyyaml")])

    def test_last_row_wins_when_reading(self):
        append_result(self.out, {"name": "x", "ecosystem": "npm", "repository_url": "", "status": ERROR})
        append_result(self.out, {"name": "x", "ecosystem": "npm",
                                 "repository_url": "https://github.com/a/x", "status": OK})
        self.assertEqual(load_results(self.out)[("npm", "x")]["status"], OK)
        with open(self.out, encoding="utf-8") as f:
            self.assertEqual(f.readline().strip(), "name,ecosystem,repository_url,status")


class TestSafety(FetchCliTestCase):

    def test_no_database_writes_and_labeled_pairs_untouched(self):
        before = self.rows("SELECT * FROM packages")
        self.run_cli()
        self.run_cli("--apply", session=FakeSession(self.answers()))
        self.assertEqual(self.rows("SELECT * FROM packages"), before)
        self.assertEqual(self.rows("SELECT COUNT(*) AS n FROM labeled_pairs")[0]["n"], 1)
        writes = [sql for sql in self.executed
                  if re.search(r"\b(INSERT|UPDATE|DELETE|ALTER|CREATE|DROP)\b", sql, re.I)]
        self.assertEqual(writes, [])

    def test_module_has_no_sql_for_labeled_pairs(self):
        source = Path(fetch_repo_urls.__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"(INTO|UPDATE|FROM|JOIN)\s+`?labeled_pairs\b", source, re.I))


if __name__ == "__main__":
    unittest.main()
