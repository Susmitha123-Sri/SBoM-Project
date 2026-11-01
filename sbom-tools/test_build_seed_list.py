# sbom-tools/test_build_seed_list.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# dataset/build_seed_list.py: search query and qualifiers, star-range slicing
# around the 1,000-result cap, the exclusion rule, reproducible sampling,
# language-matched dependency files, rate limits and retries, dry run vs
# --apply, refusing to overwrite, and the token never printed or written.
# Every network call goes to a fake GitHub: a real request fails the test.
# No database is used.

import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "dataset"))

import requests                                      # noqa: E402

import build_seed_list                               # noqa: E402
from build_seed_list import (                        # noqa: E402
    COLUMNS, GitHubClient, Stop, build_query, exclusion_reason, meets_criteria,
    pushed_cutoff, repo_row, search_language,
)

TOKEN = "ghp_TESTTOKEN_must_never_be_printed_123"
TODAY = date(2026, 11, 1)
CUTOFF = pushed_cutoff(TODAY)          # 2025-11-01


class FakeResponse:
    def __init__(self, status_code=200, data=None, headers=None, text=""):
        self.status_code = status_code
        self._data = data
        self.headers = headers or {}
        self.text = text

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class FakeClock:
    """time.time / time.sleep stand-ins: sleeping moves the clock."""

    def __init__(self, now=1_800_000_000.0):
        self.now = now
        self.slept = []

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def make_repo(repo_id, name, language="Python", stars=1000, forks=100,
              pushed="2026-10-01T12:00:00Z", fork=False, archived=False,
              topics=(), description="", files=None):
    owner = f"owner{repo_id}"
    if files is None:
        files = ["requirements.txt"] if language == "Python" else ["package.json"]
    return {
        "id": repo_id, "name": name, "full_name": f"{owner}/{name}",
        "html_url": f"https://github.com/{owner}/{name}", "language": language,
        "stargazers_count": stars, "forks_count": forks, "pushed_at": pushed,
        "fork": fork, "archived": archived, "topics": list(topics),
        "description": description, "_files": files,
    }


class FakeGitHub:
    """
    Serves /search/repositories from a repo list (filtered by the language and
    stars qualifiers, like GitHub, capped at 1,000) and /contents/ root
    listings from each repo's _files (an int is an HTTP status). Responses
    queued in self.queued[kind] are returned first.
    """

    def __init__(self, repos, reverse=False, overlap_pages=False):
        self.repos = repos
        self.files = {r["full_name"]: r["_files"] for r in repos}
        self.reverse = reverse
        self.overlap_pages = overlap_pages
        self.queued = {"search": [], "core": []}
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        kind = "search" if "/search/" in url else "core"
        self.calls.append({"kind": kind, "url": url, "params": dict(params or {}),
                           "headers": dict(headers or {}), "timeout": timeout})
        if self.queued[kind]:
            answer = self.queued[kind].pop(0)
            if isinstance(answer, Exception):
                raise answer
            return answer
        return self.search(params) if kind == "search" else self.contents(url)

    def search(self, params):
        q = params["q"]
        language = re.search(r"language:(\S+)", q).group(1)
        low, high = map(int, re.search(r"stars:(\d+)\.\.(\d+)", q).groups())
        hits = [r for r in self.repos
                if r["language"] == language and low <= r["stargazers_count"] <= high]
        hits.sort(key=lambda r: (-r["stargazers_count"], r["id"]))
        if self.reverse:
            hits.reverse()
        visible = hits[:1000]
        page, per = int(params["page"]), int(params["per_page"])
        items = visible[(page - 1) * per: page * per]
        if self.overlap_pages and page > 1:
            items = [visible[(page - 1) * per - 1]] + items     # a result shifted pages
        return FakeResponse(200, {"total_count": len(hits), "incomplete_results": False,
                                  "items": items})

    def contents(self, url):
        full_name = re.search(r"/repos/(.+)/contents/$", url).group(1)
        files = self.files.get(full_name, 404)
        if isinstance(files, int):
            return FakeResponse(files, {"message": "Not Found"})
        return FakeResponse(200, [{"name": f, "type": "file"} for f in files]
                            + [{"name": "src", "type": "dir"}])


def no_network(*args, **kwargs):
    raise AssertionError("a real network request was attempted")


def standard_repos(n_python=30, n_js=20, n_ts=20):
    repos, next_id = [], 1
    for language, n in (("Python", n_python), ("JavaScript", n_js), ("TypeScript", n_ts)):
        for i in range(n):
            repos.append(make_repo(next_id, f"{language.lower()}-tool-{i}", language,
                                   stars=500 + (next_id * 37) % 9500))
            next_id += 1
    return repos


class SeedTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.csv = self.dir / "seed_v2.csv"
        self.json = self.dir / "seed_v2_criteria.json"
        self.clock = FakeClock()
        for patcher in (
            mock.patch.object(build_seed_list, "load_dotenv", lambda *a, **k: None),
            mock.patch.dict(os.environ, {"GITHUB_TOKEN": TOKEN}),
            mock.patch.object(requests.Session, "request", no_network),
            mock.patch.object(requests, "get", no_network),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_cli(self, *args, session=None):
        argv = ["--out-csv", str(self.csv), "--out-json", str(self.json), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = build_seed_list.main(argv, session=session, clock=self.clock.time,
                                        sleep=self.clock.sleep, today=TODAY)
        return code, out.getvalue()

    def client(self, session):
        return GitHubClient(session, TOKEN, clock=self.clock.time, sleep=self.clock.sleep)

    def quiet_search(self, session, language="Python"):
        """search_language() with its progress lines captured."""
        with contextlib.redirect_stdout(io.StringIO()):
            return search_language(self.client(session), language, CUTOFF)

    def read_csv(self):
        with open(self.csv, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))


# ============================================================
# Query and filters (no I/O)
# ============================================================
class TestQuery(SeedTestCase):

    def test_query_has_every_qualifier(self):
        self.assertEqual(
            build_query("Python", 500, 599, CUTOFF),
            "language:Python stars:500..599 forks:>=50 pushed:>=2025-11-01 "
            "fork:false archived:false")

    def test_cutoff_comes_from_today(self):
        session = FakeGitHub(standard_repos(4, 2, 2))
        self.run_cli("--limit", "4", session=session)
        queries = [c["params"]["q"] for c in session.calls if c["kind"] == "search"]
        self.assertTrue(queries)
        self.assertTrue(all("pushed:>=2025-11-01" in q for q in queries))
        self.assertEqual({c["params"]["sort"] for c in session.calls if c["kind"] == "search"},
                         {"stars"})

    def test_results_are_rechecked(self):
        ok = make_repo(1, "fine")
        self.assertTrue(meets_criteria(ok, CUTOFF))
        for bad in (make_repo(2, "f", fork=True), make_repo(3, "a", archived=True),
                    make_repo(4, "few-forks", forks=49), make_repo(5, "old", pushed="2025-10-31T00:00:00Z"),
                    make_repo(6, "small", stars=499), make_repo(7, "big", stars=10001)):
            self.assertFalse(meets_criteria(bad, CUTOFF), bad["name"])
        self.assertTrue(meets_criteria(make_repo(8, "edge", pushed="2025-11-01T00:00:00Z",
                                                 forks=50, stars=10000), CUTOFF))


class TestExclusion(unittest.TestCase):

    def reason(self, name, topics=(), description=""):
        return exclusion_reason(repo_row(make_repo(1, name, topics=topics,
                                                   description=description)))

    def test_excluded(self):
        self.assertEqual(self.reason("awesome-python"), "name")
        self.assertEqual(self.reason("awesomeness"), "name")
        self.assertEqual(self.reason("python_tutorials"), "name")
        self.assertEqual(self.reason("ml.course"), "name")
        self.assertEqual(self.reason("100-days-of-code"), "name")
        self.assertEqual(self.reason("my-lib", topics=["Tutorial"]), "topic")
        self.assertEqual(self.reason("my-lib", topics=["awesome-list"]), "topic")
        self.assertEqual(self.reason("stuff", description="A Curated List of tools"), "description")

    def test_kept(self):
        for name in ("scikit-learn", "learnable", "bookshelf-api", "examplesite",
                     "coursera-dl-fork", "days-100", "roadmapper"):
            self.assertIsNone(self.reason(name), name)
        self.assertIsNone(self.reason("lib", topics=["python", "cli"],
                                      description="A small list of helpers"))


# ============================================================
# Search slicing
# ============================================================
class TestSlicing(SeedTestCase):

    def test_slice_over_1000_is_split(self):
        repos = [make_repo(i, f"r{i}", stars=500 + i % 100) for i in range(1, 1501)]
        session = FakeGitHub(repos)
        pool, records = self.quiet_search(session)

        self.assertEqual(len(pool), 1500)
        first = [r["stars"] for r in records if r["stars"][1] <= 599]
        self.assertEqual(first, [[500, 549], [550, 599]])
        self.assertFalse(any(r["truncated"] for r in records))
        self.assertTrue(all(r["total_count"] <= 1000 for r in records))

    def test_one_star_slice_over_1000_is_truncated(self):
        repos = [make_repo(i, f"r{i}", stars=777) for i in range(1, 1201)]
        session = FakeGitHub(repos)
        pool, records = self.quiet_search(session)

        truncated = [r for r in records if r["truncated"]]
        self.assertEqual([r["stars"] for r in truncated], [[777, 777]])
        self.assertEqual(truncated[0]["total_count"], 1200)
        self.assertEqual(len(pool), 1000)
        pages = [c["params"]["page"] for c in session.calls
                 if "stars:777..777" in c["params"]["q"]]
        self.assertEqual(max(pages), 10)

    def test_duplicates_across_pages_are_kept_once(self):
        repos = [make_repo(i, f"r{i}", stars=600 + i % 150) for i in range(1, 251)]
        session = FakeGitHub(repos, overlap_pages=True)
        pool, records = self.quiet_search(session)
        self.assertEqual(len(pool), 250)
        self.assertGreater(sum(r["fetched"] for r in records), 250)

    def test_results_failing_the_recheck_are_dropped(self):
        repos = [make_repo(1, "ok"), make_repo(2, "forked", fork=True),
                 make_repo(3, "stale", pushed="2024-01-01T00:00:00Z")]
        pool, records = self.quiet_search(FakeGitHub(repos))
        self.assertEqual([r["name"] for r in pool.values()], ["owner1/ok"])
        self.assertEqual(sum(r["dropped_by_recheck"] for r in records), 2)

    def test_incomplete_results_retried_once_then_recorded(self):
        session = FakeGitHub([make_repo(1, "ok")])
        incomplete = FakeResponse(200, {"total_count": 1, "incomplete_results": True,
                                        "items": [make_repo(1, "ok")]})
        session.queued["search"] = [incomplete, incomplete]
        pool, records = self.quiet_search(session)
        self.assertTrue(records[0]["incomplete_results"])
        self.assertFalse(records[1]["incomplete_results"])
        self.assertEqual(len(pool), 1)

    def test_progress_line_per_slice(self):
        _, out = self.run_cli("--limit", "4", session=FakeGitHub(standard_repos(4, 2, 2)))
        self.assertRegex(out, r"\[search\] Python stars 500\.\.599: \d+ found, pool \d+")
        self.assertRegex(out, r"\[search\] TypeScript stars \d+\.\.\d+: ")


# ============================================================
# Sampling and dependency files
# ============================================================
class TestSampling(SeedTestCase):

    def selected_names(self, *args, reverse=False):
        if self.csv.exists():
            self.csv.unlink()
            self.json.unlink()
        code, out = self.run_cli("--apply", *args,
                                 session=FakeGitHub(standard_repos(60, 40, 40), reverse=reverse))
        self.assertEqual(code, 0, out)
        return [r["name"] for r in self.read_csv()]

    def test_same_seed_same_list_whatever_the_api_order(self):
        a = self.selected_names("--limit", "20")
        b = self.selected_names("--limit", "20", reverse=True)
        self.assertEqual(a, b)

    def test_other_seed_other_list(self):
        a = self.selected_names("--limit", "20")
        b = self.selected_names("--limit", "20", "--seed", "7")
        self.assertNotEqual(a, b)

    def test_limit_20_gives_10_per_group(self):
        self.selected_names("--limit", "20")
        rows = self.read_csv()
        self.assertEqual(sum(r["language"] == "Python" for r in rows), 10)
        self.assertEqual(sum(r["language"] in ("JavaScript", "TypeScript") for r in rows), 10)

    def test_excluded_repos_never_selected(self):
        repos = standard_repos(10, 5, 5)
        repos += [make_repo(900 + i, f"awesome-thing-{i}", stars=800) for i in range(30)]
        code, _ = self.run_cli("--apply", "--limit", "20", session=FakeGitHub(repos))
        self.assertEqual(code, 0)
        self.assertFalse(any("awesome" in r["name"] for r in self.read_csv()))
        record = json.loads(self.json.read_text(encoding="utf-8"))
        self.assertEqual(record["counts"]["excluded_in_pool"]["python"]["name"], 30)

    def test_dependency_file_must_match_language(self):
        repos = [
            make_repo(1, "py-ok", files=["requirements.txt", "pyproject.toml"]),
            make_repo(2, "py-only-package-json", files=["package.json"]),
            make_repo(3, "py-empty", files=404),
            make_repo(4, "js-ok", "JavaScript", files=["package.json"]),
            make_repo(5, "js-only-requirements", "TypeScript", files=["requirements.txt"]),
            make_repo(6, "py-only-pyproject", files=["pyproject.toml", "uv.lock"]),
        ]
        code, out = self.run_cli("--apply", "--limit", "20", session=FakeGitHub(repos))
        self.assertEqual(code, 0, out)
        rows = {r["name"].split("/")[1]: r for r in self.read_csv()}
        self.assertEqual(sorted(rows), ["js-ok", "py-ok"])
        self.assertEqual(rows["py-ok"]["dependency_files"], "requirements.txt")
        walk = json.loads(self.json.read_text(encoding="utf-8"))["counts"]["walk_by_group"]
        self.assertEqual(walk["python"]["no_dependency_file"], 2)   # package.json, pyproject.toml
        self.assertEqual(walk["python"]["contents_unavailable"], 1)
        self.assertEqual(walk["js_ts"]["no_dependency_file"], 1)
        self.assertIn("[warn] Python: only 1 of 10 found", out)

    def test_pyproject_rule_change_is_recorded(self):
        code, out = self.run_cli("--apply", "--limit", "20", session=FakeGitHub(standard_repos()))
        self.assertEqual(code, 0, out)
        record = json.loads(self.json.read_text(encoding="utf-8"))
        self.assertEqual(record["criteria"]["dependency_files"],
                         {"python": ["requirements.txt"], "js_ts": ["package.json"]})
        notes = [n for n in record["notes"] if "pyproject.toml" in n]
        self.assertEqual(len(notes), 1)
        self.assertIn("dataset/pilot_syft_results.csv", notes[0])
        self.assertIn("Syft 1.17", notes[0])

    def test_check_progress_every_25(self):
        _, out = self.run_cli("--limit", "100", session=FakeGitHub(standard_repos(60, 40, 40)))
        self.assertIn("[check] Python 25/50 accepted, 25 checked", out)
        self.assertIn("[check] Python 50/50 accepted, 50 checked (done)", out)
        self.assertIn("[check] JavaScript/TypeScript 50/50 accepted, 50 checked (done)", out)


# ============================================================
# Rate limits and retries
# ============================================================
class TestClient(SeedTestCase):

    def test_search_requests_at_least_2_1_seconds_apart(self):
        client = self.client(FakeGitHub([]))
        starts = []
        for _ in range(4):
            client.get("search", build_seed_list.SEARCH_URL, {"q": "language:Python stars:1..2",
                                                               "page": 1, "per_page": 100})
            starts.append(self.clock.now)
            self.clock.now += 0.3
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        self.assertTrue(all(g >= 2.1 - 1e-6 for g in gaps), gaps)

    def test_core_pacing_is_separate_and_shorter(self):
        session = FakeGitHub([make_repo(1, "x")])
        client = self.client(session)
        client.get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        client.get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        self.assertEqual(len(self.clock.slept), 1)
        self.assertAlmostEqual(self.clock.slept[0], 0.8)

    def test_remaining_zero_waits_for_reset_before_next_request(self):
        session = FakeGitHub([make_repo(1, "x")])
        reset = self.clock.now + 40
        session.queued["core"] = [FakeResponse(200, [], {"X-RateLimit-Remaining": "0",
                                                         "X-RateLimit-Reset": str(int(reset))})]
        client = self.client(session)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            client.get("core", build_seed_list.API + "/repos/owner1/x/contents/")
            client.get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        self.assertGreaterEqual(self.clock.now, reset + 1 - 1e-6)
        self.assertIn("[wait] core limit, sleeping 41 s", out.getvalue())

    def test_429_with_retry_after_is_retried(self):
        session = FakeGitHub([make_repo(1, "x")])
        session.queued["core"] = [FakeResponse(429, headers={"Retry-After": "30"})]
        client = self.client(session)
        with contextlib.redirect_stdout(io.StringIO()):
            r = client.get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(30.0, self.clock.slept)
        self.assertEqual(client.requests["core"], 2)

    def test_secondary_limit_403_is_retried(self):
        session = FakeGitHub([make_repo(1, "x")])
        session.queued["core"] = [FakeResponse(403, text="You have exceeded a secondary rate limit")]
        with contextlib.redirect_stdout(io.StringIO()):
            r = self.client(session).get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(60, self.clock.slept)

    def test_rate_limit_three_times_stops(self):
        session = FakeGitHub([])
        session.queued["core"] = [FakeResponse(429, headers={"Retry-After": "1"})] * 3
        with self.assertRaises(Stop):
            self.client(session).get("core", build_seed_list.API + "/repos/a/b/contents/")

    def test_5xx_backs_off_then_succeeds(self):
        session = FakeGitHub([make_repo(1, "x")])
        session.queued["core"] = [FakeResponse(502), FakeResponse(503)]
        with contextlib.redirect_stdout(io.StringIO()):
            r = self.client(session).get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([s for s in self.clock.slept if s >= 2], [2, 4])

    def test_network_error_is_retried(self):
        session = FakeGitHub([make_repo(1, "x")])
        session.queued["core"] = [requests.ConnectionError("offline")]
        with contextlib.redirect_stdout(io.StringIO()):
            r = self.client(session).get("core", build_seed_list.API + "/repos/owner1/x/contents/")
        self.assertEqual(r.status_code, 200)

    def test_plain_404_is_returned_not_retried(self):
        session = FakeGitHub([])
        client = self.client(session)
        r = client.get("core", build_seed_list.API + "/repos/a/b/contents/")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(client.requests["core"], 1)

    def test_reset_too_far_away_stops_and_writes_nothing(self):
        session = FakeGitHub(standard_repos(4, 2, 2))
        session.queued["search"] = [FakeResponse(403, headers={
            "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(self.clock.now + 3600))})]
        code, out = self.run_cli("--apply", "--limit", "4", session=session)
        self.assertEqual(code, 1)
        self.assertIn("Nothing was written", out)
        self.assertFalse(self.csv.exists())
        self.assertFalse(self.json.exists())

    def test_bad_token_stops(self):
        session = FakeGitHub([])
        session.queued["search"] = [FakeResponse(401)]
        code, out = self.run_cli("--limit", "4", session=session)
        self.assertEqual(code, 1)
        self.assertIn("rejected the token", out)
        self.assertEqual(len(session.calls), 1)


# ============================================================
# CLI: dry run, apply, overwrite, token
# ============================================================
class TestCli(SeedTestCase):

    def test_dry_run_writes_nothing_and_lists_first_20(self):
        code, out = self.run_cli("--limit", "40", session=FakeGitHub(standard_repos()))
        self.assertEqual(code, 0)
        self.assertFalse(self.csv.exists())
        self.assertFalse(self.json.exists())
        self.assertIn("First 20 repos:", out)
        self.assertEqual(len(re.findall(r"^  owner\d+/", out, re.M)), 20)
        self.assertIn("Pool by language:", out)
        self.assertIn("Dry run: nothing was written", out)
        self.assertFalse(list(self.dir.iterdir()))

    def test_apply_writes_csv_and_criteria(self):
        code, out = self.run_cli("--apply", "--limit", "20", session=FakeGitHub(standard_repos()))
        self.assertEqual(code, 0, out)
        with open(self.csv, encoding="utf-8") as f:
            self.assertEqual(f.readline().strip(), ",".join(COLUMNS))
        rows = self.read_csv()
        self.assertEqual(len(rows), 20)
        self.assertRegex(rows[0]["last_push"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertTrue(rows[0]["url"].startswith("https://github.com/"))

        record = json.loads(self.json.read_text(encoding="utf-8"))
        for key in ("query_date_utc", "seed", "criteria", "query_template", "slices",
                    "counts", "test_run", "limit"):
            self.assertIn(key, record)
        self.assertEqual(record["query_date_utc"], "2026-11-01")
        self.assertEqual(record["criteria"]["pushed_on_or_after"], "2025-11-01")
        self.assertTrue(record["test_run"])
        self.assertEqual(record["counts"]["selected_total"], 20)
        self.assertEqual(record["counts"]["selected_by_group"], {"python": 10, "js_ts": 10})
        self.assertTrue(all("query" in s and "total_count" in s for s in record["slices"]))
        self.assertEqual([p.name for p in sorted(self.dir.iterdir())],
                         ["seed_v2.csv", "seed_v2_criteria.json"])     # no .tmp left

    def test_refuses_existing_file_without_overwrite(self):
        self.csv.write_text("keep me", encoding="utf-8")
        session = FakeGitHub(standard_repos())
        code, out = self.run_cli("--apply", "--limit", "20", session=session)
        self.assertEqual(code, 2)
        self.assertIn("--overwrite", out)
        self.assertEqual(session.calls, [])
        self.assertEqual(self.csv.read_text(encoding="utf-8"), "keep me")

    def test_overwrite_replaces(self):
        self.csv.write_text("old", encoding="utf-8")
        code, _ = self.run_cli("--apply", "--overwrite", "--limit", "20",
                               session=FakeGitHub(standard_repos()))
        self.assertEqual(code, 0)
        self.assertEqual(len(self.read_csv()), 20)

    def test_missing_token_exits_2_without_requests(self):
        session = FakeGitHub(standard_repos())
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": ""}):
            code, out = self.run_cli("--limit", "20", session=session)
        self.assertEqual(code, 2)
        self.assertIn("GITHUB_TOKEN is not set", out)
        self.assertEqual(session.calls, [])

    def test_limit_too_small(self):
        code, _ = self.run_cli("--limit", "1", session=FakeGitHub([]))
        self.assertEqual(code, 2)

    def test_token_sent_but_never_printed_or_written(self):
        session = FakeGitHub(standard_repos())
        session.queued["core"] = [FakeResponse(429, headers={"Retry-After": "10"}),
                                  requests.ConnectionError("offline")]
        code, out = self.run_cli("--apply", "--limit", "20", session=session)
        self.assertEqual(code, 0, out)
        self.assertIn("[wait]", out)
        self.assertNotIn(TOKEN, out)
        self.assertNotIn(TOKEN, self.csv.read_text(encoding="utf-8"))
        self.assertNotIn(TOKEN, self.json.read_text(encoding="utf-8"))
        self.assertNotIn(TOKEN, repr(self.client(session)))
        self.assertTrue(all(c["headers"]["Authorization"] == f"Bearer {TOKEN}"
                            for c in session.calls))
        self.assertTrue(all(TOKEN not in c["url"] and TOKEN not in json.dumps(c["params"])
                            for c in session.calls))


class TestSafety(unittest.TestCase):

    def test_no_database_code(self):
        source = Path(build_seed_list.__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*(import|from)\s+(db_storage|pymysql|mysql)", source, re.M))

    def test_default_outputs_are_the_new_files(self):
        self.assertEqual(build_seed_list.DEFAULT_CSV, PROJECT_ROOT / "dataset" / "seed_v2.csv")
        self.assertEqual(build_seed_list.DEFAULT_JSON,
                         PROJECT_ROOT / "dataset" / "seed_v2_criteria.json")


if __name__ == "__main__":
    unittest.main()
