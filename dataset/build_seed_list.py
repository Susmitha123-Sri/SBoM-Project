# dataset/build_seed_list.py
#
# Build seed list v2: about 1,000 medium-sized open-source GitHub projects,
# half Python and half JavaScript/TypeScript (one pooled group), for the SBOM
# scans. Reads the GitHub API only; no database, no existing file is changed.
#
#   criteria   stars 500..10,000, forks >= 50, pushed in the last 365 days,
#              not a fork, not archived, not an awesome-list / tutorial /
#              course (see exclusion_reason), and a dependency file in the
#              root folder that matches the language:
#                Python                 requirements.txt or pyproject.toml
#                JavaScript/TypeScript  package.json
#   sampling   each group's pool is sorted by repo id, shuffled with a fixed
#              seed, and walked in that order until the group has its target
#              (500, or --limit // 2): same pool + same seed = same list.
#   1,000 cap  GitHub search returns at most 1,000 results per query, so each
#              language is searched in star-range slices; a slice with more
#              than 1,000 results is split in half until it fits.
#
# Needs GITHUB_TOKEN in .env (project root) or the environment. The token is
# only ever sent in the Authorization header; it is never printed or written.
#
# Dry run (default): queries GitHub, prints counts and the first 20 repos,
# writes nothing.
#     python dataset/build_seed_list.py [--limit 20]
# Write dataset/seed_v2.csv and dataset/seed_v2_criteria.json:
#     python dataset/build_seed_list.py --apply [--overwrite]

import argparse
import csv
import io
import json
import math
import os
import random
import re
import sys
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
DEFAULT_CSV = PROJECT_ROOT / "dataset" / "seed_v2.csv"
DEFAULT_JSON = PROJECT_ROOT / "dataset" / "seed_v2_criteria.json"

API = "https://api.github.com"
SEARCH_URL = API + "/search/repositories"
USER_AGENT = "sbom-project-build-seed-list/1.0"
TIMEOUT = 30.0

# ============================
# CRITERIA
# ============================
# group -> GitHub language names searched (one pooled sample per group)
GROUPS = {"python": ("Python",), "js_ts": ("JavaScript", "TypeScript")}
GROUP_LABELS = {"python": "Python", "js_ts": "JavaScript/TypeScript"}
# Dependency file names (root folder) that count for each group
DEP_FILES = {"python": ("pyproject.toml", "requirements.txt"), "js_ts": ("package.json",)}

STARS_MIN, STARS_MAX = 500, 10000
FORKS_MIN = 50
PUSHED_WITHIN_DAYS = 365
TARGET_PER_GROUP = 500
DEFAULT_SEED = 42
LIMIT_POOL_FACTOR = 10        # with --limit, stop searching at 10 x target per group

SEARCH_CAP = 1000             # GitHub search: at most 1,000 results per query
PER_PAGE = 100
START_SLICES = [(500, 599), (600, 799), (800, 1199), (1200, 1999), (2000, 3999), (4000, 10000)]

# Exclusion rule: whole name tokens (split on - _ .), topics, description
EXCLUDE_NAME_TOKENS = frozenset({
    "awesome", "tutorial", "tutorials", "course", "courses", "cheatsheet",
    "cheatsheets", "roadmap", "interview", "book", "books", "examples", "exercises",
})
EXCLUDE_NAME_PHRASES = ("100-days",)
EXCLUDE_NAME_PREFIX = "awesome"
EXCLUDE_TOPICS = frozenset({
    "awesome", "awesome-list", "tutorial", "tutorials", "course", "courses", "education",
    "interview-questions", "cheatsheet", "roadmap", "books", "learning-resources",
})
EXCLUDE_DESCRIPTION = ("curated list",)

COLUMNS = ["name", "url", "language", "stars", "forks", "last_push", "dependency_files"]

# ============================
# RATE LIMITS
# ============================
MIN_INTERVAL = {"search": 2.1, "core": 0.8}   # search 30/min, core 5,000/h
MAX_TRIES = 3
BACKOFF = (2, 4, 8)                            # seconds, 5xx and network errors
SECONDARY_WAIT = 60                            # no Retry-After given
MAX_WAIT = 15 * 60                             # longer than this: stop instead
LOG_WAIT_FROM = 5                              # only print waits this long


def log(message):
    print(message, flush=True)


# ============================
# QUERY AND FILTERS (no I/O)
# ============================
def pushed_cutoff(today):
    return today - timedelta(days=PUSHED_WITHIN_DAYS)


def build_query(language, low, high, cutoff):
    return (f"language:{language} stars:{low}..{high} forks:>={FORKS_MIN} "
            f"pushed:>={cutoff.isoformat()} fork:false archived:false")


def meets_criteria(item, cutoff):
    """Re-check the search qualifiers on one result (search is not always exact)."""
    return (not item.get("fork") and not item.get("archived")
            and STARS_MIN <= (item.get("stargazers_count") or 0) <= STARS_MAX
            and (item.get("forks_count") or 0) >= FORKS_MIN
            and (item.get("pushed_at") or "")[:10] >= cutoff.isoformat())


def name_tokens(name):
    return [t for t in re.split(r"[-_.]+", str(name or "").lower()) if t]


def exclusion_reason(row):
    """"name", "topic", "description" or None (kept)."""
    name = str(row.get("repo_name") or "").lower()
    dashed = "-" + "-".join(name_tokens(name)) + "-"
    if (name.startswith(EXCLUDE_NAME_PREFIX)
            or any(t in EXCLUDE_NAME_TOKENS for t in name_tokens(name))
            or any(f"-{p}-" in dashed for p in EXCLUDE_NAME_PHRASES)):
        return "name"
    if any(str(t).lower() in EXCLUDE_TOPICS for t in row.get("topics") or []):
        return "topic"
    description = str(row.get("description") or "").lower()
    if any(p in description for p in EXCLUDE_DESCRIPTION):
        return "description"
    return None


def repo_row(item):
    """The fields kept from one search result."""
    return {
        "id": item["id"],
        "name": item["full_name"],
        "repo_name": item.get("name") or item["full_name"].split("/")[-1],
        "url": item["html_url"],
        "language": item.get("language") or "",
        "stars": item.get("stargazers_count") or 0,
        "forks": item.get("forks_count") or 0,
        "last_push": (item.get("pushed_at") or "")[:10],
        "topics": list(item.get("topics") or []),
        "description": item.get("description") or "",
    }


def shuffled(pool, seed, group):
    """Pool sorted by repo id, then shuffled with a seed fixed per group."""
    ordered = sorted(pool.values(), key=lambda r: r["id"])
    random.Random(f"{seed}-{group}").shuffle(ordered)
    return ordered


# ============================
# GITHUB CLIENT
# ============================
class Stop(Exception):
    """The run cannot continue (nothing is written)."""


class GitHubClient:
    """
    GETs to the GitHub API with pacing per API (search / core), waiting on
    rate limits and retrying 5xx / network errors. Every request is a GET,
    so a retry never changes anything.
    """

    def __init__(self, session, token, timeout=TIMEOUT, clock=time.time, sleep=time.sleep):
        self.session = session
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": USER_AGENT,
        }
        self.timeout = timeout
        self.clock = clock
        self.sleep = sleep
        self._last_start = {}
        self._blocked_until = {}
        self.requests = Counter()

    def __repr__(self):
        return f"GitHubClient(requests={dict(self.requests)})"   # never the token

    def _wait(self, seconds, why):
        if seconds <= 0:
            return
        if seconds > MAX_WAIT:
            raise Stop(f"{why}: GitHub asks to wait {seconds / 60:.0f} min (more than "
                       f"{MAX_WAIT // 60} min); rerun later")
        if seconds >= LOG_WAIT_FROM:
            log(f"[wait] {why}, sleeping {math.ceil(seconds)} s")
        self.sleep(seconds)

    def _pace(self, kind):
        now = self.clock()
        blocked = self._blocked_until.pop(kind, None)
        if blocked is not None:
            self._wait(blocked - now, f"{kind} limit")
            now = self.clock()
        last = self._last_start.get(kind)
        if last is not None:
            self._wait(MIN_INTERVAL[kind] - (now - last), f"{kind} pacing")
        self._last_start[kind] = self.clock()
        self.requests[kind] += 1

    def _reset_wait(self, response):
        """Seconds until X-RateLimit-Reset (+1), or None if not given."""
        try:
            return float(response.headers.get("X-RateLimit-Reset")) - self.clock() + 1
        except (TypeError, ValueError):
            return None

    def _limit_wait(self, response):
        """Seconds to wait if this response is a rate limit, else None."""
        if response.status_code not in (403, 429):
            return None
        headers = response.headers or {}
        retry_after = headers.get("Retry-After")
        if retry_after is not None:
            try:
                return max(float(retry_after), 1.0)
            except ValueError:
                return SECONDARY_WAIT
        if headers.get("X-RateLimit-Remaining") == "0":
            wait = self._reset_wait(response)
            return SECONDARY_WAIT if wait is None else max(wait, 1.0)
        if response.status_code == 429 or "rate limit" in str(getattr(response, "text", "")).lower():
            return SECONDARY_WAIT
        return None

    def get(self, kind, url, params=None):
        """
        The response (any status the caller has to judge, e.g. 200 or 404).
        Raises Stop on a bad token, or when retries / waits run out.
        """
        import requests

        for attempt in range(MAX_TRIES):
            last_try = attempt + 1 == MAX_TRIES
            self._pace(kind)
            try:
                response = self.session.get(url, params=params, headers=self._headers,
                                            timeout=self.timeout)
            except requests.RequestException as e:
                if last_try:
                    raise Stop(f"network error ({type(e).__name__}) on {url}")
                self._wait(BACKOFF[attempt], f"network error ({type(e).__name__})")
                continue

            status = response.status_code
            if status == 401:
                raise Stop("GitHub rejected the token (401); check GITHUB_TOKEN in .env")

            wait = self._limit_wait(response)
            if wait is not None:
                if last_try:
                    raise Stop(f"{kind} rate limit still hit after {MAX_TRIES} tries")
                self._wait(wait, f"{kind} limit")
                continue

            if status >= 500:
                if last_try:
                    raise Stop(f"GitHub error {status} on {url} after {MAX_TRIES} tries")
                self._wait(BACKOFF[attempt], f"GitHub error {status}")
                continue

            # Out of quota after this one: wait before the next request
            if (response.headers or {}).get("X-RateLimit-Remaining") == "0":
                wait = self._reset_wait(response)
                if wait is not None:
                    self._blocked_until[kind] = self.clock() + wait
            return response

        raise Stop(f"no answer from {url}")   # not reached


# ============================
# SEARCH (star-range slices)
# ============================
def search_page(client, query, page):
    """(data, incomplete) for one search page; incomplete pages are retried once."""
    params = {"q": query, "sort": "stars", "order": "desc", "per_page": PER_PAGE, "page": page}
    for attempt in range(2):
        response = client.get("search", SEARCH_URL, params)
        if response.status_code != 200:
            raise Stop(f"search failed with HTTP {response.status_code} for: {query}")
        try:
            data = response.json()
        except ValueError:
            raise Stop(f"search returned invalid JSON for: {query}")
        if not data.get("incomplete_results") or attempt == 1:
            return data, bool(data.get("incomplete_results"))
    return data, True   # not reached


def search_language(client, language, cutoff, pool_cap=None):
    """
    ({repo id: row}, slice records) for one language. Slices over 1,000
    results are split in half; a one-star slice still over 1,000 is fetched
    up to the cap and marked truncated. With pool_cap, stops once the pool
    has that many repos (test runs).
    """
    pool = {}
    records = []
    todo = list(START_SLICES)

    while todo:
        low, high = todo.pop(0)
        query = build_query(language, low, high, cutoff)
        data, incomplete = search_page(client, query, 1)
        total = int(data.get("total_count") or 0)

        if total > SEARCH_CAP and high > low:
            mid = (low + high) // 2
            todo[0:0] = [(low, mid), (mid + 1, high)]
            continue

        record = {"language": language, "stars": [low, high], "query": query,
                  "total_count": total, "truncated": total > SEARCH_CAP,
                  "incomplete_results": incomplete, "fetched": 0,
                  "dropped_by_recheck": 0}
        pages = math.ceil(min(total, SEARCH_CAP) / PER_PAGE)
        page = 1
        while True:
            for item in data.get("items") or []:
                record["fetched"] += 1
                if not meets_criteria(item, cutoff):
                    record["dropped_by_recheck"] += 1
                    continue
                pool.setdefault(item["id"], repo_row(item))   # de-duplicate by id
            page += 1
            if page > pages or not data.get("items") or (pool_cap and len(pool) >= pool_cap):
                break
            data, incomplete = search_page(client, query, page)
            record["incomplete_results"] = record["incomplete_results"] or incomplete

        records.append(record)
        log(f"[search] {language} stars {low}..{high}: {total:,} found, pool {len(pool):,}")
        if pool_cap and len(pool) >= pool_cap:
            record["stopped_at_pool_cap"] = True
            break

    return pool, records


# ============================
# DEPENDENCY FILES
# ============================
def dependency_files(client, full_name, wanted):
    """
    (sorted names of the wanted files in the root folder, ok). ok is False
    when the listing was not available (404 empty repo, 451 blocked, ...).
    """
    url = f"{API}/repos/{quote(full_name, safe='/')}/contents/"
    response = client.get("core", url)
    if response.status_code != 200:
        return [], False
    try:
        entries = response.json()
    except ValueError:
        return [], False
    if not isinstance(entries, list):
        return [], False
    names = {e.get("name") for e in entries if isinstance(e, dict) and e.get("type") == "file"}
    return sorted(f for f in wanted if f in names), True


def sample_group(client, group, pool, target, seed):
    """(selected rows, walk counts): walk the shuffled pool until target are accepted."""
    label = GROUP_LABELS[group]
    selected = []
    counts = Counter()

    for row in shuffled(pool, seed, group):
        if len(selected) >= target:
            break
        reason = exclusion_reason(row)
        if reason:
            counts[f"excluded_{reason}"] += 1
            continue
        counts["checked"] += 1
        found, ok = dependency_files(client, row["name"], DEP_FILES[group])
        if found:
            selected.append(dict(row, group=group, dependency_files=";".join(found)))
        elif ok:
            counts["no_dependency_file"] += 1
        else:
            counts["contents_unavailable"] += 1
        if counts["checked"] % 25 == 0:
            log(f"[check] {label} {len(selected)}/{target} accepted, {counts['checked']} checked")

    counts["accepted"] = len(selected)
    log(f"[check] {label} {len(selected)}/{target} accepted, {counts['checked']} checked (done)")
    return selected, counts


# ============================
# OUTPUT
# ============================
def write_atomically(files):
    """files: {path: text}. All are written to .tmp first, then renamed."""
    temps = []
    try:
        for path, text in files.items():
            path = Path(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(path.name + ".tmp")
            with open(tmp, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            temps.append((tmp, path))
        for tmp, path in temps:
            os.replace(tmp, path)
    finally:
        for tmp, _ in temps:
            if tmp.exists():
                tmp.unlink()


def csv_text(rows):
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return out.getvalue()


def criteria_record(args, today, cutoff, target, slices, pools, pool_excluded, walks,
                    selected, client):
    by_language = Counter(r["language"] for r in selected)
    return {
        "dataset": "seed_v2",
        "script": "dataset/build_seed_list.py",
        "query_date_utc": today.isoformat(),
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "test_run": args.limit is not None,
        "limit": args.limit,
        "seed": args.seed,
        "criteria": {
            "groups": {g: list(langs) for g, langs in GROUPS.items()},
            "target_per_group": target,
            "stars_min": STARS_MIN,
            "stars_max": STARS_MAX,
            "forks_min": FORKS_MIN,
            "pushed_within_days": PUSHED_WITHIN_DAYS,
            "pushed_on_or_after": cutoff.isoformat(),
            "fork": False,
            "archived": False,
            "dependency_files": {g: list(f) for g, f in DEP_FILES.items()},
            "dependency_check": "root folder only, GET /repos/{owner}/{repo}/contents/; "
                                "the file must match the group's language",
            "exclusion_rule": {
                "name_tokens": sorted(EXCLUDE_NAME_TOKENS),
                "name_phrases": list(EXCLUDE_NAME_PHRASES),
                "name_prefix": EXCLUDE_NAME_PREFIX,
                "topics": sorted(EXCLUDE_TOPICS),
                "description_contains": list(EXCLUDE_DESCRIPTION),
                "how": "repo name lowercased and split on - _ . into whole tokens; "
                       "topics compared lowercased; description substring",
            },
        },
        "query_template": build_query("<language>", "<low>", "<high>", cutoff),
        "search": {"sort": "stars", "order": "desc", "per_page": PER_PAGE,
                   "cap_per_query": SEARCH_CAP,
                   "start_slices": [list(s) for s in START_SLICES],
                   "split_rule": "a slice with total_count > 1000 is split in half"},
        "sampling": ("pool per group sorted by repo id, shuffled with "
                     "random.Random(f'{seed}-{group}'), walked in order; excluded repos "
                     "skipped, the rest checked for a dependency file until the target is met"),
        "slices": slices,
        "counts": {
            "pool_by_language": {lang: n for lang, n in pools["by_language"].items()},
            "pool_by_group": pools["by_group"],
            "excluded_in_pool": pool_excluded,
            "walk_by_group": walks,
            "selected_by_group": {g: sum(1 for r in selected if r["group"] == g) for g in GROUPS},
            "selected_by_language": dict(sorted(by_language.items())),
            "selected_total": len(selected),
            "requests": dict(client.requests),
        },
        "notes": [
            "Stars, forks and push dates are as of query_date_utc; rerunning later gives a "
            "different pool, so seed_v2.csv is the frozen record.",
            "excluded_in_pool counts the whole pool; walk_by_group counts only the repos "
            "walked until the target was met.",
        ] + (["test run (--limit): the pool was capped, so the sample is not representative"]
             if args.limit is not None else []),
    }


# ============================
# CLI
# ============================
def load_token():
    load_dotenv(ENV_FILE)
    return (os.environ.get("GITHUB_TOKEN") or "").strip()


def main(argv=None, session=None, clock=time.time, sleep=time.sleep, today=None):
    parser = argparse.ArgumentParser(
        description="Build seed list v2 from GitHub search (dry run by default)."
    )
    parser.add_argument("--apply", action="store_true",
                        help="write the CSV and criteria JSON (default: dry run, nothing written)")
    parser.add_argument("--limit", type=int, default=None,
                        help="total repos for a test run (split evenly between the two groups)")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="sampling seed")
    parser.add_argument("--out-csv", default=str(DEFAULT_CSV))
    parser.add_argument("--out-json", default=str(DEFAULT_JSON))
    parser.add_argument("--overwrite", action="store_true",
                        help="with --apply, replace existing output files")
    parser.add_argument("--show", type=int, default=20, help="repos listed in the summary")
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 2:
        print("Error: --limit must be at least 2 (one repo per group).")
        return 2
    target = args.limit // 2 if args.limit is not None else TARGET_PER_GROUP

    out_csv, out_json = Path(args.out_csv), Path(args.out_json)
    if args.apply and not args.overwrite:
        existing = [str(p) for p in (out_csv, out_json) if p.exists()]
        if existing:
            print("Error: already exists (use --overwrite to replace): " + ", ".join(existing))
            return 2

    token = load_token()
    if not token:
        print(f"Error: GITHUB_TOKEN is not set. Add GITHUB_TOKEN=... to {ENV_FILE}.")
        return 2

    today = today or datetime.now(timezone.utc).date()
    cutoff = pushed_cutoff(today)
    if session is None:
        import requests
        session = requests.Session()
    client = GitHubClient(session, token, clock=clock, sleep=sleep)
    del token

    pool_cap = target * LIMIT_POOL_FACTOR if args.limit is not None else None
    slices = []
    pools = {"by_language": {}, "by_group": {}}
    pool_excluded = {}
    walks = {}
    selected = []

    print(f"Seed list v2 ({'apply' if args.apply else 'dry run'}): target {target} per group, "
          f"seed {args.seed}, pushed on or after {cutoff.isoformat()}", flush=True)
    try:
        for group, languages in GROUPS.items():
            group_pool = {}
            for language in languages:
                pool, records = search_language(client, language, cutoff, pool_cap)
                slices.extend(records)
                pools["by_language"][language] = len(pool)
                for repo_id, row in pool.items():
                    group_pool.setdefault(repo_id, row)
            pools["by_group"][group] = len(group_pool)
            pool_excluded[group] = dict(Counter(
                exclusion_reason(r) or "kept" for r in group_pool.values()))

            rows, counts = sample_group(client, group, group_pool, target, args.seed)
            walks[group] = dict(counts)
            selected.extend(rows)
            if len(rows) < target:
                log(f"[warn] {GROUP_LABELS[group]}: only {len(rows)} of {target} found")
    except Stop as e:
        print(f"\nStopped: {e}. Nothing was written.")
        return 1

    selected.sort(key=lambda r: (list(GROUPS).index(r["group"]), r["name"].lower()))
    by_language = Counter(r["language"] for r in selected)

    print("\nPool by language:   " + ", ".join(f"{k} {v:,}" for k, v in pools["by_language"].items()))
    print("Selected by group:  " + ", ".join(
        f"{GROUP_LABELS[g]} {walks[g]['accepted']}" for g in GROUPS))
    print("Selected by language: " + ", ".join(f"{k} {v}" for k, v in sorted(by_language.items())))
    print(f"Requests made: search {client.requests['search']}, core {client.requests['core']}")

    shown = selected[:args.show]
    if shown:
        print(f"\nFirst {len(shown)} repos:")
        for r in shown:
            print(f"  {r['name']:<45} {r['language']:<11} {r['stars']:>6} stars "
                  f"{r['forks']:>5} forks  {r['last_push']}  {r['dependency_files']}")

    if not args.apply:
        print("\nDry run: nothing was written. Re-run with --apply to write "
              f"{out_csv.name} and {out_json.name}.")
        return 0

    record = criteria_record(args, today, cutoff, target, slices, pools, pool_excluded,
                             walks, selected, client)
    write_atomically({out_csv: csv_text(selected),
                      out_json: json.dumps(record, indent=2) + "\n"})
    print(f"\nWrote {len(selected)} repos to {out_csv} and the criteria to {out_json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
