# sbom-tools/fetch_repo_urls.py
#
# Look up repository URLs on PyPI and npm, only for the names that can form a
# "same name, different repository" pair: our packages (pypi, npm or none)
# whose name is known on BOTH PyPI and npm. Known names come from
# data-prep/reference_names.csv when it exists, else the release cache.
#
# Results go to data-prep/repo_urls.csv (name, ecosystem, repository_url,
# status), read by propose_labeled_pairs.py --repo-urls. No database writes.
#
#   status       meaning
#   ok           a GitHub repository URL was found
#   non_github   a URL was found, but not on GitHub
#   no_repo_url  the package has no repository / homepage URL
#   not_found    the registry answered 404 / 410
#   error        network error, timeout, 5xx or bad JSON (retried next run)
#
# Preview (default): lists the names and the count; makes NO request.
#     python sbom-tools/fetch_repo_urls.py
# Look them up (at most 1 request per second, one attempt per name; a 429 or
# 5 errors in a row stop the run). Resumable: a rerun skips names already
# done and retries only "error" rows.
#     python sbom-tools/fetch_repo_urls.py --apply [--contact you@example.org]

import argparse
import csv
import re
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import quote

from name_match import collapse, ecosystem_of, load_candidates
from reference_sources import normalize_repo_url

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REFERENCE_NAMES = PROJECT_ROOT / "data-prep" / "reference_names.csv"
DEFAULT_RELEASE_CACHE = PROJECT_ROOT / "data-prep" / "release_cache.json"
DEFAULT_OUT = PROJECT_ROOT / "data-prep" / "repo_urls.csv"

ECOSYSTEMS = ("pypi", "npm")
PACKAGE_ECOSYSTEMS = ("pypi", "npm", "none")

USER_AGENT = "sbom-project-fetch-repo-urls/1.0"
MIN_INTERVAL = 1.0          # seconds between request starts; never less
TIMEOUT = 15.0
MAX_ERRORS_IN_A_ROW = 5

OK, NON_GITHUB, NO_REPO_URL, NOT_FOUND, ERROR = (
    "ok", "non_github", "no_repo_url", "not_found", "error")
STATUSES = (OK, NON_GITHUB, NO_REPO_URL, NOT_FOUND, ERROR)
FINAL_STATUSES = (OK, NON_GITHUB, NO_REPO_URL, NOT_FOUND)   # not looked up again

COLUMNS = ["name", "ecosystem", "repository_url", "status"]

# PyPI project_urls labels, best first (compared case-insensitively)
PYPI_URL_KEYS = ["source", "source code", "repository", "code", "github", "homepage", "home"]

# npm "repository" shorthand: owner/repo, github:owner/repo, gitlab:..., bitbucket:...
NPM_SHORTHAND = re.compile(r"^(?:(github|gitlab|bitbucket):)?([\w.-]+)/([\w.-]+)$")
SHORTHAND_HOSTS = {"github": "github.com", "gitlab": "gitlab.com", "bitbucket": "bitbucket.org"}


# ============================
# WHICH NAMES
# ============================
def known_names(reference_names=None, release_cache=None):
    """
    ({ecosystem: {collapse(name): set of registry spellings}}, source used)
    for pypi and npm, from reference_names.csv if it exists, else the
    release cache.
    """
    if reference_names and Path(reference_names).is_file():
        pairs, source = load_candidates(reference_names), str(reference_names)
    elif release_cache and Path(release_cache).is_file():
        pairs, source = load_candidates(release_cache), str(release_cache)
    else:
        raise FileNotFoundError(
            f"no known names: neither {reference_names} nor {release_cache} exists")

    known = {eco: {} for eco in ECOSYSTEMS}
    for name, eco in pairs:
        eco = ecosystem_of(eco) or eco
        if eco in known:
            known[eco].setdefault(collapse(name), set()).add(name)
    return known, source


def select_names(packages, known):
    """
    Sorted (ecosystem, name) to look up: for every package (pypi, npm or
    none) whose name is known on both registries, each registry's spelling.
    """
    wanted = set()
    for row in packages:
        if (ecosystem_of(row["ecosystem"]) or row["ecosystem"]) not in PACKAGE_ECOSYSTEMS:
            continue
        key = collapse(row["package_name"])
        if all(key in known[eco] for eco in ECOSYSTEMS):
            for eco in ECOSYSTEMS:
                for name in known[eco][key]:
                    if not name.startswith("@"):     # scoped npm can't be a PyPI name
                        wanted.add((eco, name))
    return sorted(wanted)


# ============================
# RESULTS FILE
# ============================
def load_results(path):
    """{(ecosystem, name): row} from repo_urls.csv; the last row per name wins."""
    results = {}
    path = Path(path)
    if not path.is_file():
        return results
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("name") and row.get("ecosystem"):
                results[(row["ecosystem"], row["name"])] = row
    return results


def append_result(path, row):
    """Append one result and flush it, writing the header for a new file."""
    path = Path(path)
    new = not path.is_file() or path.stat().st_size == 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        if new:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") or "" for k in COLUMNS})
        f.flush()


# ============================
# FINDING THE URL IN A RESPONSE
# ============================
def _first_url(urls):
    """(url, status): the first GitHub URL, else the first URL, else none."""
    urls = [u.strip() for u in urls if isinstance(u, str) and u.strip()
            and u.strip().lower() not in ("unknown", "none", "nan")]
    for url in urls:
        if normalize_repo_url(url):
            return url, OK
    if urls:
        return urls[0], NON_GITHUB
    return "", NO_REPO_URL


def pypi_repo_url(data):
    """(url, status) from a PyPI JSON API response."""
    info = (data or {}).get("info") or {}
    project_urls = info.get("project_urls") or {}
    by_label = {str(k).strip().lower(): v for k, v in project_urls.items()}
    ordered = [by_label[k] for k in PYPI_URL_KEYS if k in by_label]
    ordered += [v for k, v in by_label.items() if k not in PYPI_URL_KEYS]
    ordered.append(info.get("home_page"))
    return _first_url(ordered)


def expand_npm_shorthand(text):
    """github:owner/repo or owner/repo -> https://github.com/owner/repo (etc.)."""
    m = NPM_SHORTHAND.match(text.strip())
    if not m:
        return text
    host = SHORTHAND_HOSTS[m.group(1) or "github"]
    return f"https://{host}/{m.group(2)}/{m.group(3)}"


def npm_repo_url(data):
    """(url, status) from an npm registry /<name>/latest response."""
    repo = (data or {}).get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    if isinstance(repo, str) and repo.strip():
        return _first_url([expand_npm_shorthand(repo)])
    return "", NO_REPO_URL


def registry_url(ecosystem, name):
    if ecosystem == "pypi":
        return f"https://pypi.org/pypi/{quote(name, safe='')}/json"
    return f"https://registry.npmjs.org/{quote(name, safe='')}/latest"


# ============================
# REQUESTS
# ============================
class RateLimited(Exception):
    """HTTP 429: stop the run (retry_after is the server's Retry-After, if any)."""

    def __init__(self, retry_after):
        super().__init__(f"rate limited (Retry-After: {retry_after or 'not given'})")
        self.retry_after = retry_after


class Fetcher:
    """One HTTP GET at a time, at most one start per min_interval seconds."""

    def __init__(self, session, user_agent=USER_AGENT, timeout=TIMEOUT,
                 min_interval=MIN_INTERVAL, clock=time.monotonic, sleep=time.sleep):
        self.session = session
        self.headers = {"User-Agent": user_agent, "Accept": "application/json"}
        self.timeout = timeout
        self.min_interval = max(float(min_interval), MIN_INTERVAL)
        self.clock = clock
        self.sleep = sleep
        self._last_start = None
        self.requests = 0

    def get(self, url):
        if self._last_start is not None:
            wait = self.min_interval - (self.clock() - self._last_start)
            if wait > 0:
                self.sleep(wait)
        self._last_start = self.clock()
        self.requests += 1
        return self.session.get(url, headers=self.headers, timeout=self.timeout)


def look_up(fetcher, ecosystem, name):
    """
    (repository_url, status) for one name. One attempt only. Raises
    RateLimited on HTTP 429.
    """
    import requests

    try:
        response = fetcher.get(registry_url(ecosystem, name))
    except requests.RequestException:
        return "", ERROR

    if response.status_code == 429:
        raise RateLimited(response.headers.get("Retry-After"))
    if response.status_code in (404, 410):
        return "", NOT_FOUND
    if response.status_code != 200:
        return "", ERROR
    try:
        data = response.json()
    except ValueError:
        return "", ERROR
    return pypi_repo_url(data) if ecosystem == "pypi" else npm_repo_url(data)


# ============================
# CLI
# ============================
def main(argv=None, session=None, clock=time.monotonic, sleep=time.sleep):
    parser = argparse.ArgumentParser(
        description="Look up PyPI/npm repository URLs for names on both registries (preview by default)."
    )
    parser.add_argument("--reference-names", default=str(DEFAULT_REFERENCE_NAMES),
                        help="known names (used if the file exists)")
    parser.add_argument("--release-cache", default=str(DEFAULT_RELEASE_CACHE),
                        help="known names when reference_names.csv is missing")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="results CSV (appended)")
    parser.add_argument("--contact", default="",
                        help="added to the User-Agent, e.g. an email or URL (nothing by default)")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="seconds per request")
    parser.add_argument("--min-interval", type=float, default=MIN_INTERVAL,
                        help="seconds between requests (at least 1)")
    parser.add_argument("--show", type=int, default=None,
                        help="list only the first N names in the preview (default: all)")
    parser.add_argument("--apply", action="store_true",
                        help="Actually make the requests. Without this flag only a preview is shown.")
    args = parser.parse_args(argv)

    try:
        known, source = known_names(args.reference_names, args.release_cache)
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        return 2

    from db_storage import get_db_storage
    packages = get_db_storage().package_match_rows()

    names = select_names(packages, known)
    done = load_results(args.out)
    todo = [n for n in names if done.get(n, {}).get("status") not in FINAL_STATUSES]
    retry = [n for n in todo if n in done]
    interval = max(args.min_interval, MIN_INTERVAL)

    print(f"Known names from {source}")
    print(f"Names on both PyPI and npm among our {len(packages)} packages: "
          f"{len(names)} lookups ({dict(Counter(e for e, _ in names))})")
    print(f"Already done in {args.out}: {len(names) - len(todo)}; "
          f"to look up: {len(todo)} (of which {len(retry)} earlier errors)")
    print(f"Estimated time: about {len(todo) * interval / 60:.1f} min at one request per "
          f"{interval:g} s")

    if not args.apply:
        shown = todo if args.show is None else todo[:args.show]
        if shown:
            print("\nWould look up:")
            for eco, name in shown:
                print(f"  {eco:<5} {name}")
            if len(shown) < len(todo):
                print(f"  ... and {len(todo) - len(shown)} more")
        print("\nPreview only. No request was made and nothing was written. "
              "Re-run with --apply to look them up.")
        return 0

    if session is None:
        import requests
        session = requests.Session()
    user_agent = USER_AGENT + (f" (+{args.contact})" if args.contact else "")
    fetcher = Fetcher(session, user_agent, args.timeout, interval, clock, sleep)

    counts = Counter()
    errors_in_a_row = 0
    stopped = None
    for i, (eco, name) in enumerate(todo, start=1):
        try:
            url, status = look_up(fetcher, eco, name)
        except RateLimited as e:
            stopped = f"stopped: {e}. Progress is saved; rerun later to continue."
            break
        append_result(args.out, {"name": name, "ecosystem": eco,
                                 "repository_url": url, "status": status})
        counts[status] += 1
        errors_in_a_row = errors_in_a_row + 1 if status == ERROR else 0
        if errors_in_a_row >= MAX_ERRORS_IN_A_ROW:
            stopped = (f"stopped: {MAX_ERRORS_IN_A_ROW} errors in a row (network down?). "
                       "Progress is saved; rerun later to continue.")
            break
        if i % 50 == 0:
            print(f"  {i}/{len(todo)} ...", flush=True)

    print(f"\nRequests made: {fetcher.requests}")
    print("Results: " + ", ".join(f"{s} {counts[s]}" for s in STATUSES))
    if stopped:
        print(stopped)
        return 1
    print(f"Saved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
