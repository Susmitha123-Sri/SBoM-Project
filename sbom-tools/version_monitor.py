import requests
from packaging import version as v
from datetime import datetime
from dotenv import load_dotenv
from urllib.parse import quote
import os
import time

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ============================
# CACHE (VERY IMPORTANT)
# ============================
VERSION_CACHE = {}

# ============================
# ECOSYSTEM OF A PACKAGE NAME
# ============================
# Other spellings stored in packages.ecosystem (sbom.py uses "python" etc.)
ECOSYSTEM_ALIASES = {
    "pypi": "pypi", "python": "pypi",
    "npm": "npm", "node": "npm",
    "github": "github", "github-action": "github",
    "none": "none",
}

# "none": not on any registry we can query (e.g. a dataset row whose
# registry_ecosystem is not_found). Never looked up; status stays unknown.
NO_REGISTRY = "none"

# package_type argument of get_latest_version() for each ecosystem
# (None = no registry, nothing to look up)
PACKAGE_TYPES = {"pypi": "python", "npm": "npm", "github": "github-action", NO_REGISTRY: None}


def is_npm_scoped(package_name):
    """@scope/name is an npm package, never a GitHub owner/repo."""
    return str(package_name or "").startswith("@")


def package_ecosystem(package_name, hint=None):
    """
    "pypi", "npm", "github" or "none" for a package name.

    A "none" hint (no registry) always wins. Then the name decides when it
    can: @scope/name is npm, and any other name with a "/" is a GitHub
    owner/repo (neither PyPI nor unscoped npm names can contain "/").
    Otherwise the hint (a stored or CSV ecosystem such as "npm", "pypi",
    "python") decides, and anything else means PyPI.
    """
    name = str(package_name or "")
    if ECOSYSTEM_ALIASES.get(str(hint or "").strip().lower()) == NO_REGISTRY:
        return NO_REGISTRY
    if is_npm_scoped(name):
        return "npm"
    if "/" in name:
        return "github"
    hinted = ECOSYSTEM_ALIASES.get(str(hint or "").strip().lower())
    return hinted if hinted in ("pypi", "npm") else "pypi"


def package_type(package_name, hint=None):
    """get_latest_version() package_type for this package (None = no registry)."""
    return PACKAGE_TYPES[package_ecosystem(package_name, hint)]

# ============================
# SAFE REQUEST
# ============================
def safe_request(url, headers):

    for attempt in range(3):
        try:
            r = requests.get(url, headers=headers, timeout=10)

            if r.status_code == 200:
                return r

            elif r.status_code == 403:
                time.sleep(5 * (attempt + 1))

        except Exception as e:
            print("Request error:", e)

    return None


def clear_caches():
    """Forget cached latest versions, so each monitor run sees new releases."""
    VERSION_CACHE.clear()
    NPM_CACHE.clear()


# ============================
# ARE THE REGISTRIES REACHABLE?
# ============================
REACHABILITY_URLS = ("https://pypi.org/", "https://registry.npmjs.org/")


def registries_reachable(tries=2, timeout=10):
    """True if PyPI and npm both answer (any HTTP status below 500)."""
    for url in REACHABILITY_URLS:
        for attempt in range(tries):
            try:
                if requests.head(url, timeout=timeout).status_code < 500:
                    break
            except requests.RequestException:
                pass
        else:
            return False
    return True


# ============================
# GET LATEST VERSION (CACHED)
# ============================
def get_latest_version(package_name, package_type):

    key = f"{package_name}:{package_type}"

    if key in VERSION_CACHE:
        return VERSION_CACHE[key]

    try:
        if package_type == "python":
            result = get_latest_pypi_version(package_name)

        elif package_type == "github-action":
            result = get_latest_github_action_version(package_name)

        elif package_type == "npm":
            result = get_latest_npm_version(package_name)

        else:
            result = None   # no registry for this type (e.g. None = "none")

        # Only successful lookups are cached: a failure (timeout, rate
        # limit) is retried next time instead of sticking until restart
        if result is not None:
            VERSION_CACHE[key] = result
        return result

    except Exception as e:
        print("Version fetch error:", e)
        return None


# ============================
# PYPI VERSION
# ============================
def get_latest_pypi_version(package_name):
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return None

        return response.json().get("info", {}).get("version")

    except Exception as e:
        print("PyPI error:", package_name, e)
        return None


# ============================
# GITHUB VERSION
# ============================
def get_latest_github_action_version(package_name):
    try:
        if "/" not in package_name or is_npm_scoped(package_name):
            return None

        headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

        # latest release
        url = f"https://api.github.com/repos/{package_name}/releases/latest"
        response = safe_request(url, headers)

        if response:
            return response.json().get("tag_name")

        # fallback → tags
        url = f"https://api.github.com/repos/{package_name}/tags"
        response = safe_request(url, headers)

        if response:
            data = response.json()
            if data:
                return data[0].get("name")

        return None

    except Exception as e:
        print("GitHub version error:", package_name, e)
        return None


# ============================
# NPM (latest version + release dates from one request)
# ============================
NPM_REGISTRY = "https://registry.npmjs.org/"
NPM_CACHE = {}   # name -> {"latest": str, "releases": {version: "YYYY-MM-DD"}}


def get_npm_package_info(package_name):
    """
    Latest version and release dates of an npm package, or None if the
    lookup failed. Only successful lookups are cached, so a failure is
    retried next time.
    """
    if package_name in NPM_CACHE:
        return NPM_CACHE[package_name]

    try:
        # Scoped names keep the "@" but encode the "/": @babel%2Fcore
        url = NPM_REGISTRY + quote(package_name, safe="@")
        response = requests.get(url, timeout=15)

        if response.status_code != 200:
            return None

        data = response.json()
        times = data.get("time") or {}
        info = {
            "latest": (data.get("dist-tags") or {}).get("latest"),
            "releases": {
                ver: str(when)[:10]
                for ver, when in times.items()
                if ver not in ("created", "modified") and when
            },
        }

        NPM_CACHE[package_name] = info
        return info

    except Exception as e:
        print("npm error:", package_name, e)
        return None


def get_latest_npm_version(package_name):
    info = get_npm_package_info(package_name)
    return info["latest"] if info else None


def get_npm_release_info(package_name):
    """{version: "YYYY-MM-DD"} like get_package_release_info(); {} on failure."""
    info = get_npm_package_info(package_name)
    return dict(info["releases"]) if info else {}


# ============================
# COMPARE
# ============================
def pypi_release(text):
    """A plain PyPI version, parsed; None if unparseable, a dev build or a local version."""
    try:
        parsed = v.Version(str(text).strip())
    except v.InvalidVersion:
        return None
    if parsed.is_devrelease or parsed.local:
        return None
    return parsed


def same_version(a, b, ecosystem=None):
    """
    True if a and b are the same release. Exact string, except on PyPI where
    26 == 26.0 and 0.8 == 0.8.0 (PEP 440). Dev/local builds and
    unparseable versions only match exactly; npm/GitHub always exactly.
    (Same rule as data-prep/add_release_dates.py match_current.)
    """
    if not a or not b:
        return False
    if a == b:
        return True
    if ecosystem != "pypi":
        return False
    pa = pypi_release(a)
    return pa is not None and pa == pypi_release(b)


def match_release(releases, version, ecosystem=None):
    """The key in releases that is this version (see same_version), or None."""
    if not version:
        return None
    if version in releases:
        return version
    if ecosystem != "pypi":
        return None
    return next((key for key in releases if same_version(version, key, ecosystem)), None)


def compare_versions(current_version, latest_version, ecosystem=None):
    """
    "up_to_date", "outdated" or "unknown" (a version missing). ecosystem
    "pypi" compares by PEP 440 (see same_version); anything else, exactly.
    """
    if not current_version or not latest_version:
        return "unknown"
    elif same_version(current_version, latest_version, ecosystem):
        return "up_to_date"
    else:
        return "outdated"


# ============================
# PYPI RELEASE INFO
# ============================
def get_package_release_info(package_name):
    try:
        url = f"https://pypi.org/pypi/{package_name}/json"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return {}

        data = response.json()
        releases = {}

        for ver, files in data.get("releases", {}).items():
            if not files:
                continue

            for f in files:
                if f.get("upload_time"):
                    releases[ver] = f["upload_time"][:10]
                    break

        return releases

    except Exception as e:
        print("PyPI fetch failed:", package_name, e)
        return {}


# ============================
# GITHUB COMMIT DATE
# ============================
def get_commit_date(package_name, version):
    try:
        if "/" not in package_name or is_npm_scoped(package_name):
            return None

        headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
        url = f"https://api.github.com/repos/{package_name}/commits"

        r = safe_request(url, headers)

        if not r:
            return None

        data = r.json()

        if data:
            return data[0]["commit"]["committer"]["date"][:10]

        return None

    except Exception as e:
        print("Commit API error:", package_name, e)
        return None


# ============================
# GITHUB RELEASE INFO
# ============================
def get_github_release_info(package_name):
    try:
        if "/" not in package_name or is_npm_scoped(package_name):
            return {}

        headers = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

        releases = {}

        url = f"https://api.github.com/repos/{package_name}/releases"
        response = safe_request(url, headers)

        if response:
            for r in response.json():
                tag = r.get("tag_name")
                date = r.get("published_at")

                if tag and date:
                    releases[tag] = date[:10]

        # fallback
        if not releases:
            url = f"https://api.github.com/repos/{package_name}/tags"
            response = safe_request(url, headers)

            if response:
                for t in response.json()[:10]:
                    releases[t.get("name")] = None

        return releases

    except Exception as e:
        print("GitHub fetch failed:", package_name, e)
        return {}