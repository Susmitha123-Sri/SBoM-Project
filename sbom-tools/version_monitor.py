import requests
from packaging import version as v
from datetime import datetime
from dotenv import load_dotenv
import os
import time

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ============================
# CACHE (VERY IMPORTANT)
# ============================
VERSION_CACHE = {}

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

        else:
            result = None

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
        if "/" not in package_name:
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
# COMPARE
# ============================
def compare_versions(current_version, latest_version):
    if not current_version or not latest_version:
        return "unknown"
    elif current_version == latest_version:
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
        if "/" not in package_name:
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
        if "/" not in package_name:
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