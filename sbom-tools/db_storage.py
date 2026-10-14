#!/usr/bin/env python
# coding: utf-8

import pymysql
import threading
import traceback
from typing import Optional
from datetime import datetime
from version_monitor import get_package_release_info
from version_monitor import get_commit_date
from version_monitor import package_ecosystem, ECOSYSTEM_ALIASES
from age_tiers import classify_age, tier_label, TIER_NAMES, UNKNOWN_TIER
import requests
from packaging import version as v

import re

def smart_gap(current, latest):
    try:
        c = int(re.findall(r'\d+', str(current))[0])
        l = int(re.findall(r'\d+', str(latest))[0])
        return max(l - c, 0)
    except:
        return 0

def normalize_version(v):
    try:
        v = str(v).lower().replace("v", "")
        nums = re.findall(r'\d+', v)
        return [int(n) for n in nums] if nums else [0]
    except:
        return [0]


def calculate_real_gap(current, latest):
    try:
        c = normalize_version(current)
        l = normalize_version(latest)

        length = max(len(c), len(l))
        c += [0] * (length - len(c))
        l += [0] * (length - len(l))

        gap = 0
        for i in range(length):
            if l[i] > c[i]:
                gap += (l[i] - c[i]) * (10 ** (length - i - 1))

        return gap

    except:
        return 0

#-----------------------------------------

def ecosystem_differs(stored, new):
    """True if new is a known ecosystem and stored is a different one."""
    def norm(e):
        return ECOSYSTEM_ALIASES.get(str(e or "").strip().lower())
    return norm(new) is not None and norm(stored) != norm(new)


def detect_package_source(package_name, ecosystem=None):
    """
    "pypi", "npm" or "github". @scope/name is npm (never a GitHub repo);
    see version_monitor.package_ecosystem for the full rule.
    """
    return package_ecosystem(package_name, ecosystem)


def get_github_releases(repo_name):
    try:
        url = f"https://api.github.com/repos/{repo_name}/releases"
        response = requests.get(url, timeout=5)

        if response.status_code != 200:
            return {}

        data = response.json()

        releases = {}
        for r in data:
            tag = r.get("tag_name")
            date = r.get("published_at")

            if tag and date:
                releases[tag] = date[:10]

        return releases

    except:
        return {}


def find_closest_version(current, versions):
    try:
        current_v = v.parse(str(current))
        parsed_versions = []

        for ver in versions:
            try:
                parsed_versions.append((ver, v.parse(ver)))
            except:
                continue

        parsed_versions.sort(key=lambda x: x[1])

        for i, (ver, parsed) in enumerate(parsed_versions):
            if parsed >= current_v:
                return ver, i

        return parsed_versions[-1][0], len(parsed_versions) - 1

    except:
        return None, None

#------------------------------------------
VERSION_GAP_UNKNOWN = "N/A"


def calculate_versions_behind(current, latest):
    """
    "Version Behind" (stored in versions.versions_behind and shown in the UI).

    Compares major, then minor, then patch, and reports only the first part
    that differs: 1.26.5 -> 2.8.0 is "1.0.0", 1.2.9 -> 1.5.0 is "0.3.0",
    1.2.3 -> 1.2.7 is "0.0.4". Never negative (an installed version at or
    ahead of latest is "0.0.0"). "N/A" if either version can't be parsed.
    """
    if not current or not latest:
        return VERSION_GAP_UNKNOWN
    try:
        cur = v.Version(str(current).strip()).release
        lat = v.Version(str(latest).strip()).release
    except v.InvalidVersion:
        return VERSION_GAP_UNKNOWN

    cur = (list(cur) + [0, 0, 0])[:3]
    lat = (list(lat) + [0, 0, 0])[:3]

    gap = [0, 0, 0]
    for i in range(3):
        if lat[i] != cur[i]:
            gap[i] = max(lat[i] - cur[i], 0)
            break

    return ".".join(str(n) for n in gap)

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "root123",
    "database": "sbom_common",
    "cursorclass": pymysql.cursors.DictCursor
}

# ======================================
# NEW: SAFE CONNECTION (THREAD SAFE)
# ======================================
def get_new_connection():
    return pymysql.connect(**DB_CONFIG)

# ======================================
# SETTINGS (shared, stored in DB)
# ======================================
RESCAN_UNITS = ("minutes", "hours", "days")

DEFAULT_SETTINGS = {
    "rescan_interval_value": "6",
    "rescan_interval_unit": "hours",
    "age_threshold_days": "365",
}

# Management review of a package (package_reviews.status). A package with
# no package_reviews row is "Open".
REVIEW_STATUSES = ("Open", "Reviewed - Accepted", "Compensating Control", "Resolved")


def ensure_schema():
    """Create the settings table and days_since_release column if missing."""
    conn = get_new_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    setting_key VARCHAR(100) PRIMARY KEY,
                    setting_value VARCHAR(255) NOT NULL,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP
                )
            """)

            for key, value in DEFAULT_SETTINGS.items():
                cursor.execute(
                    "INSERT IGNORE INTO settings (setting_key, setting_value) VALUES (%s, %s)",
                    (key, value)
                )

            # MySQL has no ADD COLUMN IF NOT EXISTS, so check first.
            # Both columns are nullable, so existing rows are left untouched.
            for column, definition in (
                ("days_since_release", "INT NULL"),
                ("age_tier", "VARCHAR(20) NULL"),
            ):
                cursor.execute("""
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'versions'
                      AND COLUMN_NAME = %s
                """, (column,))
                if cursor.fetchone()["cnt"] == 0:
                    cursor.execute(
                        f"ALTER TABLE versions ADD COLUMN {column} {definition}"
                    )

        conn.commit()
    finally:
        conn.close()


def days_since(date_str):
    """Days between a YYYY-MM-DD(...) date string and today, or None."""
    if not date_str:
        return None
    try:
        released = datetime.strptime(str(date_str)[:10], "%Y-%m-%d")
        return max((datetime.now() - released).days, 0)
    except Exception:
        return None


def find_release_date(releases, version):
    """Release date of exactly this version (tolerating a leading 'v')."""
    if not releases or not version:
        return None
    version = str(version)
    bare = version[1:] if version.lower().startswith("v") else version
    for candidate in (version, bare, "v" + bare):
        if releases.get(candidate):
            return releases[candidate]
    return None


def compute_age_tier(releases, version, latest_version):
    """
    Age tier label from how far the installed version's release date is
    behind the latest version's release date, both looked up in the releases
    already fetched ({version: "YYYY-MM-DD"}). See age_tiers.classify_age.
    Returns None (stored as NULL, shown as "unknown") when a date is missing.
    """
    return tier_label(classify_age(
        find_release_date(releases, version),
        find_release_date(releases, latest_version),
    ))

#----------------------------------------
def compute_severity_from_string(versions_behind, days_outdated):
    try:
        gap = str(versions_behind or "0.0.0")
        parts = gap.split(".")

        # An "N/A" gap (unparseable version) gives no version-based risk,
        # but the time-based risk below still applies
        try:
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
        except ValueError:
            major = minor = patch = 0

        days = days_outdated or 0

        # ============================
        # VERSION RISK
        # ============================
        if major >= 2:
            version_risk = "high"
        elif major == 1:
            version_risk = "medium"
        elif minor >= 10:
            version_risk = "medium"
        else:
            version_risk = "low"

        # ============================
        # TIME RISK (LESS AGGRESSIVE)
        # ============================
        if days >= 1500:        # ~4 years
            time_risk = "high"
        elif days >= 365:       # 1 year
            time_risk = "medium"
        else:
            time_risk = "low"

        # ============================
        # FINAL
        # ============================
        severity_rank = {"low": 1, "medium": 2, "high": 3}

        return max(version_risk, time_risk, key=lambda x: severity_rank[x])

    except:
        return "low"

# Statuses decided by comparing installed vs latest. Any other status a
# caller passes (e.g. "baseline" from initial_population.py) is kept.
DERIVED_STATUSES = (None, "up_to_date", "outdated", "unknown")


def compute_version_metrics(package_name, version, status=None, latest_version=None,
                            ecosystem=None):
    """
    The one place that decides a row's status, latest version, tier and
    other metrics (registry lookups, no database). Used by insert_version()
    and refresh_version(), so every write stores values that agree.

    Returns a dict with status, latest_version, versions_behind,
    days_outdated, days_since_release, age_tier and severity_level.

    - latest_version is the registry's latest version, or the caller's if
      the lookup fails, or None. It is never filled in with the installed
      version, so a failed lookup is "unknown", not "up_to_date".
    - status (when derived) is up_to_date only if installed == latest.
    - ecosystem "none" (no registry): no lookups at all; unknown, no tier.
    """

    # ============================
    # GET REAL DATA FROM API
    # ============================

    from version_monitor import get_latest_version, compare_versions, PACKAGE_TYPES

    source = detect_package_source(package_name, ecosystem)

    if PACKAGE_TYPES.get(source) is None:
        # Not on any registry we can query: nothing to look up
        return {
            "status": "unknown" if status in DERIVED_STATUSES else status,
            "latest_version": None,
            "versions_behind": "0.0.0",
            "days_outdated": 0,
            "days_since_release": None,
            "age_tier": None,
            "severity_level": None,
        }

    try:
        latest_version_api = get_latest_version(package_name, PACKAGE_TYPES[source])
    except:
        latest_version_api = None

    latest_version = latest_version_api or latest_version or None

    if status in DERIVED_STATUSES:
        status = compare_versions(version, latest_version)

    # ============================
    # REAL VERSION + TIME CALCULATION
    # ============================

    from datetime import datetime
    from version_monitor import get_package_release_info
    

    versions_behind = "0.0.0"
    days_outdated = 0
    days_since_release = None
    age_tier = None

    try:
        if source == "pypi":
            releases = get_package_release_info(package_name)
        elif source == "npm":
            from version_monitor import get_npm_release_info
            releases = get_npm_release_info(package_name)
        elif source == "github":
            from version_monitor import get_github_release_info
            releases = get_github_release_info(package_name)
            #releases = get_github_releases(package_name)
        else:
            releases = {}

        # -------- DAYS SINCE RELEASE (installed version's own age) --------
        days_since_release = days_since(find_release_date(releases, version))

        # -------- AGE TIER (days behind the latest release) --------
        age_tier = compute_age_tier(releases, version, latest_version)

        if releases:
            # Sort versions chronologically if possible
            #versions = sorted(releases.keys())
            safe_versions = []

            for ver in releases.keys():
                try:
                    v.parse(ver)
                    safe_versions.append(ver)
                except:
                    continue

            versions = sorted(safe_versions, key=lambda x: v.parse(x))
            #versions = sorted(releases.keys(), key=lambda x: v.parse(x))

            # -------- VERSION BEHIND --------
            #versions_behind = calculate_structured_gap(version, versions)
            #versions_behind = self.calculate_structured_gap(version, versions)
            # -------------------------
            # REAL VERSION GAP
            # -------------------------
            if latest_version and latest_version != version:
                versions_behind = calculate_versions_behind(version, latest_version)
            else:
                versions_behind = "0.0.0"
            '''
            if version in versions:
                current_index = versions.index(version)
                versions_behind = len(versions) - current_index - 1
            '''

            # -------- DAYS OUTDATED --------
            #release_date = releases.get(version)
            matched_current, _ = find_closest_version(version, versions)
            matched_latest, _ = find_closest_version(latest_version, versions)

            # ============================
            # DAYS OUTDATED (FINAL FIX)
            # ============================

            date_current = None
            date_latest = None

            if status == "up_to_date":
                days_outdated = 0
            else:
                try:
                    date_current = None
                    date_latest = None

                    # ---------------------------
                    # PYPI / NPM (registry release dates)
                    # ---------------------------
                    if source in ("pypi", "npm"):
                        date_current = releases.get(version)
                        date_latest = releases.get(latest_version)

                    # ---------------------------
                    # GITHUB
                    # ---------------------------
                    elif source == "github":
                        if not matched_current:
                            matched_current = version

                        date_current = get_commit_date(package_name, matched_current)
                        date_latest = get_commit_date(package_name, latest_version)

                    # ---------------------------
                    # CALCULATE
                    # ---------------------------
                    if date_current and date_latest:
                        d1 = datetime.strptime(str(date_current)[:10], "%Y-%m-%d")
                        d2 = datetime.strptime(str(date_latest)[:10], "%Y-%m-%d")
                        days_outdated = (d2 - d1).days
                    else:
                        try:
                            parts = [int(x) for x in str(versions_behind).split(".")]
                            major = parts[0]
                            minor = parts[1] if len(parts) > 1 else 0
                            patch = parts[2] if len(parts) > 2 else 0

                            days_outdated = (major * 180) + (minor * 30) + (patch * 7)

                        except:
                            days_outdated = 30

                except Exception as e:
                    print("Date calculation failed:", package_name, e)
                    days_outdated = 0

            # -------------------------
            # TRY RELEASE FIRST, THEN COMMITS
            # -------------------------
            # FORCE fallback if missing (commit dates exist only for GitHub
            # repos; never ask GitHub about other names)
            if not date_current and source == "github":
                date_current = get_commit_date(package_name, matched_current)

            if not date_latest and source == "github":
                date_latest = get_commit_date(package_name, matched_latest)

            # -------------------------
            # CALCULATE DAYS
            # -------------------------
            if date_current and date_latest:
                try:
                    d1 = datetime.strptime(str(date_current)[:10], "%Y-%m-%d")
                    d2 = datetime.strptime(str(date_latest)[:10], "%Y-%m-%d")

                    days_outdated = (d2 - d1).days
                except:
                    days_outdated = 0
            else:
                try:
                    parts = [int(x) for x in str(versions_behind).split(".")]
                    major = parts[0]
                    minor = parts[1] if len(parts) > 1 else 0
                    patch = parts[2] if len(parts) > 2 else 0

                    days_outdated = (major * 180) + (minor * 30) + (patch * 7)

                except:
                    days_outdated = 30

    except Exception as e:
        print("Real calculation failed:", package_name, e)

    # ============================
    # SAFE DEFAULTS (FINAL FIX)
    # ============================

    # versions_behind must ALWAYS be string
    if not versions_behind or versions_behind == 0:
        versions_behind = "0.0.0"

    # days_outdated must be integer
    if days_outdated is None or days_outdated < 0:
        days_outdated = 0
    

    # 🔥 ADD THIS LINE HERE
    #versions_behind = f"{versions_behind}.0.0"
    '''
    if not versions_behind:
        versions_behind = "0.0.0"
    '''

    # Same severity rule recalculate_metrics_for_scan used; none when the
    # status isn't known
    if status == "up_to_date":
        severity_level = "low"
    elif status == "outdated":
        severity_level = compute_severity_from_string(versions_behind, days_outdated)
    else:
        severity_level = None

    return {
        "status": status,
        "latest_version": latest_version,
        "versions_behind": versions_behind,
        "days_outdated": days_outdated,
        "days_since_release": days_since_release,
        "age_tier": age_tier,
        "severity_level": severity_level,
    }

#=========================================

def empty_scan_summary():
    """Counts for a scan with no packages (shape of get_scan_summaries values)."""
    return {
        "total": 0,
        "outdated": 0,
        "up_to_date": 0,
        "tiers": {name: 0 for name in TIER_NAMES + [UNKNOWN_TIER]},
    }

#=========================================

# Errors that mean the connection was closed or lost mid-use; the
# operation can be retried on a fresh connection.
CONNECTION_LOST_ERRORS = (pymysql.err.InterfaceError, pymysql.err.OperationalError)


class DatabaseStorage:

    # One instance is shared app-wide (get_db_storage), but Flask request
    # threads and the background scheduler/scan threads must never share a
    # pymysql connection, so each thread gets its own.
    def __init__(self):
        self._local = threading.local()

    @property
    def connection(self) -> Optional[pymysql.Connection]:
        return getattr(self._local, "connection", None)

    @connection.setter
    def connection(self, value):
        self._local.connection = value

    def reset_connection(self):
        """Close and drop this thread's connection; the next call reconnects."""
        conn = self.connection
        self.connection = None
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass   # already closed/broken; we're discarding it anyway

    def with_reconnect(self, func, *args, **kwargs):
        """
        Run func; if the connection was lost, reconnect and retry once.
        A second failure is raised to the caller.
        """
        try:
            return func(*args, **kwargs)
        except CONNECTION_LOST_ERRORS as e:
            print(f"Database connection lost ({e!r}); reconnecting and retrying once")
            self.reset_connection()
            return func(*args, **kwargs)

    def _connect(self):
        if self.connection:
            try:
                self.connection.ping(reconnect=False)
                return True
            except Exception:
                self.reset_connection()

        try:
            self.connection = pymysql.connect(**DB_CONFIG)
            return True
        except Exception as e:
            print("Database connection error:", e)
            return False

    # ============================
    # INSERT SCAN (reuse existing)
    # ============================
    def insert_scan(self, target_name):
        if not self._connect():
            return None

        with self.connection.cursor() as cursor:
            cursor.execute("""
                SELECT scan_id FROM scan
                WHERE target_name=%s
                ORDER BY scan_id DESC
                LIMIT 1
            """, (target_name,))
            existing = cursor.fetchone()

            if existing:
                return existing["scan_id"]

            cursor.execute(
                "INSERT INTO scan (target_name) VALUES (%s)",
                (target_name,)
            )
            scan_id = cursor.lastrowid

        self.connection.commit()
        return scan_id

    # ============================
    # INSERT PACKAGE
    # ============================
    def insert_package(self, package_name, ecosystem=None):
        if not self._connect():
            return None

        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT package_id, ecosystem FROM packages WHERE package_name=%s",
                (package_name,)
            )
            result = cursor.fetchone()

            if result:
                # Correct a wrong stored ecosystem (uploads used to store
                # "pypi" for everything, npm packages included)
                if ecosystem_differs(result["ecosystem"], ecosystem):
                    cursor.execute(
                        "UPDATE packages SET ecosystem=%s WHERE package_id=%s",
                        (ecosystem, result["package_id"])
                    )
                    self.connection.commit()
                return result["package_id"]

            cursor.execute(
                "INSERT INTO packages (package_name, ecosystem) VALUES (%s, %s)",
                (package_name, ecosystem)
            )
            package_id = cursor.lastrowid

        self.connection.commit()
        return package_id

    # ============================
    # INSERT / UPDATE VERSION
    # ============================
    def insert_version(
        self,
        scan_id,
        package_id,
        package_name,
        version,
        status="unknown",
        latest_version=None,
        baseline_status="inactive",
        ecosystem=None
    ):
        """
        Insert or update the one row for (scan_id, package_name). Returns its
        version_id, or None if the database is unavailable. ecosystem
        ("pypi"/"npm"/...) picks the registry; None decides from the name.
        """

        if not self._connect():
            return None

        from datetime import datetime
        now = datetime.now()

        metrics = compute_version_metrics(
            package_name, version, status, latest_version, ecosystem
        )
        status = metrics["status"]
        latest_version = metrics["latest_version"]          # None if unknown
        severity_level = metrics["severity_level"]
        versions_behind = metrics["versions_behind"]
        days_outdated = metrics["days_outdated"]
        days_since_release = metrics["days_since_release"]
        age_tier = metrics["age_tier"]

        with self.connection.cursor() as cursor:

            # One row per package name per scan. Matched by name (not
            # package_id) so rescans without a package_id, and rows whose
            # package_id changed, still update instead of duplicating.
            cursor.execute("""
                SELECT version_id, version_number
                FROM versions
                WHERE package_name=%s AND scan_id=%s
                ORDER BY version_id
                LIMIT 1
            """, (package_name, scan_id))

            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE versions
                    SET package_id=COALESCE(%s, package_id),
                        version_number=%s,
                        status=%s,
                        latest_version=%s,
                        baseline_status=%s,
                        release_date=%s,
                        days_outdated=%s,
                        versions_behind=%s,
                        days_since_release=%s,
                        age_tier=%s,
                        severity_level=%s
                    WHERE version_id=%s
                """, (
                    package_id,
                    version,
                    status,
                    latest_version,
                    baseline_status,
                    now,
                    days_outdated,
                    versions_behind,
                    days_since_release,
                    age_tier,
                    severity_level,
                    existing["version_id"]
                ))

                self.connection.commit()
                return existing["version_id"]

            # ✅ CORRECT INSERT
            cursor.execute("""
                INSERT INTO versions
                (scan_id, package_id, package_name, version_number,
                baseline_status, release_date, status, latest_version,
                days_outdated, versions_behind, days_since_release, age_tier,
                severity_level)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                package_id,
                package_name,
                version,
                baseline_status,
                now,
                status,
                latest_version,
                days_outdated,
                versions_behind,
                days_since_release,
                age_tier,
                severity_level
            ))

            version_id = cursor.lastrowid

        self.connection.commit()
        return version_id

    # ============================
    # SCHEDULED REFRESH OF ONE ROW
    # ============================
    def refresh_version(self, scan_id, package_name, ecosystem=None):
        """
        Re-check one row's latest version and metrics (scheduled job, repair
        script), without ever writing stale data:

          1. re-read the row now (not from an earlier copy of the scan),
          2. compute status/metrics for the version it has *now*
             (compute_version_metrics, the same function every write uses),
          3. write only those computed columns (never version_number,
             package_id or baseline_status), and only if version_number is
             still what was read in step 1. If an upload changed the row
             during the registry lookups, the upload's data is kept.

        ecosystem overrides the stored one (e.g. "none" from the repair).
        Returns "refreshed", "changed" (row changed meanwhile, not written),
        "missing" (no such row) or None (database unavailable).
        """
        if not self._connect():
            return None

        # End any open transaction so the read below sees the latest data
        # (InnoDB keeps one snapshot per transaction)
        self.connection.commit()

        with self.connection.cursor() as cursor:
            cursor.execute("""
                SELECT v.version_id, v.version_number, p.ecosystem
                FROM versions v
                LEFT JOIN packages p ON p.package_id = v.package_id
                WHERE v.scan_id=%s AND v.package_name=%s
                ORDER BY v.version_id
                LIMIT 1
            """, (scan_id, package_name))
            row = cursor.fetchone()

        if not row:
            return "missing"

        metrics = compute_version_metrics(
            package_name, row["version_number"], None, None,
            ecosystem or row["ecosystem"]
        )
        written = self.write_version_metrics(
            row["version_id"], row["version_number"], metrics
        )
        return "refreshed" if written else "changed"

    def write_version_metrics(self, version_id, expected_version, metrics):
        """
        Write the computed columns of one row (compute_version_metrics
        output), only if its version_number is still expected_version.
        Returns True if written, False if the row changed meanwhile.
        """
        if not self._connect():
            return False

        with self.connection.cursor() as cursor:
            cursor.execute("""
                UPDATE versions
                SET status=%s,
                    latest_version=%s,
                    release_date=%s,
                    days_outdated=%s,
                    versions_behind=%s,
                    days_since_release=%s,
                    age_tier=%s,
                    severity_level=%s
                WHERE version_id=%s AND version_number=%s
            """, (
                metrics["status"],
                metrics["latest_version"],
                datetime.now(),
                metrics["days_outdated"],
                metrics["versions_behind"],
                metrics["days_since_release"],
                metrics["age_tier"],
                metrics["severity_level"],
                version_id,
                expected_version,
            ))
            written = cursor.rowcount

        self.connection.commit()
        return bool(written)

    # ============================
    # ROWS ALREADY STORED FOR A SCAN (for uploads)
    # ============================
    def get_scan_rows(self, scan_id):
        """
        {package_name: {"version_number", "status", "ecosystem"}} for every
        row of the scan, read fresh. ecosystem comes from the packages table.
        """
        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT v.package_name, v.version_number, v.status, p.ecosystem
                    FROM versions v
                    LEFT JOIN packages p ON p.package_id = v.package_id
                    WHERE v.scan_id = %s
                """, (scan_id,))
                rows = cursor.fetchall()
        finally:
            conn.close()

        return {
            r["package_name"]: {
                "version_number": r["version_number"],
                "status": r["status"],
                "ecosystem": r["ecosystem"],
            }
            for r in rows
        }

    # ============================
    # INSERT VULNERABILITY (unchanged)
    # ============================
    def insert_vulnerability(self, vuln_id, severity):
        if not self._connect():
            return

        with self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT IGNORE INTO vulnerability (vulnerability_id, severity) VALUES (%s, %s)",
                (vuln_id, severity)
            )

        self.connection.commit()

    # ============================
    # INSERT SCAN RESULT
    # ============================
    def insert_scan_result(self, scan_id, version_id, vuln_id, fixed_version):
        if not self._connect():
            return

        with self.connection.cursor() as cursor:
            cursor.execute("""
                SELECT spr_id FROM scan_results
                WHERE scan_id=%s AND version_id=%s AND vulnerability_id=%s
            """, (scan_id, version_id, vuln_id))

            if cursor.fetchone():
                return

            cursor.execute("""
                INSERT INTO scan_results
                (scan_id, version_id, vulnerability_id, fixed_version)
                VALUES (%s, %s, %s, %s)
            """, (scan_id, version_id, vuln_id, fixed_version))

        self.connection.commit()

    #--------------------------
    def get_all_scans(self):

        if not self._connect():
            return []

        conn = get_new_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT scan_id, target_name, scan_timestamp
            FROM scan
            ORDER BY scan_timestamp DESC
        """)

        results = cursor.fetchall()

        cursor.close()
        conn.close()

        return results

    #Update packages status    
    def update_package_status(self, package_name, latest_version, status):

        if not self._connect():
            return

        with self.connection.cursor() as cursor:

            cursor.execute("""
                SELECT version_id, version_number
                FROM versions
                WHERE package_name=%s
            """, (package_name,))

            rows = cursor.fetchall()

            for row in rows:

                version_id = row["version_id"]
                current_version = row["version_number"]

                # =========================
                # VERSION GAP
                # =========================
                versions_behind = calculate_versions_behind(
                    current_version,
                    latest_version
                )

                # =========================
                # DAYS OUTDATED (fallback)
                # =========================
                days_outdated = 0

                if status == "outdated":
                    try:
                        major = int(str(versions_behind).split(".")[0])
                    except:
                        major = 1

                    days_outdated = max(major * 7, 1)

                cursor.execute("""
                    UPDATE versions
                    SET latest_version=%s,
                        status=%s,
                        release_date=NOW(),
                        days_outdated=%s,
                        versions_behind=%s
                    WHERE version_id=%s
                """, (
                    latest_version,
                    status,
                    days_outdated,
                    versions_behind,
                    version_id
                ))

        self.connection.commit()

    #--------------------------

    #---------------------

    def package_exists(self, package_name):

        if not self._connect():
            return False

        with self.connection.cursor() as cursor:

            cursor.execute(
                "SELECT package_id FROM packages WHERE package_name=%s",
                (package_name,)
            )

            return cursor.fetchone() is not None

    #----------------------------
        
    def get_avg_outdated_days(self, scan_id):
        try:
            cursor = self.connection.cursor()

            #Calculate days difference from monitored_time
            query = """
                SELECT AVG(DATEDIFF(NOW(), monitored_time))
                FROM monitored_packages
                WHERE version_status = 'outdated'
                AND scan_id = %s
            """

            cursor.execute(query, (scan_id,))
            result = cursor.fetchone()

            cursor.close()

            if result and result[0] is not None:
                return round(result[0], 1)  # return whole number days

            return 0

        except Exception as e:
            print("Error in get_avg_outdated_days:", e)
            return 0

    #----------------------------

    def get_trend_data(self, scan_id):

        if not self._connect():
            return []

        with self.connection.cursor(pymysql.cursors.DictCursor) as cursor:

            # Get ALL scan dates (not just outdated)
            cursor.execute("""
                SELECT DATE(release_date) as date,
                    SUM(CASE WHEN status='outdated' THEN 1 ELSE 0 END) as outdated_count
                FROM versions
                WHERE scan_id=%s
                GROUP BY DATE(release_date)
                ORDER BY date
            """, (scan_id,))

            data = cursor.fetchall()

        # ✅ If no data → return default
        if not data:
            return [{"date": "Now", "outdated_count": 0}]

        return data
    
    # ============================
    # GET MONITORED VERSIONS
    # ============================

    def get_monitored_versions(self, scan_id, limit=None, offset=0):
        """
        Version rows of one scan, ordered by package name.

        limit=None (the default) returns every row. Pass limit/offset to get
        one slice of them.
        """

        if not self._connect():
            return []

        conn = get_new_connection()
        cursor = conn.cursor()

        params = [scan_id]
        page_sql = ""
        if limit is not None:
            page_sql = "LIMIT %s OFFSET %s"
            params += [int(limit), int(offset)]

        # version_id breaks ties so slices don't overlap or skip rows
        query = f"""
        SELECT
            v.package_name,
            v.version_number AS current_version,
            v.latest_version,
            v.status AS version_status,
            v.baseline_status,
            v.release_date,
            v.days_outdated,
            v.versions_behind,
            v.severity_level,
            v.days_since_release,
            v.age_tier,
            p.ecosystem
        FROM versions v
        LEFT JOIN packages p ON p.package_id = v.package_id
        WHERE v.scan_id = %s
        ORDER BY v.package_name, v.version_id
        {page_sql}
        """

        cursor.execute(query, params)
        results = cursor.fetchall()

        cursor.close()
        conn.close()

        # ADD THIS BLOCK HERE
        for row in results:

            # ---------------------------
            # HANDLE UP-TO-DATE
            # ---------------------------
            if row["version_status"] == "up_to_date":
                row["severity_level"] = "Not Applicable"
                row["days_outdated"] = 0
                row["versions_behind"] = "0.0.0"
                row["total_gap"] = 0
                continue

            # ---------------------------
            # HANDLE UNKNOWN (lookup failed / can't determine risk)
            # ---------------------------
            if row["version_status"] == "unknown":
                row["severity_level"] = "Unknown"
                # latest_version was stored as the installed version when the
                # lookup failed, so the gap isn't known
                row["versions_behind"] = VERSION_GAP_UNKNOWN
                continue

            # ---------------------------
            # GAP CALCULATION
            # ---------------------------
            # Recomputed from the version strings, so rows saved before the
            # calculate_versions_behind() fix (e.g. "0.-9.5") show correctly
            row["versions_behind"] = calculate_versions_behind(
                row.get("current_version"), row.get("latest_version")
            )

            row["severity_level"] = compute_severity_from_string(
                row.get("versions_behind"),
                row.get("days_outdated")
            )

        # format date safely
        for row in results:
            if row.get("release_date"):
                row["monitored_time"] = row["release_date"].strftime("%Y-%m-%d %H:%M:%S")
            else:
                row["monitored_time"] = "N/A"

        return results

    # ============================
    # PER-SCAN COUNTS (no rows loaded)
    # ============================
    def get_scan_summaries(self):
        """
        Package counts for every scan from one GROUP BY query:
            {scan_id: {"total", "outdated", "up_to_date", "tiers": {tier: n}}}
        tiers has every name in TIER_NAMES plus UNKNOWN_TIER (NULL or an
        unrecognised value). Scans with no versions are left out; use
        empty_scan_summary() for those.
        """

        if not self._connect():
            return {}

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT v.scan_id, v.status, v.age_tier, COUNT(*) AS n
                    FROM versions v
                    JOIN scan s ON s.scan_id = v.scan_id
                    GROUP BY v.scan_id, v.status, v.age_tier
                """)
                rows = cursor.fetchall()
        finally:
            conn.close()

        summaries = {}
        for row in rows:
            summary = summaries.setdefault(row["scan_id"], empty_scan_summary())
            n = int(row["n"])

            summary["total"] += n
            if row["status"] == "outdated":
                summary["outdated"] += n
            elif row["status"] == "up_to_date":
                summary["up_to_date"] += n

            tier = row["age_tier"]
            summary["tiers"][tier if tier in TIER_NAMES else UNKNOWN_TIER] += n

        return summaries

    #=========================================
    def recalculate_metrics_for_scan(self, scan_id):
        """
        Re-check every row of a scan with refresh_version() (live registry
        lookups). Only for background work: the scheduled job and the
        repair script, never a page load.

        Returns a Counter of refresh_version() results.
        """
        from collections import Counter

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT package_name FROM versions WHERE scan_id = %s "
                    "ORDER BY package_name",
                    (scan_id,)
                )
                names = [r["package_name"] for r in cursor.fetchall()]
        finally:
            conn.close()

        results = Counter()
        for name in names:
            try:
                results[self.refresh_version(scan_id, name)] += 1
            except Exception as e:
                print("Refresh failed:", name, e)
                results["error"] += 1

        return results

    #--------------------------------------
    def calculate_structured_gap(self, current, versions):
        try:
            from packaging import version as v

            current_v = v.parse(str(current))

            parsed_versions = []
            for ver in versions:
                try:
                    parsed_versions.append(v.parse(ver))
                except:
                    continue

            parsed_versions.sort()

            # find index
            current_index = None
            for i, pv in enumerate(parsed_versions):
                if pv >= current_v:
                    current_index = i
                    break

            if current_index is None:
                return "0.0.0"

            future_versions = parsed_versions[current_index + 1:]

            major = minor = patch = 0
            prev = parsed_versions[current_index]

            for ver in future_versions:
                if ver.major > prev.major:
                    major += 1
                elif ver.minor > prev.minor:
                    minor += 1
                elif ver.micro > prev.micro:
                    patch += 1

                prev = ver

            return f"{major}.{minor}.{patch}"

        except Exception as e:
            print("GAP ERROR:", e)
            return "0.0.0"

    #----------------------------------------
    def clean_dataset(self):

        if not self._connect():
            return

        with self.connection.cursor() as cursor:

            # Remove duplicates
            cursor.execute("""
                DELETE v1 FROM versions v1
                INNER JOIN versions v2
                WHERE v1.version_id > v2.version_id
                AND v1.scan_id = v2.scan_id
                AND v1.package_name = v2.package_name
            """)

            # Fix NULL values
            cursor.execute("""
                UPDATE versions
                SET days_outdated = 0
                WHERE days_outdated IS NULL
            """)

            cursor.execute("""
                UPDATE versions
                SET versions_behind = '0.0.0'
                WHERE versions_behind IS NULL
            """)

        self.connection.commit()

    #------------------------------
    def compute_features(self):

        if not self._connect():
            return

        with self.connection.cursor() as cursor:

            cursor.execute("""
                UPDATE versions
                SET severity_level = 'Low'
            """)

        self.connection.commit()

    #----------------------------------
    def get_distribution_data(self):

        if not self._connect():
            return [], []

        with self.connection.cursor() as cursor:

            cursor.execute("""
                SELECT versions_behind
                FROM versions
            """)

            rows = cursor.fetchall()

        # ============================
        # NEW CATEGORY COUNTS
        # ============================

        up_to_date = 0
        low = 0
        medium = 0
        high = 0

        for row in rows:
            gap = row.get("versions_behind")
            gap = str(gap) if gap else "0.0.0"

            try:
                major = int(str(gap).split(".")[0])
            except:
                major = 0

            if major == 0:
                up_to_date += 1
            elif major <= 4:
                low += 1
            elif major <= 9:
                medium += 1
            else:
                high += 1

        labels = ["Up-to-date", "Low (1–4)", "Medium (5–9)", "High (10+)"]
        values = [up_to_date, low, medium, high]

        return labels, values

    #----------------------------------------
    #----------------------------------------
    @staticmethod
    def _package_filters(older_than_days=None, age_tier=None, review_status=None):
        """
        WHERE clause + params shared by the /packages list and its count.
        Both queries LEFT JOIN package_reviews r (no row = "Open").
        """
        clauses = []
        params = []

        if older_than_days is not None:
            clauses.append("v.days_since_release > %s")
            params.append(older_than_days)

        if age_tier == "unknown":
            clauses.append("v.age_tier IS NULL")
        elif age_tier in TIER_NAMES:
            clauses.append("v.age_tier = %s")
            params.append(age_tier)

        if review_status in REVIEW_STATUSES:
            clauses.append("COALESCE(r.status, 'Open') = %s")
            params.append(review_status)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def get_packages_paginated(self, limit, offset, older_than_days=None,
                               age_tier=None, sort_by_tier=False,
                               review_status=None):
        """
        older_than_days: only rows whose installed version is older than this.
        age_tier:        only rows in this tier ("unknown" = no tier).
        sort_by_tier:    Abandoned first, then Stale, Aging, Fresh, unknown.
        review_status:   only rows with this review status (one of REVIEW_STATUSES).
        """

        if not self._connect():
            return []

        from db_storage import compute_severity_from_string

        conn = get_new_connection()
        cursor = conn.cursor()

        where, params = self._package_filters(older_than_days, age_tier, review_status)

        order_by = "v.release_date DESC"
        if sort_by_tier:
            # FIELD() is 0 for NULL/unlisted, so those sort last via the "= 0" key
            placeholders = ", ".join(["%s"] * len(TIER_NAMES))
            order_by = (
                f"FIELD(v.age_tier, {placeholders}) = 0, "
                f"FIELD(v.age_tier, {placeholders}), "
                "v.days_since_release DESC, v.release_date DESC"
            )
            params += TIER_NAMES + TIER_NAMES

        cursor.execute(f"""
            SELECT
                v.package_name,
                v.version_number AS current_version,
                v.latest_version,
                v.status AS version_status,
                v.days_outdated,
                v.versions_behind,
                v.days_since_release,
                v.age_tier,
                v.release_date,
                s.target_name as repo,
                v.package_id,
                COALESCE(r.status, 'Open') AS review_status,
                r.reviewer,
                r.reviewed_at,
                r.note AS review_note
            FROM versions v
            JOIN scan s ON v.scan_id = s.scan_id
            LEFT JOIN package_reviews r ON r.package_id = v.package_id
            {where}
            ORDER BY {order_by}
            LIMIT %s OFFSET %s
        """, (*params, limit, offset))

        results = cursor.fetchall()

        cursor.close()
        conn.close()

        for row in results:

            # DATE FORMAT
            if row.get("release_date"):
                row["scan_date"] = row["release_date"].strftime("%Y-%m-%d %H:%M:%S")
            else:
                row["scan_date"] = "N/A"

            # SAFE DEFAULTS
            row["days_outdated"] = row.get("days_outdated") or 0
            row["version_status"] = row.get("version_status") or "unknown"

            # "Version Behind", recomputed from the version strings so rows
            # saved before the calculate_versions_behind() fix (e.g. "0.-9.5")
            # show correctly. When the latest-version lookup failed,
            # latest_version was stored as the installed version, so the gap
            # is not known.
            if row["version_status"] == "unknown":
                row["versions_behind"] = VERSION_GAP_UNKNOWN
            else:
                row["versions_behind"] = calculate_versions_behind(
                    row.get("current_version"), row.get("latest_version")
                )

            # ✅ FINAL SEVERITY (uses the corrected versions_behind)
            if row["version_status"] == "up_to_date":
                row["severity_level"] = "Not Applicable"
            elif row["version_status"] == "unknown":
                row["severity_level"] = "Unknown"
            else:
                row["severity_level"] = compute_severity_from_string(
                    row.get("versions_behind"),
                    row.get("days_outdated")
                )

        return results

    #-----------------------------------------
    def get_total_packages(self, older_than_days=None, age_tier=None,
                           review_status=None):

        if not self._connect():
            return 0

        # Same JOIN + filters as get_packages_paginated so page counts line up
        where, params = self._package_filters(older_than_days, age_tier, review_status)
        query = f"""
            SELECT COUNT(*) as total
            FROM versions v
            JOIN scan s ON v.scan_id = s.scan_id
            LEFT JOIN package_reviews r ON r.package_id = v.package_id
            {where}
        """

        with self.connection.cursor() as cursor:
            cursor.execute(query, params)
            result = cursor.fetchone()

        return result["total"] if result else 0

    #-----------------------------------------
    def get_settings(self):
        """All settings as a dict of strings, with defaults for missing keys."""

        settings = dict(DEFAULT_SETTINGS)

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT setting_key, setting_value FROM settings")
                for row in cursor.fetchall():
                    settings[row["setting_key"]] = row["setting_value"]
        finally:
            conn.close()

        return settings

    def save_settings(self, values):

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                for key, value in values.items():
                    cursor.execute("""
                        INSERT INTO settings (setting_key, setting_value)
                        VALUES (%s, %s)
                        ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
                    """, (key, str(value)))
            conn.commit()
        finally:
            conn.close()

    #-----------------------------------------
    # PACKAGE REVIEWS (management check mark)
    #-----------------------------------------
    # Rows in package_reviews / package_review_history are never deleted;
    # every save is an upsert plus one history row.
    def save_review(self, package_id, status, reviewer, note):
        """
        Set the review of a package and log the change, in one transaction.
        status must be one of REVIEW_STATUSES (validated by the caller).
        A package with no review row gets one. Every save is logged, even a
        note-only change. Returns False if the package does not exist.
        """

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT package_id FROM packages WHERE package_id = %s",
                    (package_id,)
                )
                if cursor.fetchone() is None:
                    return False

                # Lock the row so two saves can't both read the same old_status
                cursor.execute(
                    "SELECT status FROM package_reviews WHERE package_id = %s FOR UPDATE",
                    (package_id,)
                )
                existing = cursor.fetchone()
                old_status = existing["status"] if existing else None

                cursor.execute("""
                    INSERT INTO package_reviews
                        (package_id, status, reviewer, note, reviewed_at)
                    VALUES (%s, %s, %s, %s, NOW())
                    ON DUPLICATE KEY UPDATE
                        status = VALUES(status),
                        reviewer = VALUES(reviewer),
                        note = VALUES(note),
                        reviewed_at = NOW()
                """, (package_id, status, reviewer, note))

                cursor.execute("""
                    INSERT INTO package_review_history
                        (package_id, old_status, new_status, reviewer, note)
                    VALUES (%s, %s, %s, %s, %s)
                """, (package_id, old_status, status, reviewer, note))

            conn.commit()
            return True
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_review(self, package_id):
        """The package's name and current review (status "Open" if none), or None."""

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT p.package_id, p.package_name,
                           COALESCE(r.status, 'Open') AS status,
                           r.reviewer, r.reviewed_at, r.note
                    FROM packages p
                    LEFT JOIN package_reviews r ON r.package_id = p.package_id
                    WHERE p.package_id = %s
                """, (package_id,))
                return cursor.fetchone()
        finally:
            conn.close()

    def get_review_history(self, package_id):
        """Every review change for a package, newest first."""

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT old_status, new_status, reviewer, note, changed_at
                    FROM package_review_history
                    WHERE package_id = %s
                    ORDER BY changed_at DESC, history_id DESC
                """, (package_id,))
                return cursor.fetchall()
        finally:
            conn.close()

    def get_review_status_counts(self):
        """{status: number of packages} for every status in REVIEW_STATUSES."""

        counts = {status: 0 for status in REVIEW_STATUSES}

        conn = get_new_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    SELECT COALESCE(r.status, 'Open') AS status, COUNT(*) AS n
                    FROM packages p
                    LEFT JOIN package_reviews r ON r.package_id = p.package_id
                    GROUP BY COALESCE(r.status, 'Open')
                """)
                for row in cursor.fetchall():
                    if row["status"] in counts:
                        counts[row["status"]] += int(row["n"])
        finally:
            conn.close()

        return counts

# ============================
# WRITE A LIST OF PACKAGES (with honest counts)
# ============================
def write_packages(db, packages, write_one, on_result=None):
    """
    Call write_one(pkg) for each package, retrying once if the database
    connection was lost. write_one returns a result (e.g. the version_id),
    or None if nothing was written.

    on_result(pkg, result), if given, is called after every package, with
    result None for a failure (used for upload counts and progress).

    Returns (inserted_count, failed_names). Every failure is printed with
    its traceback; none are skipped silently.
    """
    inserted = 0
    failed = []

    for pkg in packages:
        name = pkg.get("name")
        try:
            result = db.with_reconnect(write_one, pkg)
        except Exception:
            print(f"Failed to save package {name}:")
            traceback.print_exc()
            result = None
        else:
            if result is None:
                print(f"Failed to save package {name}: nothing was written")

        if result is None:
            failed.append(name)
        else:
            inserted += 1

        if on_result is not None:
            on_result(pkg, result)

    return inserted, failed

# ============================
# GLOBAL INSTANCE
# ============================
_db_storage = None

def get_db_storage():
    global _db_storage
    if _db_storage is None:
        _db_storage = DatabaseStorage()
    return _db_storage

#--------------------------------
# ============================
# RUN CLEANING PIPELINE
# ============================

if __name__ == "__main__":

    print("\n Running Data Cleaning + Feature Engineering...\n")

    db = get_db_storage()

    db.clean_dataset()
    print(" Cleaning completed")

    db.compute_features()
    print(" Feature engineering completed")

    print("\ Database is ready for UI\n")