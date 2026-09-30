#!/usr/bin/env python
# coding: utf-8

import pymysql
from typing import Optional
from datetime import datetime
from version_monitor import get_package_release_info
from version_monitor import get_commit_date
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

def detect_package_source(package_name):
    if "/" in package_name:
        return "github"
    return "pypi"


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
def calculate_versions_behind(current, latest):
    try:
        cur = [int(x) for x in current.replace("v", "").split(".")]
        lat = [int(x) for x in latest.replace("v", "").split(".")]

        # normalize to 3 parts
        while len(cur) < 3:
            cur.append(0)
        while len(lat) < 3:
            lat.append(0)

        major = lat[0] - cur[0]
        minor = lat[1] - cur[1]
        patch = lat[2] - cur[2]

        # normalize negatives
        if patch < 0:
            patch += 10
            minor -= 1

        if minor < 0:
            minor += 10
            major -= 1

        return f"{major}.{minor}.{patch}"

    except:
        return "0.0.0"

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

#----------------------------------------
def compute_severity_from_string(versions_behind, days_outdated):
    try:
        gap = str(versions_behind or "0.0.0")
        parts = gap.split(".")

        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0

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

#=========================================

class DatabaseStorage:

    def __init__(self):
        self.connection: Optional[pymysql.Connection] = None

    def _connect(self):
        if self.connection:
            try:
                self.connection.ping(reconnect=False)
                return True
            except:
                self.connection = None

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
                "SELECT package_id FROM packages WHERE package_name=%s",
                (package_name,)
            )
            result = cursor.fetchone()

            if result:
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
        baseline_status="inactive"
    ):

        if not self._connect():
            return None

        from datetime import datetime
        now = datetime.now()

        # ============================
        # GET REAL DATA FROM API
        # ============================

        from version_monitor import get_latest_version

        try:
            #latest_version_api = get_latest_version(package_name, "pypi")
            #latest_version_api = get_latest_version(package_name, "python")
            source = detect_package_source(package_name)

            if source == "pypi":
                latest_version_api = get_latest_version(package_name, "python")
            elif source == "github":
                latest_version_api = get_latest_version(package_name, "github-action")
            else:
                latest_version_api = None
        except:
            latest_version_api = version

        if latest_version_api and latest_version_api != version:
            latest_version = latest_version_api
        elif not latest_version:
            latest_version = version

        # ============================
        # REAL VERSION + TIME CALCULATION
        # ============================

        from datetime import datetime
        from version_monitor import get_package_release_info
        

        versions_behind = "0.0.0"
        days_outdated = 0

        try:
            #releases = get_package_release_info(package_name)
            source = detect_package_source(package_name)

            if source == "pypi":
                releases = get_package_release_info(package_name)
            elif source == "github":
                from version_monitor import get_github_release_info
                releases = get_github_release_info(package_name)
                #releases = get_github_releases(package_name)
            else:
                releases = {}

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
                        # PYPI
                        # ---------------------------
                        if source == "pypi":
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
                # FORCE fallback if missing
                if not date_current:
                    date_current = get_commit_date(package_name, matched_current)

                if not date_latest:
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

        with self.connection.cursor() as cursor:

            # Check existing
            cursor.execute("""
                SELECT version_id, version_number
                FROM versions
                WHERE package_id=%s AND scan_id=%s
                LIMIT 1
            """, (package_id, scan_id))

            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE versions
                    SET version_number=%s,
                        status=%s,
                        latest_version=%s,
                        baseline_status=%s,
                        release_date=%s,
                        days_outdated=%s,
                        versions_behind=%s
                    WHERE version_id=%s
                """, (
                    version,
                    status,
                    latest_version if latest_version else version,
                    baseline_status,
                    now,
                    days_outdated,
                    versions_behind,
                    existing["version_id"]
                ))

                self.connection.commit()
                return existing["version_id"]

            # ✅ CORRECT INSERT
            cursor.execute("""
                INSERT INTO versions
                (scan_id, package_id, package_name, version_number,
                baseline_status, release_date, status, latest_version,
                days_outdated, versions_behind)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                package_id,
                package_name,
                version,
                baseline_status,
                now,
                status,
                latest_version if latest_version else version,
                days_outdated,
                versions_behind
            ))

            version_id = cursor.lastrowid

        self.connection.commit()
        return version_id

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

    def get_monitored_versions(self, scan_id):

        if not self._connect():
            return []

        conn = get_new_connection()
        cursor = conn.cursor()

        query = """
        SELECT
            v.package_name,
            v.version_number AS current_version,
            v.latest_version,
            v.status AS version_status,
            v.baseline_status,
            v.release_date,
            v.days_outdated,
            v.versions_behind,
            v.severity_level 
        FROM versions v
        WHERE v.scan_id = %s
        ORDER BY v.package_name LIMIT 500
        """

        cursor.execute(query, (scan_id,))
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
                continue

            # ---------------------------
            # GAP CALCULATION
            # ---------------------------
            gap = str(row.get("versions_behind") or "0.0.0")

            try:
                parts = [int(x) for x in gap.split(".")]
                major = parts[0]
                minor = parts[1] if len(parts) > 1 else 0
                patch = parts[2] if len(parts) > 2 else 0
            except:
                major = minor = patch = 0

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

            # REAL CALCULATION
            current = row.get("current_version")
            latest = row.get("latest_version")
            status = row.get("version_status")

            if row["version_status"] != "up_to_date":
                row["versions_behind"] = row.get("versions_behind") or "0.0.0"

        return results
    
    #=========================================
    def recalculate_metrics_for_scan(self, scan_id):

        from version_monitor import (
            get_package_release_info,
            get_github_release_info,
            get_commit_date,
            compare_versions
        )

        if not self._connect():
            return

        conn = self.connection
        conn.ping(reconnect=True)
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        cursor.execute("""
            SELECT version_id, package_name, version_number, latest_version
            FROM versions
            WHERE scan_id = %s
        """, (scan_id,))

        rows = cursor.fetchall()

        for row in rows:
            try:
                version_id = row["version_id"]
                package = row["package_name"]
                current = row["version_number"]
                latest = row["latest_version"]

                # ============================
                # STATUS
                # ============================
                status = compare_versions(current, latest)

                versions_behind = "0.0.0"
                days_outdated = 0

                try:
                    # ---------------------------
                    # Detect source
                    # ---------------------------
                    source = detect_package_source(package)

                    if source == "pypi":
                        releases = get_package_release_info(package)
                    elif source == "github":
                        releases = get_github_release_info(package)
                    else:
                        releases = {}

                    if releases:

                        # ---------------------------
                        # CLEAN + SORT VERSIONS
                        # ---------------------------
                        safe_versions = []
                        for ver in releases.keys():
                            try:
                                v.parse(ver)
                                safe_versions.append(ver)
                            except:
                                continue

                        versions = sorted(safe_versions, key=lambda x: v.parse(x))

                        matched_version, _ = find_closest_version(current, versions)

                        # ---------------------------
                        # VERSION GAP
                        # ---------------------------
                        if latest and latest != current:
                            versions_behind = calculate_versions_behind(current, latest)
                        else:
                            versions_behind = "0.0.0"

                        # ---------------------------
                        # DAYS OUTDATED
                        # ---------------------------
                        if status == "up_to_date":
                            days_outdated = 0
                        else:
                            try:
                                date_current = None
                                date_latest = None

                                if source == "pypi":
                                    date_current = releases.get(current)
                                    date_latest = releases.get(latest)

                                elif source == "github":
                                    if not matched_version:
                                        matched_version = current

                                    date_current = get_commit_date(package, matched_version)
                                    date_latest = get_commit_date(package, latest)

                                if date_current and date_latest:
                                    d1 = datetime.strptime(str(date_current)[:10], "%Y-%m-%d")
                                    d2 = datetime.strptime(str(date_latest)[:10], "%Y-%m-%d")
                                    days_outdated = max((d2 - d1).days, 0)

                                else:
                                    # ============================
                                    # 🔥 TIME DECAY FALLBACK MODEL
                                    # ============================
                                    try:
                                        parts = [int(x) for x in str(versions_behind).split(".")]
                                        major = parts[0]
                                        minor = parts[1] if len(parts) > 1 else 0
                                        patch = parts[2] if len(parts) > 2 else 0

                                        # realistic estimation
                                        days_outdated = (major * 180) + (minor * 30) + (patch * 7)

                                    except:
                                        days_outdated = 30  # minimal fallback

                            except Exception as e:
                                print("Date calculation failed:", package, e)
                                days_outdated = 0

                except Exception as e:
                    print("Advanced calculation failed:", package, e)

                # ---------------------------
                # SAFETY CLEANUP
                # ---------------------------
                if not versions_behind:
                    versions_behind = "0.0.0"

                if days_outdated is None or days_outdated < 0:
                    days_outdated = 0

                # ============================
                # 🔥 SEVERITY (AUTO)
                # ============================
                if status == "up_to_date":
                    severity = "low"
                else:
                    severity = compute_severity_from_string(
                        versions_behind,
                        days_outdated
                    )

                # ============================
                # 🔥 FINAL UPDATE (ALL COLUMNS)
                # ============================
                cursor.execute("""
                    UPDATE versions
                    SET latest_version=%s,
                        status=%s,
                        days_outdated=%s,
                        versions_behind=%s,
                        severity_level=%s,
                        release_date=NOW()
                    WHERE version_id=%s
                """, (
                    latest,
                    status,
                    days_outdated,
                    versions_behind,
                    severity,
                    version_id
                ))

            except Exception as e:
                if "timeout" in str(e).lower():
                    print("API timeout:", package)
                else:
                    pass
                continue

        conn.commit()

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
    def get_packages_paginated(self, limit, offset):

        if not self._connect():
            return []

        from db_storage import compute_severity_from_string

        conn = get_new_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                v.package_name,
                v.version_number AS current_version,
                v.latest_version,
                v.status AS version_status,
                v.days_outdated,
                v.versions_behind,
                v.release_date,
                s.target_name as repo
            FROM versions v
            JOIN scan s ON v.scan_id = s.scan_id
            ORDER BY v.release_date DESC
            LIMIT %s OFFSET %s
        """, (limit, offset))

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
            row["versions_behind"] = row.get("versions_behind") or "0.0.0"
            row["version_status"] = row.get("version_status") or "unknown"

            # ✅ FINAL SEVERITY
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
    def get_total_packages(self):

        if not self._connect():
            return 0

        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) as total FROM versions")
            result = cursor.fetchone()

        return result["total"] if result else 0

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