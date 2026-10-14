# sbom-tools/upload_jobs.py
#
# Processing for /upload-sbom, run in a background thread so the request
# returns at once and the monitor page can show progress.
#
#   parse_upload()     CSV/JSON bytes -> package dicts, with the real ecosystem
#   dedupe_packages()  one entry per package name (the last occurrence wins)
#   upload_action()    insert / update / skip for one package
#   process_upload()   writes the packages and records progress in JOBS
#
# Safe to repeat: re-uploading a file updates rows in place (one row per
# package name per scan) and skips packages already stored with the same
# version, so a re-upload after an interruption only processes the rest.

import csv
import json
import threading
import traceback
from datetime import datetime

from version_monitor import ECOSYSTEM_ALIASES, NO_REGISTRY, package_ecosystem

# Statuses that mean a stored row is complete; "unknown" rows are retried
DONE_STATUSES = ("up_to_date", "outdated")

FAILED_NAMES_KEPT = 20


# ============================
# PARSING
# ============================
def _known_hint(*values):
    """First value that names a known ecosystem ("npm", "pypi", "python"...)."""
    for value in values:
        if str(value or "").strip().lower() in ECOSYSTEM_ALIASES:
            return value
    return None


def parse_upload(filename, raw):
    """
    Package dicts {"name", "version", "ecosystem", "risk_level"} from an
    uploaded .csv or .json file. Rows without a name or version are left
    out. Raises ValueError for another file type or invalid JSON.
    """
    filename = filename.lower()
    packages = []

    if filename.endswith(".csv"):
        content = raw.decode("utf-8-sig").strip()

        for row in csv.DictReader(content.splitlines()):
            # Accept either naming convention for the name/version columns
            name = (row.get("package_name") or row.get("name") or "").strip()
            version = (row.get("current_version") or row.get("version") or "").strip()
            risk_level = (row.get("risk_level") or row.get("severity") or "").strip()

            if name and version:
                # registry_ecosystem is the registry that actually has the
                # package; ecosystem may only say "pypi_or_npm". not_found
                # means no registry has it: "none", never looked up (a
                # same-named PyPI project would be a different package).
                registry = (row.get("registry_ecosystem") or "").strip().lower()
                if registry == "not_found":
                    ecosystem = NO_REGISTRY
                else:
                    hint = _known_hint(row.get("registry_ecosystem"), row.get("ecosystem"))
                    ecosystem = package_ecosystem(name, hint)
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "risk_level": risk_level,
                })

    elif filename.endswith(".json"):
        try:
            data = json.loads(raw)
        except ValueError as e:
            raise ValueError(f"Invalid SBOM file: {e}") from e

        raw_packages = (
            data.get("packages")
            or data.get("components")
            or data.get("artifacts")
            or []
        )

        for pkg in raw_packages:
            name = pkg.get("package") or pkg.get("name")
            version = pkg.get("version") or pkg.get("versionInfo")
            purl = pkg.get("purl") or ""

            # fallback from purl
            if not name and purl:
                name = purl.split("/")[-1].split("@")[0]

            if not version and "@" in purl:
                version = purl.split("@")[-1]

            if name and version:
                # "pkg:npm/..." -> npm; else the report's "type" (python/npm/...)
                purl_type = purl[4:].split("/")[0] if purl.startswith("pkg:") else None
                name = str(name).strip()
                packages.append({
                    "name": name,
                    "version": str(version).strip(),
                    "ecosystem": package_ecosystem(name, _known_hint(purl_type, pkg.get("type"))),
                })

    else:
        raise ValueError(f"Unsupported file type: {filename}")

    return packages


def name_key(name):
    """Package names compare like MySQL's default collation (case-insensitive)."""
    return str(name).strip().casefold()


def dedupe_packages(packages):
    """
    One entry per package name, in order of first appearance, holding the
    LAST occurrence (a later row overrides an earlier one, as before).
    """
    by_name = {}
    for pkg in packages:
        by_name[name_key(pkg["name"])] = pkg   # keeps the first position
    return list(by_name.values())


def upload_action(stored, pkg):
    """
    "insert" (no row yet), "skip" (row already has this version and the same
    ecosystem, and its status is final: up_to_date/outdated, or unknown for
    a package with no registry) or "update".
    """
    from db_storage import ecosystem_differs

    if stored is None:
        return "insert"
    final = (stored["status"] in DONE_STATUSES
             or (pkg["ecosystem"] == NO_REGISTRY and stored["status"] == "unknown"))
    if (stored["version_number"] == pkg["version"]
            and final
            and not ecosystem_differs(stored["ecosystem"], pkg["ecosystem"])):
        return "skip"
    return "update"


# ============================
# JOB REGISTRY (in memory; lost on restart, but the rows are not)
# ============================
class UploadJobs:
    """Progress of the latest upload per scan_id. Thread-safe."""

    ACTIVE = ("running", "finishing")

    def __init__(self):
        self._lock = threading.Lock()
        self._jobs = {}

    def start(self, scan_id, **info):
        """
        Register a new job. Returns (job, True), or (existing job, False) if
        this scan is already being processed (it is never processed twice
        at the same time).
        """
        with self._lock:
            current = self._jobs.get(scan_id)
            if current and current["state"] in self.ACTIVE:
                return dict(current), False

            job = {
                "scan_id": scan_id,
                "state": "running",
                "csv_rows": 0,
                "distinct": 0,
                "processed": 0,
                "inserted": 0,
                "updated": 0,
                "skipped": 0,
                "failed": 0,
                "failed_names": [],
                "current": None,
                "error": None,
                "started_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": None,
            }
            job.update(info)
            self._jobs[scan_id] = job
            return dict(job), True

    def update(self, scan_id, **fields):
        with self._lock:
            if scan_id in self._jobs:
                self._jobs[scan_id].update(fields)

    def record(self, scan_id, name, outcome):
        """Count one package: outcome is inserted/updated/skipped, None = failed."""
        with self._lock:
            job = self._jobs.get(scan_id)
            if job is None:
                return
            job["processed"] += 1
            if outcome in ("inserted", "updated", "skipped"):
                job[outcome] += 1
            else:
                job["failed"] += 1
                if len(job["failed_names"]) < FAILED_NAMES_KEPT:
                    job["failed_names"].append(name)

    def finish(self, scan_id, error=None):
        self.update(
            scan_id,
            state="error" if error else "done",
            error=error,
            current=None,
            finished_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

    def get(self, scan_id):
        with self._lock:
            job = self._jobs.get(scan_id)
            return None if job is None else {**job, "failed_names": list(job["failed_names"])}

    def is_active(self, scan_id):
        job = self.get(scan_id)
        return bool(job and job["state"] in self.ACTIVE)


JOBS = UploadJobs()


# ============================
# PROCESSING
# ============================
def process_upload(db, scan_id, packages, jobs=None):
    """
    Write the (already de-duplicated) packages for scan_id, recording
    progress and inserted/updated/skipped/failed counts in jobs (default:
    the module's JOBS).
    """
    from db_storage import write_packages

    jobs = jobs if jobs is not None else JOBS

    try:
        stored = {name_key(n): row for n, row in db.get_scan_rows(scan_id).items()}

        def save(pkg):
            """Returns "inserted"/"updated"/"skipped", or None if not written."""
            name, version, ecosystem = pkg["name"], pkg["version"], pkg["ecosystem"]
            jobs.update(scan_id, current=name)

            existing = stored.get(name_key(name))
            action = upload_action(existing, pkg)
            if action == "skip":
                return "skipped"   # no registry lookups for these

            package_id = db.insert_package(name, ecosystem)

            # insert_version looks up the latest version (none for
            # ecosystem "none") and derives status, tier and metrics
            version_id = db.insert_version(
                scan_id, package_id, name, version, None, None,
                "active", ecosystem=ecosystem
            )
            if version_id is None:
                return None
            return "inserted" if action == "insert" else "updated"

        def on_result(pkg, outcome):
            jobs.record(scan_id, pkg["name"], outcome)

        write_packages(db, packages, save, on_result)

        job = jobs.get(scan_id) or {}
        print(f"Upload scan {scan_id}: {job.get('distinct')} distinct packages "
              f"({job.get('csv_rows')} rows): {job.get('inserted')} inserted, "
              f"{job.get('updated')} updated, {job.get('skipped')} skipped, "
              f"{job.get('failed')} failed")

        # No whole-scan recalculation here: every written row already got
        # its status, tier and metrics from compute_version_metrics, and
        # skipped rows are unchanged. The scheduled job refreshes them all.
        jobs.finish(scan_id)

    except Exception as e:
        print(f"Upload processing for scan {scan_id} failed:")
        traceback.print_exc()
        jobs.finish(scan_id, error=str(e))
