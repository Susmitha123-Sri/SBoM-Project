from __future__ import annotations

'''Added'''
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime

import importlib
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set
import json

from flask import Flask, jsonify, render_template, request, send_from_directory, redirect
import requests

from dotenv import load_dotenv
import os

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
 
REPO_ROOT = Path(__file__).resolve().parent
SBOM_MODULE_PATH = REPO_ROOT / "sbom-tools"
if str(SBOM_MODULE_PATH) not in sys.path:
    sys.path.insert(0, str(SBOM_MODULE_PATH))

# Lazy import - only import when needed to speed up app startup
_config = None
_scanner_class = None

def get_config():
    """Lazy import of Config class"""
    global _config
    if _config is None:
        from sbom import Config  # type: ignore
        _config = Config
    return _config

def get_scanner_class():
    """Lazy import of SBOMScanner class"""
    global _scanner_class
    if _scanner_class is None:
        from sbom import SBOMScanner  # type: ignore
        # Verify SBOMScanner has required methods
        if not hasattr(SBOMScanner, 'get_report'):
            raise RuntimeError("SBOMScanner class is missing 'get_report' method. Please check sbom.py file.")
        _scanner_class = SBOMScanner
    return _scanner_class


@dataclass
class TreeNode:
    name: str
    children: List["TreeNode"]


def build_dependency_tree(graph: List[Dict[str, str]]) -> List[Dict[str, object]]:
    """
    Build a dependency tree structure from the flat dependency graph.
    Returns a list of root nodes with children in recursive dictionaries.
    """
    children_map: Dict[str, List[str]] = {}
    child_counts: Dict[str, int] = {}

    for edge in graph:
        parent = edge.get("parent")
        child = edge.get("child")
        if not parent or not child:
            continue

        children_map.setdefault(parent, []).append(child)
        child_counts[child] = child_counts.get(child, 0) + 1
        child_counts.setdefault(parent, child_counts.get(parent, 0))

    all_nodes = set(children_map.keys()) | set(child_counts.keys())
    roots = [node for node in all_nodes if child_counts.get(node, 0) == 0]
    if not roots and all_nodes:
        roots = sorted(all_nodes)

    def build_node(name: str, visited: Set[str]) -> TreeNode:
        if name in visited:
            return TreeNode(name=name, children=[])

        visited = set(visited)
        visited.add(name)

        children = [
            build_node(child, visited)
            for child in sorted(children_map.get(name, []))
        ]
        return TreeNode(name=name, children=children)

    tree = [build_node(root, set()) for root in sorted(roots)]
    return [
        {"name": node.name, "children": _serialize_child_nodes(node.children)}
        for node in tree
    ]


def _serialize_child_nodes(children: List[TreeNode]) -> List[Dict[str, object]]:
    serialized: List[Dict[str, object]] = []
    for child in children:
        serialized.append(
            {"name": child.name, "children": _serialize_child_nodes(child.children)}
        )
    return serialized

def run_in_background(target, *args):
    """Run target(*args) in a daemon thread (tests replace this)."""
    threading.Thread(target=target, args=args, daemon=True).start()


# Only one monitoring run at a time (scheduler, startup scan, /run-monitor)
_monitor_lock = threading.Lock()


def auto_monitor_versions():
    """
    Background job: re-check every row of every scan against the live
    registries. Runs from the scheduler, the startup scan and /run-monitor
    (which starts it in the background); never as part of a page load.
    """
    if not _monitor_lock.acquire(blocking=False):
        print("Auto monitoring already running; skipped this run.")
        return
    try:
        _auto_monitor_versions()
    finally:
        _monitor_lock.release()


def _auto_monitor_versions():

    from collections import Counter
    from db_storage import get_db_storage
    from version_monitor import (get_latest_version, package_type, clear_caches,
                                 registries_reachable)

    print("\n======================================")
    print("Auto Version Monitoring Started:", datetime.now())
    print("======================================")

    db = get_db_storage()

    # Latest versions are looked up afresh on every run
    clear_caches()

    # Offline: record it and refresh nothing (failed lookups would only be
    # skipped, and the day's snapshot would repeat stale values)
    if not registries_reachable():
        print("PyPI or npm is not reachable: nothing refreshed, run recorded as offline.")
        db.record_failed_run("monitor", "offline")
        return

    scans = db.get_all_scans()

    if not scans:
        print("No scans found. Nothing to monitor.")
        return

    existing_packages = {}
    totals = Counter()

    for scan in scans:

        scan_id = scan["scan_id"]

        # One pass per row through refresh_version(): re-reads the row,
        # recomputes status/tier/metrics, never writes back a stale copy
        results = db.recalculate_metrics_for_scan(scan_id)
        totals.update(results)
        print(f"Scan {scan_id}: {dict(results)}")

        existing_packages = {
            p["package_name"]: p.get("ecosystem")
            for p in db.get_monitored_versions(scan_id)
        }

    print("Auto monitoring finished:", datetime.now())

    # Detect new packages (not in baseline)

    # Example: you can fetch from PyPI or repo (simplified demo)

    for package_name, ecosystem in existing_packages.items():

        # Checked first so known packages cost no registry lookup; packages
        # with no registry (ecosystem "none") are never looked up
        if db.package_exists(package_name):
            continue

        kind = package_type(package_name, ecosystem)
        if kind is None:
            continue

        latest_version = get_latest_version(package_name, kind)

        if not latest_version:
            continue

        # If package not in DB → insert as inactive baseline
        package_id = db.insert_package(package_name)

        db.insert_version(
            scan_id,
            package_id,
            package_name,
            latest_version,
            None,               # status derived (installed == latest)
            latest_version,
            "active",
            ecosystem=ecosystem
        )

        print("New package detected:", package_name)

    # Today's snapshot of every row (at most one per date)
    snapshot = db.write_daily_snapshot(trigger_source="monitor",
                                       lookup_failed=totals["lookup_failed"])
    print("Daily snapshot:", snapshot)


MONITOR_PAGE_SIZE = 100   # package rows per page on /monitor/<scan_id>


def paginate(total, page, per_page):
    """
    Clamp page to 1..total_pages (at least 1, even with no rows).
    Returns (page, total_pages, offset).
    """
    total_pages = max(1, -(-total // per_page))
    page = min(max(page, 1), total_pages)
    return page, total_pages, (page - 1) * per_page


def dashboard_totals(summaries):
    """Add up get_scan_summaries() values into one set of dashboard counts."""
    from db_storage import empty_scan_summary

    totals = empty_scan_summary()
    for summary in summaries.values():
        for key in ("total", "outdated", "up_to_date"):
            totals[key] += summary[key]
        for tier, n in summary["tiers"].items():
            totals["tiers"][tier] += n
    return totals


def repo_outdated_percentages(scans, summaries):
    """(target_name, % outdated) for each scan, in scan order; 0 for empty scans."""
    from db_storage import empty_scan_summary

    result = []
    for scan in scans:
        summary = summaries.get(scan["scan_id"]) or empty_scan_summary()
        total = summary["total"]
        percentage = round(summary["outdated"] / total * 100, 2) if total else 0
        result.append((scan["target_name"], percentage))
    return result


SCAN_JOB_ID = "auto_scan_repositories"
MONITOR_JOB_ID = "auto_monitor_versions"
RESCAN_WEEKS = 1   # repositories are re-cloned and rescanned weekly, never at startup

RESCAN_UNITS = ("minutes", "hours", "days")


def validate_settings(raw):
    """
    Validate raw (string) settings from the form or DB.
    Returns (cleaned_dict, errors).
    """
    errors = []
    cleaned = {}

    try:
        value = int(str(raw.get("rescan_interval_value", "")).strip())
        if not 1 <= value <= 1000:
            raise ValueError
        cleaned["rescan_interval_value"] = value
    except ValueError:
        errors.append("Rescan interval must be a whole number between 1 and 1000.")

    unit = str(raw.get("rescan_interval_unit", "")).strip()
    if unit in RESCAN_UNITS:
        cleaned["rescan_interval_unit"] = unit
    else:
        errors.append("Rescan interval unit must be minutes, hours, or days.")

    try:
        threshold = int(str(raw.get("age_threshold_days", "")).strip())
        if not 0 <= threshold <= 36500:
            raise ValueError
        cleaned["age_threshold_days"] = threshold
    except ValueError:
        errors.append("Age threshold must be a whole number of days between 0 and 36500.")

    return cleaned, errors


REVIEWER_MAX_LENGTH = 100   # package_reviews.reviewer is VARCHAR(100)


def validate_review(raw):
    """
    Validate a review form (status, reviewer, note).
    Returns (cleaned_dict, errors); an empty note becomes None.
    """
    from db_storage import REVIEW_STATUSES

    errors = []
    cleaned = {}

    status = str(raw.get("status", "")).strip()
    if status in REVIEW_STATUSES:
        cleaned["status"] = status
    else:
        errors.append("Status must be one of: " + ", ".join(REVIEW_STATUSES) + ".")

    reviewer = str(raw.get("reviewer", "")).strip()
    if not reviewer:
        errors.append("Reviewer name is required.")
    elif len(reviewer) > REVIEWER_MAX_LENGTH:
        errors.append(f"Reviewer name must be at most {REVIEWER_MAX_LENGTH} characters.")
    else:
        cleaned["reviewer"] = reviewer

    cleaned["note"] = str(raw.get("note", "")).strip() or None

    return cleaned, errors


def safe_packages_url(url):
    """url if it is a /packages page on this site, else /packages (no open redirect)."""
    url = str(url or "")
    if url == "/packages" or url.startswith("/packages?"):
        return url
    return "/packages"


def create_app() -> Flask:

    app = Flask(
        __name__,
        template_folder="ui/templates",
        static_folder="ui/static",
    )

    app.config["scanner_lock"] = threading.Lock()

   # ======================================
    # AUTO SCAN FUNCTION (NO CHANGE HERE)
    # ======================================
    def auto_scan_repositories():

        from db_storage import get_db_storage
        from target_files import resolve_target_file

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("\n======================================")
        print(f"[Auto Monitor] Scheduled scan started at: {scan_time}")
        print("======================================")

        Config = get_config()
        SBOMScanner = get_scanner_class()
        Config.init_directories()

        db = get_db_storage()

        scans = db.get_all_scans()

        if not scans:
            print("No repositories found in database.")
            return

        for scan in scans:

            target = scan.get("target_name")

            if not target:
                continue

            print(f"\nProcessing target: {target}")

            try:

                # ==============================
                # CASE 1: REPOSITORY
                # ==============================
                if target.startswith("http") or target.startswith("git"):
                    print(f"→ Scanning repository: {target}")

                    scanner = SBOMScanner(use_cache=True, shallow_clone=True)
                    scanner.scan(target)

                # ==============================
                # CASE 2: CSV DATASET
                # ==============================
                elif target.endswith(".csv"):
                    print(f"→ Monitoring CSV file: {target}")

                    import pandas as pd

                    df = pd.read_csv(resolve_target_file(target))

                    print(f"CSV Rows: {len(df)}, Columns: {len(df.columns)}")

                # ==============================
                # CASE 3: JSON FILE
                # ==============================
                elif target.endswith(".json"):
                    print(f"→ Monitoring JSON file: {target}")

                    import json

                    with open(resolve_target_file(target), "r") as f:
                        data = json.load(f)

                    print(f"JSON Keys: {list(data.keys())[:5]}")

                # ==============================
                # UNKNOWN TYPE
                # ==============================
                else:
                    print(f"Skipping unsupported target: {target}")

            except Exception as e:
                print(f"Error processing {target}: {e}")


    # ======================================
    # SCHEDULER SETUP (FIXED ORDER)
    # ======================================
    from db_storage import get_db_storage, ensure_schema, DEFAULT_SETTINGS

    # Create settings table / new columns if this DB predates them
    try:
        ensure_schema()
    except Exception as e:
        print("Schema check failed (is MySQL running?):", e)

    try:
        settings, errors = validate_settings(get_db_storage().get_settings())
        if errors:
            print("Invalid stored settings, using defaults:", errors)
            settings, _ = validate_settings(DEFAULT_SETTINGS)
    except Exception as e:
        print("Could not load settings, using defaults:", e)
        settings, _ = validate_settings(DEFAULT_SETTINGS)

    interval_value = settings["rescan_interval_value"]
    interval_unit = settings["rescan_interval_unit"]

    scheduler = BackgroundScheduler()
    app.config["scheduler"] = scheduler

    # Add jobs BEFORE starting scheduler
    scheduler.add_job(
        auto_scan_repositories,
        trigger="interval",
        id=SCAN_JOB_ID,
        weeks=RESCAN_WEEKS
    )

    scheduler.add_job(
        auto_monitor_versions,
        trigger="interval",
        id=MONITOR_JOB_ID,
        **{interval_unit: interval_value}
    )


    # Prevent double scheduler in Flask debug mode
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":

        scheduler.start()

        print("Background scheduler started")
        print(f"Repository scanning every {RESCAN_WEEKS} week(s), not at startup")
        print(f"Package monitoring every {interval_value} {interval_unit}")

        # ======================================
        # INITIAL BACKGROUND MONITORING (RUN ONCE; no repository rescan)
        # ======================================

        def initial_background_scan():
            print("\n Running initial monitoring (background)...")

            try:
                auto_monitor_versions()

                print("✅ Initial scan complete")

            except Exception as e:
                print("Initial scan error:", e)

        # Run in background (non-blocking + safe shutdown)
        threading.Thread(
            target=initial_background_scan,
            daemon=True
        ).start()
    
    # ======================================
    # ROUTES
    # ======================================

    @app.route("/")
    def home():
        return redirect("/dashboard")

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"}), 200
    
    @app.route("/run-scan")
    def run_scan():
        return render_template("index.html")
    

    # ======================================
    # SCAN API
    # ======================================

    @app.route("/api/scan", methods=["POST"])
    def scan():
        payload = request.get_json(silent=True) or {}
        target = payload.get("target")

        if not target:
            return jsonify({"error": "Target repository or path is required"}), 400

        Config = get_config()
        SBOMScanner = get_scanner_class()
        Config.init_directories()

        lock: threading.Lock = app.config["scanner_lock"]

        try:
            with lock:
                scanner = SBOMScanner(
                    use_cache=payload.get("useCache", True),
                    shallow_clone=payload.get("shallowClone", True),
                    skip_vuln=False
                )

                scan_id = scanner.scan(target)
                report = scanner.get_report(scan_id) if scan_id else None

        except Exception as e:
            return jsonify({"error": str(e)}), 500

        if not report:
            return jsonify({"error": "Scan failed"}), 500

        # Build dependency tree
        dependency_tree = build_dependency_tree(
            report.get("dependency_graph", [])
        )
        report["dependency_tree"] = dependency_tree

        return jsonify({
            "scanId": scan_id,
            "report": report
        })

    @app.route("/upload-sbom", methods=["POST"])
    def upload_sbom():
        """
        Save the file, create (or reuse) its scan, and process the packages
        in a background thread. The monitor page shows the progress.
        """
        from db_storage import get_db_storage
        from target_files import save_upload
        from upload_jobs import JOBS, dedupe_packages, parse_upload, process_upload

        db = get_db_storage()

        # =========================
        # VALIDATION
        # =========================
        if "file" not in request.files:
            return redirect("/dashboard")

        file = request.files["file"]

        if file.filename == "":
            return redirect("/dashboard")

        # Read once: the same bytes are parsed below and saved to uploaded_sboms/
        raw = file.read()

        try:
            rows = parse_upload(file.filename, raw)
        except ValueError as e:
            print(e)
            return redirect("/dashboard")

        # One entry per package name; a later row overrides an earlier one
        packages = dedupe_packages(rows)

        # =========================
        # SAVE FILE + SCAN
        # =========================
        # Save the file so the scheduled rescan can open it. The stored target
        # is exactly the saved file name. A different file that already has
        # this name is never overwritten; this one gets a _1, _2... suffix.
        # The same file again reuses its name, and so its scan.
        target, renamed = save_upload(raw, file.filename)
        if renamed:
            print(f"Saved upload {file.filename!r} as uploaded_sboms/{target} "
                  f"(a different file with that name already exists)")
        else:
            print(f"Saved upload {file.filename!r} as uploaded_sboms/{target}")

        scan_id = db.with_reconnect(db.insert_scan, target)
        if scan_id is None:
            print(f"Upload of {target} failed: could not create scan (database unavailable)")
            return redirect("/dashboard")

        # =========================
        # PROCESS IN THE BACKGROUND
        # =========================
        job, started = JOBS.start(
            scan_id,
            target=target,
            saved_as=target if renamed else None,
            csv_rows=len(rows),
            distinct=len(packages),
        )
        if started:
            print(f"Processing {target}: {len(packages)} distinct packages "
                  f"from {len(rows)} rows (scan {scan_id})")
            run_in_background(process_upload, db, scan_id, packages)
        else:
            print(f"{target} (scan {scan_id}) is already being processed; "
                  f"not starting it again")

        return redirect(f"/monitor/{scan_id}")

    @app.route("/api/upload-status/<int:scan_id>")
    def upload_status(scan_id):
        """Progress of the latest upload for this scan (polled by the monitor page)."""
        from upload_jobs import JOBS

        return jsonify(JOBS.get(scan_id) or {"scan_id": scan_id, "state": "none"})

    @app.route("/monitor/<int:scan_id>")
    def monitor_packages(scan_id):

        from db_storage import get_db_storage
        db = get_db_storage()

        # Latest upload for this scan (running or finished), for the
        # progress/result box
        from upload_jobs import JOBS
        upload_job = JOBS.get(scan_id)

        # No registry lookups on a page load: rows are recalculated by the
        # upload (as they are written) and by the scheduled background job.

        #packages = db.get_monitored_versions(scan_id)
        packages = db.get_monitored_versions(scan_id)
        # 🔥 CLEAN BAD DATA (ADD THIS)
        packages = [
            p for p in packages
            if p.get("package_name") and p.get("current_version")
        ]

        # only recalc if missing/bad data
        if not packages:
            print("No data available after recalculation")

        # =========================
        # SAFE FETCH + CLEAN DATE
        # =========================

        from datetime import datetime

        try:
            # Get scan info
            all_scans = db.get_all_scans()
            scan_info = next((s for s in all_scans if s["scan_id"] == scan_id), None)

            # Default value
            scan_date = "N/A"

            if scan_info:
                raw_date = scan_info.get("scan_timestamp")

                # ✅ Format datetime properly
                if isinstance(raw_date, datetime):
                    scan_date = raw_date.strftime("%Y-%m-%d %H:%M:%S")
                elif raw_date:
                    scan_date = str(raw_date)

            # Attach same scan date to all packages
            for p in packages:
                p["scan_date"] = scan_date

        except Exception as e:
            print("ERROR fetching packages:", e)
            packages = []

        # CLEAN DATA
        for p in packages:
            p["version_status"] = p.get("version_status") or "unknown"

            if p["version_status"] != "up_to_date":
                p["versions_behind"] = p.get("versions_behind") or "0.0.0"
                p["days_outdated"] = p.get("days_outdated") or 0

                # 🔥 FIX: avoid zero days
                if p["days_outdated"] == 0:
                    p["days_outdated"] = 30

        # ============================
        # USE DB SEVERITY (NO RE-CALCULATION)
        # ============================

        for p in packages:

            # fallback safety (in case DB missed something)
            if p.get("severity_level") is None:
                p["severity_level"] = "low"

            # 🔥 fallback for missing days (UI only)
            if p["version_status"] != "up_to_date":
                if p.get("days_outdated") == 0:
                    p["days_outdated"] = 30

        # ADD THIS BLOCK HERE
        if not packages:
            return render_template(
                "monitor.html",
                upload_job=upload_job,
                packages=[],
                total_packages=0,
                outdated_packages=0,
                uptodate_packages=0,
                avg_outdated_days=0,
                trend_data=[],
                severity_labels=[],
                severity_values=[],
                repo_labels=[],
                repo_outdated_counts=[],
                best_repo=("N/A", 0),
                worst_repo=("N/A", 0),
                empty_message=(
                    "Upload in progress: packages appear here as they are saved."
                    if JOBS.is_active(scan_id)
                    else "⚠️ No package data available (N/A)"
                )
            )
            

        # ============================
        # ANALYSIS METRICS
        # ============================

        total = len(packages)
        outdated = sum(1 for p in packages if p["version_status"] == "outdated")
        up_to_date = sum(1 for p in packages if p["version_status"] == "up_to_date")

        #  percentage outdated
        outdated_percentage = round((outdated / total) * 100, 2) if total > 0 else 0

        #  version lag stats
        version_gaps = []

        for p in packages:
            vb = str(p.get("versions_behind", "0.0.0"))

            # "N/A" = gap not known; leave it out rather than count it as 0
            if vb == "N/A":
                continue

            try:
                major = int(vb.split(".")[0])
                version_gaps.append(major)
            except:
                version_gaps.append(0)


        avg_version_gap = round(sum(version_gaps) / len(version_gaps), 2) if version_gaps else 0
        max_version_gap = max(version_gaps) if version_gaps else 0

        #REPO COMPARISON (TOP 10 ONLY)
        # % outdated per scan, counted in SQL (GROUP BY) instead of loading
        # every scan's rows
        all_scans = db.get_all_scans()
        repo_scores = repo_outdated_percentages(all_scans, db.get_scan_summaries())

        #sort descending
        repo_data = sorted(repo_scores, key=lambda x: x[1], reverse=True)[:10]

        repo_labels = [r[0] for r in repo_data]
        repo_outdated_counts = [r[1] for r in repo_data]
        #--------
        
        total = len(packages)
        outdated = sum(1 for p in packages if p["version_status"] == "outdated")
        up_to_date = sum(1 for p in packages if p["version_status"] == "up_to_date")

        #REAL AVG DAYS CALCULATION
        outdated_days = [
            p.get("days_outdated", 0)
            for p in packages
            if p["version_status"] == "outdated"
        ]

        avg_outdated_days = round(sum(outdated_days) / len(outdated_days), 2) if outdated_days else 0

        # ============================
        # TREND DATA (FINAL FIX)
        # ============================

        trend_data_raw = db.get_trend_data(scan_id) or []

        trend_data = []

        for item in trend_data_raw:
            try:
                # If dictionary
                if isinstance(item, dict):
                    label = str(item.get("date") or item.get("label") or "N/A")
                    value = int(item.get("count") or item.get("value") or 0)

                # If tuple/list
                else:
                    label = str(item[0]) if item[0] else "N/A"
                    value = int(item[1]) if item[1] is not None else 0

                trend_data.append((label, value))

            except:
                trend_data.append(("N/A", 0))

        # ============================
        # SEVERITY DISTRIBUTION
        # ============================

        severity_counts = {
            "low": 0,
            "medium": 0,
            "high": 0
        }

        for p in packages:
            if p["version_status"] == "outdated":
                sev = p.get("severity_level")
                if sev in severity_counts:
                    severity_counts[sev] += 1

        severity_labels = ["Low", "Medium", "High"]
        severity_values = [
            severity_counts["low"],
            severity_counts["medium"],
            severity_counts["high"]
        ]


        # ============================
        # BEST vs WORST REPO
        # ============================

        # sort (repo_scores is from the REPO COMPARISON step above)
        repo_scores_sorted = sorted(repo_scores, key=lambda x: x[1])

        best_repo = repo_scores_sorted[0] if repo_scores_sorted else ("N/A", 0)
        worst_repo = repo_scores_sorted[-1] if repo_scores_sorted else ("N/A", 0)

        # ============================
        # TABLE: SEARCH / FILTER + PAGINATION
        # ============================
        # The stats above cover every row; the table shows one page of
        # MONITOR_PAGE_SIZE rows. Search and the outdated filter are applied
        # here (not in the browser) so they cover all pages.
        search = request.args.get("q", "").strip()
        outdated_only = request.args.get("outdated") == "1"

        table_rows = packages
        if search:
            table_rows = [p for p in table_rows
                          if search.lower() in p["package_name"].lower()]
        if outdated_only:
            # Strictly outdated: unknown rows (lookup failed / no registry)
            # are shown as "Unknown", not "Outdated"
            table_rows = [p for p in table_rows if p["version_status"] == "outdated"]

        page, total_pages, offset = paginate(
            len(table_rows), request.args.get("page", 1, type=int), MONITOR_PAGE_SIZE
        )
        page_rows = table_rows[offset:offset + MONITOR_PAGE_SIZE]

        return render_template(
            "monitor.html",
            upload_job=upload_job,
            packages=page_rows,
            page=page,
            total_pages=total_pages,
            filtered_count=len(table_rows),
            first_row=offset + 1 if page_rows else 0,
            last_row=offset + len(page_rows),
            search=search,
            outdated_only=outdated_only,
            scan_id=scan_id,
            total_packages=total,
            outdated_packages=outdated,
            uptodate_packages=up_to_date,
            avg_outdated_days=avg_outdated_days,
            trend_data=trend_data,
            # NEW DATA
            outdated_percentage=outdated_percentage,
            avg_version_gap=avg_version_gap,
            max_version_gap=max_version_gap,
            repo_labels=repo_labels,
            repo_outdated_counts=repo_outdated_counts,
            severity_labels=severity_labels,
            severity_values=severity_values,
            best_repo=best_repo,
            worst_repo=worst_repo,
        )
    
    @app.route("/monitor")
    def monitor_latest():

        from db_storage import get_db_storage
        db = get_db_storage()

        scans = db.get_all_scans()

        if not scans:
            return "No scans found"

        latest_scan_id = scans[0]["scan_id"]

        return redirect(f"/monitor/{latest_scan_id}")
    
    @app.route("/run-monitor")
    def run_monitor():
        """Start the monitoring job in the background; returns at once."""

        run_in_background(auto_monitor_versions)

        return ("Monitoring started in the background. "
                "Results appear on the monitor pages as rows are refreshed.")
    
    #--------------------------
    @app.route("/api/monitored")
    def monitored_versions():

        from db_storage import get_db_storage
        db = get_db_storage()

        scans = db.get_all_scans()

        if not scans:
            return jsonify([])

        latest_scan_id = scans[0]["scan_id"]

        data = db.get_monitored_versions(latest_scan_id)

        return jsonify(data)
    
    #----------------------------
    @app.route("/dashboard")
    def dashboard():

        from db_storage import get_db_storage

        db = get_db_storage()
        scans = db.get_all_scans()

        # Counted in SQL (GROUP BY), so no package rows are loaded
        totals = dashboard_totals(db.get_scan_summaries())
        total_repos = len(scans)
        total_packages = totals["total"]
        total_outdated = totals["outdated"]
        total_updated = totals["up_to_date"]
        # Every package lands in exactly one bucket, so these add up to total_packages
        tier_counts = totals["tiers"]

        from db_storage import REVIEW_STATUSES
        try:
            review_counts = db.get_review_status_counts()
        except Exception as e:
            print("ERROR loading review counts:", e)
            review_counts = {status: 0 for status in REVIEW_STATUSES}

        # Per package (risk of its latest scan), not per versions row
        from db_storage import RISK_FILTERS
        try:
            risk_counts = db.get_risk_level_counts()
        except Exception as e:
            print("ERROR loading risk counts:", e)
            risk_counts = {level: 0 for level in RISK_FILTERS}

        # Head of the update queue (rank 1 first)
        try:
            top_priorities = db.get_top_priorities(10)
        except Exception as e:
            print("ERROR loading update queue:", e)
            top_priorities = []

        return render_template(
            "dashboard.html",
            total_repos=total_repos,
            total_packages=total_packages,
            total_outdated=total_outdated,
            total_updated=total_updated,
            tier_counts=tier_counts,
            review_counts=review_counts,
            risk_counts=risk_counts,
            top_priorities=top_priorities
        )

    #-----------------------------------------
    @app.route("/repos")
    def repos():
        from db_storage import get_db_storage
        db = get_db_storage()

        scans = db.get_all_scans()

        return render_template("repos.html", history_scans=scans)

    #-------------------------------------------
    @app.route("/packages")
    def all_packages():

        from db_storage import get_db_storage
        db = get_db_storage()

        # Pagination params
        page = int(request.args.get("page", 1))
        per_page = 50   # you can change (20 / 50 / 100)

        offset = (page - 1) * per_page

        # "Requires attention" = installed version older than the threshold
        attention_only = request.args.get("attention") == "1"

        try:
            cleaned, _ = validate_settings(db.get_settings())
            age_threshold = cleaned.get("age_threshold_days")
        except Exception as e:
            print("ERROR loading settings:", e)
            age_threshold = None

        if age_threshold is None:
            age_threshold = int(DEFAULT_SETTINGS["age_threshold_days"])

        older_than = age_threshold if attention_only else None

        # Age tier filter / sort (server-side so they cover every page)
        from age_tiers import TIER_NAMES, UNKNOWN_TIER
        age_tier = request.args.get("tier", "")
        if age_tier not in TIER_NAMES and age_tier != UNKNOWN_TIER:
            age_tier = ""
        # Sort: newest (default), age tier, or the update queue
        sort = request.args.get("sort", "")
        if sort not in ("tier", "priority"):
            sort = ""
        sort_by_tier = sort == "tier"
        sort_by_priority = sort == "priority"

        # Review status filter (server-side, like the tier filter)
        from db_storage import REVIEW_STATUSES
        review_status = request.args.get("review", "")
        if review_status not in REVIEW_STATUSES:
            review_status = ""

        # Risk filter (the package's risk from its latest scan)
        from db_storage import RISK_FILTERS
        risk_level = request.args.get("risk", "")
        if risk_level not in RISK_FILTERS:
            risk_level = ""

        # Update queue category filter (the package's priority)
        from db_storage import PRIORITY_FILTERS
        priority_category = request.args.get("priority", "")
        if priority_category not in PRIORITY_FILTERS:
            priority_category = ""

        try:
            # Fetch paginated data
            packages = db.get_packages_paginated(
                limit=per_page, offset=offset, older_than_days=older_than,
                age_tier=age_tier or None, sort_by_tier=sort_by_tier,
                review_status=review_status or None,
                risk_level=risk_level or None,
                sort_by_priority=sort_by_priority,
                priority_category=priority_category or None
            )

            # Total count
            total = db.get_total_packages(
                older_than_days=older_than, age_tier=age_tier or None,
                review_status=review_status or None,
                risk_level=risk_level or None,
                priority_category=priority_category or None
            )

        except Exception as e:
            print("ERROR fetching packages:", e)
            packages = []
            total = 0

        for p in packages:
            days = p.get("days_since_release")
            p["requires_attention"] = days is not None and days > age_threshold

        total_pages = (total // per_page) + (1 if total % per_page else 0)

        return render_template(
            "packages.html",
            packages=packages,
            page=page,
            total_pages=total_pages,
            age_threshold=age_threshold,
            attention_only=attention_only,
            tier_names=TIER_NAMES,
            age_tier=age_tier,
            sort_by_tier=sort_by_tier,
            sort=sort,
            review_statuses=REVIEW_STATUSES,
            review_status=review_status,
            risk_filters=RISK_FILTERS,
            risk_level=risk_level,
            priority_filters=PRIORITY_FILTERS,
            priority_category=priority_category,
            active="packages"
        )

    #----------------------------------------------------
    @app.route("/packages/<int:package_id>/review", methods=["POST"])
    def save_package_review(package_id):
        """Save a package's review status from the Packages page edit form."""

        from db_storage import get_db_storage
        db = get_db_storage()

        back = safe_packages_url(request.form.get("next"))

        cleaned, errors = validate_review(request.form)
        if errors:
            return " ".join(errors), 400

        try:
            saved = db.save_review(
                package_id, cleaned["status"], cleaned["reviewer"], cleaned["note"]
            )
        except Exception as e:
            print("ERROR saving review:", e)
            return "Could not save the review to the database.", 500

        if not saved:
            return "Package not found.", 404

        print(f"Package {package_id} review set to {cleaned['status']!r} "
              f"by {cleaned['reviewer']!r}")

        # The review changes the update queue; the review itself is already
        # saved, so a failure here is only logged (the monitor job re-ranks)
        try:
            db.update_package_priorities()
        except Exception as e:
            print("ERROR updating priorities after review:", e)

        return redirect(back)

    @app.route("/packages/<int:package_id>/history")
    def package_review_history(package_id):
        """Read-only review history for one package, newest first."""

        from db_storage import get_db_storage
        db = get_db_storage()

        try:
            review = db.get_review(package_id)
            history = db.get_review_history(package_id) if review else []
        except Exception as e:
            print("ERROR loading review history:", e)
            return "Could not load the review history.", 500

        if review is None:
            return "Package not found.", 404

        return render_template(
            "review_history.html",
            review=review,
            history=history,
            back=safe_packages_url(request.args.get("next")),
            active="packages"
        )

    #----------------------------------------------------
    @app.route("/settings", methods=["GET", "POST"])
    def settings_page():

        from db_storage import get_db_storage
        db = get_db_storage()

        if request.method == "POST":
            cleaned, errors = validate_settings(request.form)

            if errors:
                return render_template(
                    "settings.html",
                    settings=request.form,
                    units=RESCAN_UNITS,
                    errors=errors,
                    active="settings"
                ), 400

            try:
                db.save_settings(cleaned)
            except Exception as e:
                print("ERROR saving settings:", e)
                return render_template(
                    "settings.html",
                    settings=request.form,
                    units=RESCAN_UNITS,
                    errors=["Could not save settings to the database."],
                    active="settings"
                ), 500

            # Apply the new interval right away (no restart needed); the
            # repository rescan stays weekly
            interval = {cleaned["rescan_interval_unit"]: cleaned["rescan_interval_value"]}
            scheduler.reschedule_job(MONITOR_JOB_ID, trigger="interval", **interval)

            print(
                "Rescan interval updated to every "
                f"{cleaned['rescan_interval_value']} {cleaned['rescan_interval_unit']}"
            )

            return redirect("/settings?saved=1")

        try:
            current = db.get_settings()
        except Exception as e:
            print("ERROR loading settings:", e)
            current = dict(DEFAULT_SETTINGS)

        next_run = None
        job = scheduler.get_job(MONITOR_JOB_ID)
        if job and getattr(job, "next_run_time", None):
            next_run = job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")

        return render_template(
            "settings.html",
            settings=current,
            units=RESCAN_UNITS,
            errors=[],
            saved=request.args.get("saved") == "1",
            next_run=next_run,
            active="settings"
        )
            
    #----------------------------------------------------
    
    @app.route("/analytics")
    def analytics():

        from analytics_ml import run_analytics
        from datetime import datetime

        results = run_analytics()

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if not results:
            return render_template(
                "analytics.html",
                last_updated=timestamp
            )

        return render_template(
            "analytics.html",
            full_model_table=results.get("full_model_table"),
            images=results.get("images"),
            last_updated=timestamp
        )
    #---------------------------------------------

    @app.route("/refresh-analytics")
    def refresh_analytics():

        from analytics_ml import run_analytics
        import os

        print("🔄 Manual analytics refresh triggered")

        # OPTIONAL: clear cache files
        if os.path.exists("analytics_cache.json"):
            os.remove("analytics_cache.json")

        if os.path.exists("analytics_hash.txt"):
            os.remove("analytics_hash.txt")

        # Run fresh analytics
        run_analytics()

        return redirect("/analytics")
   

    return app

if __name__ == "__main__":
    
    import sys
    
    # Try to use waitress (production WSGI server) if available
    # This handles long-running requests much better than Flask dev server
    try:
        from waitress import serve
        print("Waitress found - using production server...")
    except ImportError as e:
        print(f"Waitress not found: {e}")
        print("Falling back to Flask development server...")
        application = create_app()
        print("=" * 60)
        print("Starting Flask development server...")
        print("=" * 60)
        print("\n" + "=" * 60)
        print("  SERVER IS RUNNING!")
        print("=" * 60)
        print("  Open your browser and go to:")
        print("  👉  http://127.0.0.1:5000")
        print("=" * 60)
        print("\nWARNING: Using Flask development server")
        print("This server has a 120-second timeout limit.")
        print("For large repositories, install waitress:")
        print("  pip install waitress")
        print("Then restart the server.")
        print("\nPress Ctrl+C to stop the server\n")
        print("=" * 60 + "\n")
        
        # Try to open browser automatically
        try:
            import webbrowser
            import time
            # Wait a moment for server to start, then open browser
            def open_browser():
                time.sleep(1.5)
                webbrowser.open("http://127.0.0.1:5000")
            import threading
            threading.Thread(target=open_browser, daemon=True).start()
        except Exception:
            pass  # If browser opening fails, just continue
        
        application.run(debug=True, threaded=True, use_reloader=False)
        sys.exit(0)
    
    # If we get here, waitress is available
    try:
        application = create_app()
        print("=" * 60)
        print("Starting server with Waitress (production WSGI server)")
        print("This server can handle long-running scans without timeout issues.")
        print("=" * 60)
        print("\n" + "=" * 60)
        print("  SERVER IS RUNNING!")
        print("=" * 60)
        print("  Open your browser and go to:")
        print("  👉  http://127.0.0.1:5000")
        print("=" * 60)
        print("\nPress Ctrl+C to stop the server\n")
        print("=" * 60 + "\n")
        
        # Try to open browser automatically
        try:
            import webbrowser
            import time
            # Wait a moment for server to start, then open browser
            def open_browser():
                time.sleep(1.5)
                webbrowser.open("http://127.0.0.1:5000")
            import threading
            threading.Thread(target=open_browser, daemon=True).start()
        except Exception:
            pass  # If browser opening fails, just continue
        
        serve(application, host="127.0.0.1", port=5000, threads=4)
    except Exception as e:
        print(f"Error starting server: {e}")
        print("Falling back to Flask development server...")
        application = create_app()
        print("=" * 60)
        print("Starting Flask development server...")
        print("=" * 60)
        print("\n" + "=" * 60)
        print("  SERVER IS RUNNING!")
        print("=" * 60)
        print("  Open your browser and go to:")
        print("  👉  http://127.0.0.1:5000")
        print("=" * 60)
        print("\nWARNING: Using Flask development server")
        print("This server has a 120-second timeout limit.")
        print("\nPress Ctrl+C to stop the server\n")
        print("=" * 60 + "\n")
        
        # Try to open browser automatically
        try:
            import webbrowser
            import time
            # Wait a moment for server to start, then open browser
            def open_browser():
                time.sleep(1.5)
                webbrowser.open("http://127.0.0.1:5000")
            import threading
            threading.Thread(target=open_browser, daemon=True).start()
        except Exception:
            pass  # If browser opening fails, just continue
        
        application.run(debug=True, threaded=True, use_reloader=False)

        application.run(host="0.0.0.0", port=5000, debug=True)


