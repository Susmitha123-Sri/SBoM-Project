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

def auto_monitor_versions():

    from db_storage import get_db_storage
    from version_monitor import get_latest_version

    print("\n======================================")
    print("Auto Version Monitoring Started:", datetime.now())
    print("======================================")

    db = get_db_storage()

    scans = db.get_all_scans()

    for scan in scans:

        scan_id = scan["scan_id"]

        packages = db.get_monitored_versions(scan_id)

        existing_packages = {p["package_name"] for p in packages}

        for pkg in packages:

            package_name = pkg["package_name"]
            current_version = pkg["current_version"]

            #latest_version = get_latest_version(package_name, "pypi")
            latest_version = get_latest_version(package_name, "python")

            if not latest_version:
                status = "unknown"

            elif latest_version == current_version:
                status = "up_to_date"

            else:
                status = "outdated"

            # Re-insert version to recalculate metrics
            db.insert_version(
                scan_id,
                pkg.get("package_id", None),
                package_name,
                current_version,
                status,
                latest_version,
                pkg.get("baseline_status", "active")
            )

    print("Auto monitoring finished:", datetime.now())

    from db_storage import get_db_storage

    db = get_db_storage()

    for scan in db.get_all_scans():
        print("Auto recalculating:", scan["scan_id"])
        db.recalculate_metrics_for_scan(scan["scan_id"])

    # Detect new packages (not in baseline)

    # Example: you can fetch from PyPI or repo (simplified demo)

    monitored_list = list(existing_packages)

    for package_name in monitored_list:

        #latest_version = get_latest_version(package_name, "pypi")
        latest_version = get_latest_version(package_name, "python")

        if not latest_version:
            continue

        # If package not in DB → insert as inactive baseline
        if not db.package_exists(package_name):

            package_id = db.insert_package(package_name)

            db.insert_version(
                scan_id,
                package_id,
                package_name,
                latest_version,
                status,
                latest_version,
                "active"
            )

            print("New package detected:", package_name)


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

                    df = pd.read_csv(target)

                    print(f"CSV Rows: {len(df)}, Columns: {len(df.columns)}")

                # ==============================
                # CASE 3: JSON FILE
                # ==============================
                elif target.endswith(".json"):
                    print(f"→ Monitoring JSON file: {target}")

                    import json

                    with open(target, "r") as f:
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
    scheduler = BackgroundScheduler()

    # Add jobs BEFORE starting scheduler
    scheduler.add_job(
        auto_scan_repositories,
        trigger="interval",
        hours=6
    )

    scheduler.add_job(
        auto_monitor_versions,
        trigger="interval",
        hours=6
    )


    # Prevent double scheduler in Flask debug mode
    if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":

        scheduler.start()

        print("Background scheduler started")
        print("Repository scanning every 6 hours")
        print("Package monitoring every 6 hours")

        # ======================================
        # INITIAL BACKGROUND SCAN (RUN ONCE)
        # ======================================

        def initial_background_scan():
            print("\n Running initial scan (background)...")

            try:
                auto_scan_repositories()
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

        from db_storage import get_db_storage
        from version_monitor import get_latest_version
        import csv
        import json

        db = get_db_storage()

        # =========================
        # VALIDATION
        # =========================
        if "file" not in request.files:
            return redirect("/dashboard")

        file = request.files["file"]

        if file.filename == "":
            return redirect("/dashboard")

        filename = file.filename.lower()

        packages = []

        # =========================
        # CSV HANDLING
        # =========================
        if filename.endswith(".csv"):

            content = file.read().decode("utf-8").strip()
            reader = csv.DictReader(content.splitlines())

            for row in reader:

                # Accept either naming convention for the name/version columns
                name = (row.get("package_name") or row.get("name") or "").strip()
                version = (
                    row.get("current_version")
                    or row.get("version")
                    or ""
                ).strip()
                risk_level = (
                    row.get("risk_level")
                    or row.get("severity")
                    or ""
                ).strip()

                if name and version:
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "pypi",
                        "risk_level": risk_level
                    })

        # =========================
        # JSON HANDLING (SBOM)
        # =========================
        elif filename.endswith(".json"):

            try:
                data = json.load(file)

                raw_packages = (
                    data.get("packages")
                    or data.get("components")
                    or data.get("artifacts")
                    or []
                )

                for pkg in raw_packages:

                    name = (
                        pkg.get("package")
                        or pkg.get("name")
                    )

                    version = (
                        pkg.get("version")
                        or pkg.get("versionInfo")
                    )

                    # fallback from purl
                    if not name and pkg.get("purl"):
                        name = pkg.get("purl").split("/")[-1].split("@")[0]

                    if not version and pkg.get("purl") and "@" in pkg.get("purl"):
                        version = pkg.get("purl").split("@")[-1]

                    if name and version:
                        packages.append({
                            "name": name.strip(),
                            "version": version.strip(),
                            "ecosystem": "github" if "/" in str(name) else "pypi"
                        })

            except Exception as e:
                print("Invalid SBOM file:", e)
                return redirect("/dashboard")

        else:
            return redirect("/dashboard")

        # =========================
        # INSERT INTO DATABASE
        # =========================
        target = file.filename
        scan_id = db.insert_scan(target)
        print(f"Added {target} to DB. Background scan will handle it.")

        for pkg in packages:

            name = pkg.get("name")
            version = pkg.get("version")
            ecosystem = pkg.get("ecosystem", "pypi")

            if not name or not version:
                continue

            name = name.strip()
            version = version.strip()

            # insert package
            package_id = db.insert_package(name, ecosystem)

            # detect type
            if "/" in name:
                pkg_type = "github-action"
            else:
                pkg_type = "python"

            latest_version = get_latest_version(name, pkg_type)

            # determine status
            if not latest_version:
                status = "unknown"
            elif latest_version == version:
                status = "up_to_date"
            else:
                status = "outdated"

            # insert version
            db.insert_version(
                scan_id,
                package_id,
                name,
                version,
                status,
                latest_version,
                "active"
            )

        # =========================
        # DEBUG PRINT (ONCE)
        # =========================
        print(f"Inserted {len(packages)} packages successfully")

        # =========================
        # 🔥 CRITICAL STEP (FIXES YOUR ISSUE)
        # =========================
        try:
            db.recalculate_metrics_for_scan(scan_id)
        except Exception as e:
            print("Recalculation failed:", e)

        # =========================
        # REDIRECT TO MONITOR
        # =========================
        return redirect(f"/monitor/{scan_id}")
    
    @app.route("/monitor/<int:scan_id>")
    def monitor_packages(scan_id):

        from db_storage import get_db_storage
        db = get_db_storage()

        # 🔥 ADD THIS
        
        try:
            db.recalculate_metrics_for_scan(scan_id)
        except Exception as e:
            print("Recalculation failed:", e)
        

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
                empty_message="⚠️ No package data available (N/A)"
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

            if vb == "N/A":
                version_gaps.append(0)
            else:
                try:
                    major = int(vb.split(".")[0])
                    version_gaps.append(major)
                except:
                    version_gaps.append(0)


        avg_version_gap = round(sum(version_gaps) / len(version_gaps), 2) if version_gaps else 0
        max_version_gap = max(version_gaps) if version_gaps else 0

        #REPO COMPARISON (TOP 10 ONLY)
        repo_data = []

        all_scans = db.get_all_scans()

        for scan in all_scans:
            pkgs = db.get_monitored_versions(scan["scan_id"])

            total_pkgs = len(pkgs)
            outdated_pkgs = sum(1 for p in pkgs if p["version_status"] == "outdated")

            # NORMALIZED VALUE
            percentage = round((outdated_pkgs / total_pkgs) * 100, 2) if total_pkgs > 0 else 0

            repo_data.append((scan["target_name"], percentage))

        #sort descending
        repo_data = sorted(repo_data, key=lambda x: x[1], reverse=True)[:10]

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

        repo_scores = []

        for scan in all_scans:
            pkgs = db.get_monitored_versions(scan["scan_id"])
            total_pkgs = len(pkgs)
            outdated_pkgs = sum(1 for p in pkgs if p["version_status"] == "outdated")

            percentage = (outdated_pkgs / total_pkgs * 100) if total_pkgs > 0 else 0

            repo_scores.append((scan["target_name"], percentage))

        # sort
        repo_scores_sorted = sorted(repo_scores, key=lambda x: x[1])

        best_repo = repo_scores_sorted[0] if repo_scores_sorted else ("N/A", 0)
        worst_repo = repo_scores_sorted[-1] if repo_scores_sorted else ("N/A", 0)

        return render_template(
            "monitor.html",
            packages=packages,
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

        auto_monitor_versions()

        #FORCE UPDATE ALL PACKAGES
        from db_storage import get_db_storage
        db = get_db_storage()

        scans = db.get_all_scans()

        for scan in scans:
            scan_id = scan["scan_id"]

            packages = db.get_monitored_versions(scan_id)

            for pkg in packages:

                package_name = pkg["package_name"]
                current_version = pkg["current_version"]

                from version_monitor import get_latest_version

                #latest_version = get_latest_version(package_name, "pypi")
                latest_version = get_latest_version(package_name, "python")

                if not latest_version:
                    status = "unknown"

                if latest_version == current_version:
                    status = "up_to_date"
                else:
                    status = "outdated"

                #THIS WILL UPDATE DB WITH CORRECT VALUES
                db.insert_version(
                    scan_id,
                    None,
                    package_name,
                    current_version,
                    status,
                    latest_version,
                    "active"
                )

        return "Monitoring completed successfully!"
    
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

        total_repos = len(scans)
        total_packages = 0
        total_outdated = 0
        total_updated = 0

        for scan in scans:
            pkgs = db.get_monitored_versions(scan["scan_id"])

            total_packages += len(pkgs)
            total_outdated += sum(1 for p in pkgs if p["version_status"] == "outdated")
            total_updated += sum(1 for p in pkgs if p["version_status"] == "up_to_date")

        return render_template(
            "dashboard.html",
            total_repos=total_repos,
            total_packages=total_packages,
            total_outdated=total_outdated,
            total_updated=total_updated
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

        try:
            # Fetch paginated data
            packages = db.get_packages_paginated(limit=per_page, offset=offset)

            # Total count
            total = db.get_total_packages()

        except Exception as e:
            print("ERROR fetching packages:", e)
            packages = []
            total = 0

        total_pages = (total // per_page) + (1 if total % per_page else 0)

        return render_template(
            "packages.html",
            packages=packages,
            page=page,
            total_pages=total_pages,
            active="packages"  
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


