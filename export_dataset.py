import sys
from pathlib import Path

# ============================
# FIX IMPORT PATH
# ============================
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR / "sbom-tools"))

# ============================
# IMPORTS
# ============================
import pandas as pd
from db_storage import get_db_storage


def export_clean_dataset():

    db = get_db_storage()

    print("Fetching scans...")

    all_scans = db.get_all_scans()

    # ============================
    # LATEST SCAN PER REPO
    # ============================
    latest_scans = {}

    for scan in all_scans:
        repo = scan["target_name"]

        if repo not in latest_scans or scan["scan_id"] > latest_scans[repo]["scan_id"]:
            latest_scans[repo] = scan

    scans = list(latest_scans.values())

    print(f"Using {len(scans)} latest scans")

    all_data = []

    # ============================
    # EXTRACT DATA
    # ============================
    for scan in scans:

        scan_id = scan["scan_id"]
        repo_name = scan["target_name"]

        packages = db.get_monitored_versions(scan_id)

        print(f"\nProcessing {repo_name} → {len(packages)} packages")

        for pkg in packages:

            current = pkg.get("current_version") or ""
            latest = pkg.get("latest_version") or ""
            status = pkg.get("version_status") or "unknown"

            gap = pkg.get("versions_behind") or "0.0.0"
            gap = str(gap)

            days_outdated = pkg.get("days_outdated") or 0

            # ============================
            # CLEAN LOGIC
            # ============================
            if status == "up_to_date":
                gap = "0.0.0"
                days_outdated = 0

            if days_outdated == 0 and status != "up_to_date":
                days_outdated = 30

            severity = pkg.get("severity_level") or "low"

            all_data.append({
                "repo_name": repo_name,
                "package_name": pkg.get("package_name"),
                "current_version": current,
                "latest_version": latest,
                "status": status,
                "versions_behind": gap,
                "days_outdated": days_outdated,
                "severity": severity,
            })

    print(f"\nTotal rows: {len(all_data)}")

    df = pd.DataFrame(all_data)

    # ============================
    # CLEANING
    # ============================
    df = df.dropna(subset=["package_name"])
    df = df.drop_duplicates()

    # remove unknown (optional but cleaner)
    df = df[df["status"] != "unknown"]

    # ============================
    # KEEP ONLY CLEAN COLUMNS
    # ============================
    df = df[[
        "repo_name",
        "package_name",
        "current_version",
        "latest_version",
        "status",
        "versions_behind",
        "days_outdated",
        "severity"
    ]]

    # ============================
    # DEBUG CHECK
    # ============================
    print("\nSeverity distribution:")
    print(df["severity"].value_counts())

    # ============================
    # SAVE FILES
    # ============================
    df.to_csv("sbom_dataset.csv", index=False)
    df.to_excel("sbom_dataset.xlsx", index=False)

    print("\n✅ CLEAN DATASET GENERATED:")
    print("sbom_dataset.csv")
    print("sbom_dataset.xlsx")


# ============================
# RUN
# ============================
if __name__ == "__main__":
    export_clean_dataset()