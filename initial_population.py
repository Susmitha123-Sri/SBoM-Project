#!/usr/bin/env python3

import csv
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent
SBOM_MODULE_PATH = PROJECT_ROOT / "sbom-tools"

sys.path.insert(0, str(SBOM_MODULE_PATH))

from db_storage import get_db_storage

DATASET_FILE = "older_versions_dataset.csv"


def run_initial_population():

    print("\n=================================================")
    print(" INITIAL DATABASE POPULATION STARTING")
    print("=================================================\n")

    db = get_db_storage()

    if not db._connect():
        print("Database connection failed")
        return

    # create scan entry
    scan_id = db.insert_scan("initial_population")

    with open(DATASET_FILE) as file:

        reader = csv.DictReader(file)

        for row in reader:

            package = row["package_name"]
            ecosystem = row["ecosystem"]
            version = row["older_version"]

            print(f"Loading package {package} version {version}")

            # insert package
            package_id = db.insert_package(package, ecosystem)

            # insert baseline version
            db.insert_version(
                scan_id=scan_id,
                package_id=package_id,
                version=version,
                status="baseline",
                latest_version=version
            )

    print("\n=================================================")
    print(" BASELINE DATA LOADED INTO VERSIONS TABLE")
    print("=================================================\n")


if __name__ == "__main__":
    run_initial_population()