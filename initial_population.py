'''
#!/usr/bin/env python3

"""
Initial Population Script

This script performs the baseline scan of repositories and
populates the database with dependency and version data
before version monitoring begins.
"""

import sys
from pathlib import Path

# --------------------------------------------------
# Add sbom-tools directory to Python path
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
SBOM_MODULE_PATH = PROJECT_ROOT / "sbom-tools"

sys.path.insert(0, str(SBOM_MODULE_PATH))

# Import scanner modules
from sbom import SBOMScanner, Config


# --------------------------------------------------
# Initial Population Function
# --------------------------------------------------

def run_initial_population():

    print("\n=================================================")
    print(" SBOM INITIAL DATABASE POPULATION STARTING")
    print("=================================================\n")

    # Initialize required directories
    Config.init_directories()

    # Create scanner instance
    scanner = SBOMScanner(
        use_cache=True,
        shallow_clone=True
    )

    # List of repositories to populate
    repositories = [
        "https://github.com/psf/requests",
        "https://github.com/pallets/flask",
        "https://github.com/numpy/numpy",
        "https://github.com/pandas-dev/pandas",
        "https://github.com/django/django",
        "https://github.com/scikit-learn/scikit-learn"
    ]

    # Scan each repository
    for repo in repositories:

        print("\n----------------------------------------------")
        print(f"Scanning baseline repository: {repo}")
        print("----------------------------------------------\n")

        try:
            scan_id = scanner.scan(repo)
            print(f"\nBaseline scan completed successfully.")
            print(f"Scan ID: {scan_id}\n")

        except Exception as e:
            print(f"\nError scanning repository {repo}")
            print(e)

    print("\n=================================================")
    print(" INITIAL DATABASE POPULATION COMPLETED")
    print(" Database baseline established.")
    print("=================================================\n")


# --------------------------------------------------
# Run Script
# --------------------------------------------------

if __name__ == "__main__":
    run_initial_population()
'''

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