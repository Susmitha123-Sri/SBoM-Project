import csv
import time
from pathlib import Path

# Import your SBOM scanner
import sys
sys.path.insert(0, str(Path(__file__).parent / "sbom-tools"))

from sbom import SBOMScanner


DATASET_FILE = "dataset/github_repos.csv"


def run_bulk_scan():

    scanner = SBOMScanner(
        use_cache=True,
        shallow_clone=True,
        skip_vuln=True   # ✅ IMPORTANT (faster for 500 repos)
    )

    success = 0
    failed = 0

    print("\n======================================")
    print(" STARTING BULK SCAN")
    print("======================================\n")

    with open(DATASET_FILE) as f:

        reader = csv.DictReader(f)

        for i, row in enumerate(reader, start=1):

            repo = row["repo_url"]

            print(f"\n[{i}] Scanning: {repo}")

            max_retries = 2

            for attempt in range(max_retries):
                try:
                    scanner.scan(repo)
                    success += 1
                    break

                except Exception as e:
                    print(f"⚠️ Attempt {attempt+1} failed")

                    if attempt < max_retries - 1:
                        print("Retrying in 10 seconds...")
                        time.sleep(10)
                    else:
                        print(f"❌ Failed after retries: {repo}")
                        failed += 1

            # 🛑 small delay to avoid GitHub blocking
            time.sleep(5)

    print("\n======================================")
    print(" BULK SCAN COMPLETED")
    print("======================================")
    print(f"✅ Success: {success}")
    print(f"❌ Failed: {failed}")


if __name__ == "__main__":
    run_bulk_scan()