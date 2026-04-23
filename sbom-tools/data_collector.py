#!/usr/bin/env python
# coding: utf-8

"""
Data Collector
Extracts version monitoring dataset from sbom_common database
"""

import csv
from datetime import datetime
from pathlib import Path
from db_storage import get_db_storage


class DataCollector:

    def __init__(self):
        self.output_file = (
            Path(__file__).resolve().parent.parent
            / "reports"
            / "version_dataset.csv"
        )
        self._initialize_csv()

    def _initialize_csv(self):
        """Create CSV file with headers if it doesn't exist"""
        if not self.output_file.exists():
            with open(self.output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "repository",
                    "package",
                    "version",
                    "status",
                    "vulnerability_count"
                ])

    def collect_from_database(self):
        """Extract data from sbom_common database"""

        db = get_db_storage()

        if not db._connect():
            print("[DATA COLLECTOR] Database connection failed.")
            return

        query = """
            SELECT 
                s.target_name,
                p.package_name,
                v.version_number,
                v.status,
                COUNT(sr.vulnerability_id) AS vuln_count
            FROM scan s
            JOIN versions v ON v.version_id = (
                SELECT MAX(v2.version_id)
                FROM versions v2
                WHERE v2.package_id = v.package_id
            )
            JOIN packages p ON p.package_id = v.package_id
            LEFT JOIN scan_results sr ON sr.version_id = v.version_id
            GROUP BY s.target_name, p.package_name, v.version_number, v.status
        """

        rows_to_write = []
        timestamp = datetime.now().isoformat()

        try:
            with db.connection.cursor() as cursor:
                cursor.execute(query)
                results = cursor.fetchall()

                for row in results:
                    rows_to_write.append([
                        timestamp,
                        row["target_name"],
                        row["package_name"],
                        row["version_number"],
                        row["status"],
                        row["vuln_count"]
                    ])

        except Exception as e:
            print("[DATA COLLECTOR] Query failed:", e)
            return

        if not rows_to_write:
            print("[DATA COLLECTOR] No data found in database.")
            return

        with open(self.output_file, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows_to_write)

        print(f"[DATA COLLECTOR] Stored {len(rows_to_write)} rows in version_dataset.csv")


# ============================
# Run directly from terminal
# ============================

if __name__ == "__main__":
    collector = DataCollector()
    collector.collect_from_database()