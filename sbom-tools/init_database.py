# sbom-tools/init_database.py

import os
from pathlib import Path

import mysql.connector
from dotenv import load_dotenv

# The password comes from the environment or the project's .env (DB_PASSWORD), never the code
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": os.environ.get("DB_PASSWORD", "")
}

DATABASE_NAME = "sbom_common"


def create_database():

    connection = mysql.connector.connect(**DB_CONFIG)
    cursor = connection.cursor()

    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DATABASE_NAME}")

    print("Database ready")

    cursor.close()
    connection.close()


def create_tables():

    connection = mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        database=DATABASE_NAME
    )

    cursor = connection.cursor()

    # ==============================
    # SCAN TABLE
    # ==============================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan (
        scan_id INT AUTO_INCREMENT PRIMARY KEY,
        target_name VARCHAR(255),
        scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # ==============================
    # PACKAGES TABLE
    # ==============================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        package_id INT AUTO_INCREMENT PRIMARY KEY,
        package_name VARCHAR(255),
        ecosystem VARCHAR(100)
    )
    """)

    # ==============================
    # VERSIONS TABLE
    # ==============================
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS versions (
        version_id INT AUTO_INCREMENT PRIMARY KEY,

        scan_id INT,
        package_id INT,

        package_name VARCHAR(255),

        version_number VARCHAR(100),
        latest_version VARCHAR(100),

        status VARCHAR(50),
        days_outdated INT DEFAULT 0,
        versions_behind VARCHAR(50),
        severity_level VARCHAR(50),
        days_since_release INT NULL,
        age_tier VARCHAR(20) NULL,

        baseline_status VARCHAR(50) DEFAULT 'inactive',

        release_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        
                 
        INDEX idx_scan_id (scan_id),
        INDEX idx_package_name (package_name),

        FOREIGN KEY (scan_id)
            REFERENCES scan(scan_id)
            ON DELETE CASCADE,

        FOREIGN KEY (package_id)
            REFERENCES packages(package_id)
            ON DELETE CASCADE
    )
    """)

    # ==============================
    # VERSION HISTORY
    # ==============================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS version_history (
        history_id INT AUTO_INCREMENT PRIMARY KEY,

        package_id INT,

        old_version VARCHAR(100),
        new_version VARCHAR(100),

        changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (package_id)
            REFERENCES packages(package_id)
            ON DELETE CASCADE
    )
    """)

    # ==============================
    # VULNERABILITY TABLE
    # ==============================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerability (
        vulnerability_id VARCHAR(100) PRIMARY KEY,
        severity VARCHAR(50),
        description TEXT
    )
    """)

    # ==============================
    # SCAN RESULTS
    # ==============================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        spr_id INT AUTO_INCREMENT PRIMARY KEY,

        scan_id INT,
        version_id INT,
        vulnerability_id VARCHAR(100),

        fixed_version VARCHAR(100),

        detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (scan_id)
            REFERENCES scan(scan_id)
            ON DELETE CASCADE,

        FOREIGN KEY (version_id)
            REFERENCES versions(version_id)
            ON DELETE CASCADE,

        FOREIGN KEY (vulnerability_id)
            REFERENCES vulnerability(vulnerability_id)
            ON DELETE CASCADE
    )
    """)

    # ==============================
    # EXISTING DATABASES: ADD NEW COLUMNS
    # (nullable, so existing rows are left as-is;
    #  age_tier is filled in by the next /run-monitor)
    # ==============================

    for column, definition in (
        ("days_since_release", "INT NULL"),
        ("age_tier", "VARCHAR(20) NULL"),
    ):
        cursor.execute("""
        SELECT COUNT(*)
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s
          AND TABLE_NAME = 'versions'
          AND COLUMN_NAME = %s
        """, (DATABASE_NAME, column))

        if cursor.fetchone()[0] == 0:
            cursor.execute(f"ALTER TABLE versions ADD COLUMN {column} {definition}")
            print(f"Added column versions.{column}")

    # ==============================
    # SETTINGS TABLE (shared app settings)
    # ==============================

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        setting_key VARCHAR(100) PRIMARY KEY,
        setting_value VARCHAR(255) NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP
    )
    """)

    default_settings = {
        "rescan_interval_value": "6",
        "rescan_interval_unit": "hours",
        "age_threshold_days": "365",
    }

    for key, value in default_settings.items():
        cursor.execute(
            "INSERT IGNORE INTO settings (setting_key, setting_value) VALUES (%s, %s)",
            (key, value)
        )

    connection.commit()

    print("Tables created")

    cursor.close()
    connection.close()


if __name__ == "__main__":

    create_database()
    create_tables()

    print("Database setup complete")