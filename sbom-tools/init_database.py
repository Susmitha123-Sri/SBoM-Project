# sbom-tools/init_database.py

import mysql.connector


DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "root123"
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

    connection.commit()

    print("Tables created")

    cursor.close()
    connection.close()


if __name__ == "__main__":

    create_database()
    create_tables()

    print("Database setup complete")