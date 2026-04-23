
#!/usr/bin/env python
# coding: utf-8
"""
Test script for database storage
"""

import sys
from pathlib import Path

# Add sbom-tools to path
sys.path.insert(0, str(Path(__file__).parent / "sbom-tools"))

from db_storage import get_db_storage
from datetime import datetime

def main():
    print("=" * 60)
    print("Testing Database Storage")
    print("=" * 60)
    print()
    
    # Get database storage instance
    print("1. Creating database storage instance...")
    db_storage = get_db_storage()
    print("   [OK] Instance created\n")
    
    # Test connection
    print("2. Testing database connection...")
    if db_storage._connect():
        print("   [OK] Database connection successful!\n")
    else:
        print("   [ERROR] Database connection failed!")
        print("   Please check:")
        print("   - MySQL server is running")
        print("   - Network connection to 10.14.64.11:9838")
        print("   - Database 'sbom_monitor' exists")
        print("   - User 'u1' has proper permissions")
        return
    
    # Test with sample report data
    print("3. Testing data storage with sample report...")
    test_report = {
        'scan_id': 'test-scan-' + datetime.now().strftime('%Y%m%d-%H%M%S'),
        'target': 'https://github.com/test/repo',
        'timestamp': datetime.now().isoformat(),
        'packages': [
            {
                'package': 'test-package-1',
                'version': '1.0.0',
                'type': 'npm',
                'vulnerability_id': 'CVE-2024-1234',
                'severity': 'high',
                'fixed_version': '1.0.1'
            },
            {
                'package': 'test-package-2',
                'version': '2.0.0',
                'type': 'pypi',
                'vulnerability_id': 'CVE-2024-5678',
                'severity': 'critical',
                'fixed_version': '2.0.1'
            },
            {
                'package': 'test-package-3',
                'version': '3.0.0',
                'type': 'maven',
                'vulnerability_id': 'None',
                'severity': 'None',
                'fixed_version': 'N/A'
            }
        ],
        'summary': {
            'total_packages': 3,
            'total_vulnerabilities': 2
        }
    }
    
    if db_storage.store_report(test_report):
        print(f"   [OK] Test data saved successfully!")
        print(f"   Scan ID: {test_report['scan_id']}")
        print(f"   Vulnerabilities stored: 2 (package 3 has no vulnerabilities, so not stored)\n")
    else:
        print("   [ERROR] Failed to save test data\n")
    
    # Test query to verify data
    print("4. Verifying stored data...")
    try:
        with db_storage.connection.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*) as count 
                FROM sbom_report 
                WHERE scan_id_target LIKE %s
            """, (f"{test_report['scan_id']}%",))
            result = cursor.fetchone()
            count = result['count'] if result else 0
            print(f"   [OK] Found {count} records in database for test scan\n")
            
            # Show sample records
            cursor.execute("""
                SELECT package, version, severity, vulnerability_id 
                FROM sbom_report 
                WHERE scan_id_target LIKE %s
                LIMIT 5
            """, (f"{test_report['scan_id']}%",))
            records = cursor.fetchall()
            if records:
                print("   Sample records:")
                for record in records:
                    print(f"     - {record['package']} {record['version']} ({record['severity']}) - {record['vulnerability_id']}")
    except Exception as e:
        print(f"   [ERROR] Failed to verify data: {e}\n")
    
    # Close connection
    print("5. Closing database connection...")
    db_storage.close()
    print("   [OK] Connection closed\n")
    
    print("=" * 60)
    print("Test completed!")
    print("=" * 60)

if __name__ == "__main__":
    main()

