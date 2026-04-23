import pymysql
import requests
import csv

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "root",
    "password": "root123",
    "database": "sbom_common",
    "cursorclass": pymysql.cursors.DictCursor
}


def get_packages():
    connection = pymysql.connect(**DB_CONFIG)

    with connection.cursor() as cursor:
        cursor.execute("SELECT package_name, ecosystem FROM packages")
        packages = cursor.fetchall()

    connection.close()
    return packages


def get_old_version(package):

    try:
        url = f"https://pypi.org/pypi/{package}/json"
        r = requests.get(url, timeout=10)

        if r.status_code != 200:
            return None

        data = r.json()
        versions = sorted(data["releases"].keys())

        if len(versions) >= 3:
            return versions[-3]   # 2–3 versions older
        elif len(versions) > 0:
            return versions[0]

        return None

    except:
        return None


def generate_dataset():

    packages = get_packages()

    with open("older_versions_dataset.csv", "w", newline="") as f:

        writer = csv.writer(f)

        writer.writerow([
            "package_name",
            "ecosystem",
            "older_version"
        ])

        for pkg in packages:

            package_name = pkg["package_name"]
            ecosystem = pkg["ecosystem"]

            if ecosystem != "python":
                continue

            old_version = get_old_version(package_name)

            if old_version:
                writer.writerow([
                    package_name,
                    ecosystem,
                    old_version
                ])


if __name__ == "__main__":
    generate_dataset()