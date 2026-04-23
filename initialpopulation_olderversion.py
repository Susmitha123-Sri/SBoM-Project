import csv
from db_storage import get_db_storage

def initial_population():

    db = get_db_storage()

    scan_id = db.insert_scan("initial_dataset")

    with open("older_versions_dataset.csv", "r") as file:

        reader = csv.DictReader(file)

        for row in reader:

            package = row["package_name"]
            ecosystem = row["ecosystem"]
            version = row["older_version"]

            package_id = db.insert_package(package, ecosystem)

            db.insert_version(
                scan_id=scan_id,
                package_id=package_id,
                version=version,
                status="baseline",
                latest_version=version
            )


if __name__ == "__main__":
    initial_population()