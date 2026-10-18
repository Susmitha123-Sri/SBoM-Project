# sbom-tools/test_reference_sources.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# Readers for the external reference files (reference_sources.py): the
# Package-List CSVs, PURL and CPE parsing, purl2cpe.db.zip, and repository
# URL normalization. No network: small fixture files in a temp folder, built
# to the real formats. make_package_lists() / make_purl2cpe_zip() are also
# used by test_build_reference_list.py and test_propose_labeled_pairs.py.

import csv
import os
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reference_sources import (                    # noqa: E402
    Purl, iter_package_lists, normalize_repo_url, package_list_files, parse_cpe, parse_purl,
    purl_ecosystem, purl_package_name, read_package_list_csv, read_purl2cpe,
)

HEADER = ["ID", "Platform", "Name", "Homepage URL", "Repository URL"]

# One CSV per ecosystem, as Package-List-Miner writes them (missing URL = "nan")
PACKAGE_LISTS = {
    "PyPI.csv": [
        ("PyPI", "requests", "https://requests.readthedocs.io", "https://github.com/psf/requests"),
        ("PyPI", "protobuf", "nan", "https://github.com/protocolbuffers/protobuf.git"),
        ("PyPI", "bitflags", "nan", "https://github.com/someone/bitflags-py"),
        ("PyPI", "semver", "nan", "https://github.com/python-semver/python-semver"),
        ("PyPI", "flask", "nan", "https://github.com/pallets/flask/"),
        ("PyPI", "no-repo-pkg", "nan", "nan"),
        ("PyPI", "tree-sitter", "nan", "https://github.com/tree-sitter/tree-sitter"),
    ],
    "NPM.csv": [
        ("NPM", "google-protobuf", "nan", "git+https://github.com/protocolbuffers/protobuf.git"),
        ("NPM", "bitflags", "nan", "https://github.com/other/bitflags-js"),
        ("NPM", "semver", "nan", "https://github.com/npm/node-semver"),
        ("NPM", "@babel/core", "nan", "https://github.com/babel/babel"),
        ("NPM", "lodash", "nan", "https://github.com/lodash/lodash"),
        ("NPM", "tree-sitter", "nan", "https://github.com/tree-sitter/tree-sitter.git"),
    ],
    "Maven.csv": [
        ("Maven", "com.google.protobuf:protobuf-java", "nan",
         "https://github.com/protocolbuffers/protobuf"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "nan", "https://gitbox.apache.org/log4j"),
    ],
    "Crates.csv": [
        ("Crates", "bitflags", "nan", "https://github.com/bitflags/bitflags"),
    ],
}

# purl2cpe rows: every PURL of a product x every CPE of that product
PURL2CPE_ROWS = [
    ("pkg:pypi/django", "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"),
    ("pkg:pypi/django", "cpe:2.3:a:djangoproject:django:0.91:*:*:*:*:*:*:*"),
    ("pkg:github/django/django", "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"),
    ("pkg:github/django/django", "cpe:2.3:a:djangoproject:django:0.91:*:*:*:*:*:*:*"),
    ("pkg:docker/django/django", "cpe:2.3:a:djangoproject:django:0.91:*:*:*:*:*:*:*"),
    ("pkg:npm/lodash", "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"),
    ("pkg:deb/debian/node-lodash", "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"),
    ("pkg:maven/org.apache.logging.log4j/log4j-core",
     "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"),
    ("pkg:npm/%40babel/core", "cpe:2.3:a:babeljs:babel:7.0.0:*:*:*:*:node.js:*:*"),
    ("not a purl", "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"),
]


def make_package_lists(folder, files=PACKAGE_LISTS):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    for file_name, rows in files.items():
        with open(folder / file_name, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(HEADER)
            for i, row in enumerate(rows, start=1):
                writer.writerow([i, *row])
    return folder


def make_purl2cpe_zip(path, rows=PURL2CPE_ROWS):
    """A purl2cpe.db.zip with the real table, like scanoss/purl2cpe ships it."""
    path = Path(path)
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "purl2cpe.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE IF NOT EXISTS purl2cpe(purl TEXT, cpe TEXT, UNIQUE(purl,cpe))")
        conn.executemany("INSERT INTO purl2cpe (purl, cpe) VALUES (?, ?) ON CONFLICT DO NOTHING",
                         rows)
        conn.commit()
        conn.close()
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_path, "purl2cpe.db")
    return path


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)


class TestPackageLists(TempDirTestCase):

    def test_platforms_are_mapped_and_others_skipped(self):
        folder = make_package_lists(self.dir / "lists")
        rows = list(iter_package_lists(folder))
        ecos = {eco for _, eco, _ in rows}
        self.assertEqual(ecos, {"pypi", "npm", "maven"})
        self.assertNotIn(("bitflags", "crates"), {(n, e) for n, e, _ in rows})
        self.assertEqual(len(rows), 15)

    def test_nan_is_none(self):
        rows = {n: url for n, _, url in iter_package_lists(make_package_lists(self.dir / "l"))}
        self.assertIsNone(rows["no-repo-pkg"])
        self.assertEqual(rows["requests"], "https://github.com/psf/requests")

    def test_names_are_kept_as_written(self):
        names = {n for n, _, _ in iter_package_lists(make_package_lists(self.dir / "l"))}
        self.assertIn("@babel/core", names)
        self.assertIn("com.google.protobuf:protobuf-java", names)

    def test_wrong_columns_are_rejected(self):
        path = self.dir / "bad.csv"
        path.write_text("name,ecosystem\nrequests,pypi\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not a Package-List CSV"):
            list(read_package_list_csv(path))

    def test_missing_folder(self):
        with self.assertRaises(FileNotFoundError):
            package_list_files(self.dir / "nope")


class TestRepoUrls(unittest.TestCase):

    def test_variants_normalize_to_one_form(self):
        for url in ("https://github.com/Psf/Requests", "https://github.com/psf/requests.git",
                    "https://github.com/psf/requests/", "git+https://github.com/psf/requests.git",
                    "git@github.com:psf/requests.git", "https://github.com/psf/requests#readme",
                    "https://github.com/psf/requests/tree/main"):
            self.assertEqual(normalize_repo_url(url), "github.com/psf/requests", url)

    def test_missing_or_not_github(self):
        for url in (None, "", "nan", "https://gitlab.com/a/b", "https://example.org"):
            self.assertIsNone(normalize_repo_url(url), url)


class TestPurl(unittest.TestCase):

    def test_pypi(self):
        self.assertEqual(parse_purl("pkg:pypi/django@4.2"), Purl("pypi", None, "django", "4.2"))

    def test_npm_scope_is_decoded(self):
        p = parse_purl("pkg:npm/%40babel/core@7.0.0")
        self.assertEqual(p, Purl("npm", "@babel", "core", "7.0.0"))
        self.assertEqual(purl_package_name(p), "@babel/core")

    def test_maven_namespace(self):
        p = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1?type=jar")
        self.assertEqual(purl_package_name(p), "org.apache.logging.log4j:log4j-core")
        self.assertEqual(p.version, "2.17.1")

    def test_qualifiers_and_subpath_are_dropped(self):
        p = parse_purl("pkg:github/django/django?vcs=git#docs")
        self.assertEqual((p.namespace, p.name, p.version), ("django", "django", None))
        self.assertEqual(purl_package_name(p), "django/django")

    def test_ecosystems(self):
        self.assertEqual(purl_ecosystem("PyPI"), "pypi")
        self.assertEqual(purl_ecosystem("deb"), "deb")

    def test_bad_purls(self):
        for bad in ("", "django", "pkg:", "pkg:pypi", "pkg:pypi/", "pkg:npm/@1.0"):
            with self.assertRaises(ValueError, msg=bad):
                parse_purl(bad)


class TestCpe(unittest.TestCase):

    def test_fields(self):
        c = parse_cpe(r"cpe:2.3:a:aerospike:aerospike\_server:4.0.0.1:*:*:*:community:*:*:*")
        self.assertEqual((c.part, c.vendor, c.product, c.version),
                         ("a", "aerospike", "aerospike_server", "4.0.0.1"))

    def test_not_a_cpe(self):
        with self.assertRaises(ValueError):
            parse_cpe("cpe:/a:vendor:product")


class TestPurl2Cpe(TempDirTestCase):

    def test_reads_distinct_base_purls_per_product(self):
        data = read_purl2cpe(make_purl2cpe_zip(self.dir / "purl2cpe.db.zip"))

        self.assertEqual(data.products[("djangoproject", "django")],
                         {"pkg:pypi/django", "pkg:github/django/django", "pkg:docker/django/django"})
        self.assertEqual(data.products[("lodash", "lodash")],
                         {"pkg:npm/lodash", "pkg:deb/debian/node-lodash"})
        self.assertEqual(data.bad_rows, 1)

    def test_counts_per_purl_type(self):
        data = read_purl2cpe(make_purl2cpe_zip(self.dir / "purl2cpe.db.zip"))
        self.assertEqual(data.relations_by_type["pypi"], 2)       # (purl, cpe) rows
        self.assertEqual(data.purls_by_type["pypi"], 1)           # distinct base PURLs
        self.assertEqual(data.purls_by_type["npm"], 2)            # lodash, @babel/core
        self.assertEqual(data.purls_by_type["maven"], 1)

    def test_missing_zip_and_zip_without_db(self):
        with self.assertRaises(FileNotFoundError):
            read_purl2cpe(self.dir / "nope.zip")
        empty = self.dir / "empty.zip"
        with zipfile.ZipFile(empty, "w") as zf:
            zf.writestr("readme.txt", "no db")
        with self.assertRaisesRegex(ValueError, "no .db"):
            read_purl2cpe(empty)


if __name__ == "__main__":
    unittest.main()
