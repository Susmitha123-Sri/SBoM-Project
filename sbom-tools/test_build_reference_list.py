# sbom-tools/test_build_reference_list.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# build_reference_list.py: preview by default, --apply writes only the
# reference CSV (de-duplicated, sources merged), missing inputs exit 2, the
# output loads in name_match, and the coverage summary. No network; SQLite
# stand-in for the packages read (see fake_mysql.py).

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build_reference_list                          # noqa: E402
import db_storage                                    # noqa: E402
from fake_mysql import SqliteTestCase                # noqa: E402
from name_match import load_candidates               # noqa: E402
from test_reference_sources import make_package_lists, make_purl2cpe_zip   # noqa: E402


class BuildTestCase(SqliteTestCase):

    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.lists = make_package_lists(self.dir / "Package-List")
        self.zip = make_purl2cpe_zip(self.dir / "purl2cpe.db.zip")
        self.cache = self.dir / "release_cache.json"
        self.cache.write_text(json.dumps({
            "pypi:requests": {"versions": {}},
            "pypi:only-in-cache": {"versions": {}},
            "pypi:missing-everywhere": None,          # a miss: not a known name
            "npm:lodash": {"versions": {}},
        }), encoding="utf-8")
        self.out = self.dir / "reference_names.csv"

        self.sqlite.executescript("""
            INSERT INTO packages (package_id, package_name, ecosystem) VALUES
                (1, 'requests', 'pypi'), (2, 'flask', 'pypi'), (3, 'django', 'pypi'),
                (4, 'lodash', 'npm'), (5, 'unknown-thing', 'pypi');
        """)
        self.sqlite.commit()
        patcher = mock.patch.object(db_storage, "get_db_storage", lambda: self.db)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *args, lists=None, zip_path=None, cache=None):
        argv = ["--package-lists", str(self.lists if lists is None else lists),
                "--purl2cpe", str(self.zip if zip_path is None else zip_path),
                "--release-cache", str(self.cache if cache is None else cache),
                "--out", str(self.out), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = build_reference_list.main(argv)
        return code, out.getvalue()

    def written(self):
        with open(self.out, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))


class TestBuildReferenceList(BuildTestCase):

    def test_preview_writes_nothing(self):
        code, out = self.run_cli()
        self.assertEqual(code, 0)
        self.assertFalse(self.out.exists())
        self.assertFalse(list(self.dir.glob("*.tmp")))
        self.assertIn("Preview only", out)

    def test_apply_writes_merged_unique_names(self):
        code, out = self.run_cli("--apply")
        self.assertEqual(code, 0)
        rows = self.written()
        keys = [(r["ecosystem"], r["name"]) for r in rows]
        self.assertEqual(len(keys), len(set(keys)), "no duplicate names")
        by_key = {(r["ecosystem"], r["name"]): r["source"] for r in rows}
        self.assertEqual(by_key[("pypi", "requests")], "package-list+release-cache")
        self.assertEqual(by_key[("npm", "lodash")], "package-list+purl2cpe+release-cache")
        self.assertEqual(by_key[("pypi", "django")], "purl2cpe")
        self.assertEqual(by_key[("maven", "org.apache.logging.log4j:log4j-core")],
                         "package-list+purl2cpe")
        self.assertEqual(by_key[("pypi", "only-in-cache")], "release-cache")
        self.assertNotIn(("pypi", "missing-everywhere"), by_key)
        self.assertEqual({r["ecosystem"] for r in rows}, {"pypi", "npm", "maven"})
        self.assertNotIn(("deb", "node-lodash"), by_key)      # only pypi/npm/maven

    def test_output_loads_in_name_match(self):
        self.run_cli("--apply")
        self.assertIn(("flask", "pypi"), load_candidates(self.out))

    def test_purl2cpe_counts_are_reported(self):
        _, out = self.run_cli()
        self.assertIn("(purl, cpe) relations: pypi 2, npm 2, maven 1", out)
        self.assertIn("distinct base PURLs:   pypi 1, npm 2, maven 1", out)

    def test_coverage_counts_newly_matched_packages(self):
        """flask and django are not in the release cache but are in the new list"""
        _, out = self.run_cli()
        self.assertIn("newly matched: 2", out)
        self.assertIn("flask (pypi): unmatched -> matched", out)

    def test_sources_can_be_left_out(self):
        code, _ = self.run_cli("--apply", "--no-coverage", lists="", zip_path="")
        self.assertEqual(code, 0)
        self.assertEqual({r["name"] for r in self.written()},
                         {"requests", "only-in-cache", "lodash"})

    def test_missing_inputs_exit_2(self):
        for kwargs in ({"lists": self.dir / "nope"}, {"zip_path": self.dir / "nope.zip"},
                       {"cache": self.dir / "nope.json"},
                       {"lists": "", "zip_path": "", "cache": ""}):
            code, out = self.run_cli(**kwargs)
            self.assertEqual(code, 2, kwargs)
            self.assertIn("Error", out)
        self.assertFalse(self.out.exists())

    def test_never_writes_the_database(self):
        before = self.rows("SELECT * FROM packages")
        self.run_cli("--apply")
        self.assertEqual(self.rows("SELECT * FROM packages"), before)


if __name__ == "__main__":
    import unittest
    unittest.main()
