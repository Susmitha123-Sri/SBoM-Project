# sbom-tools/test_exclude_seed_repos.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# dataset/exclude_seed_repos.py: the dry run writes nothing; --apply drops
# exactly the 5 excluded rows and keeps every other line byte for byte (CRLF
# and LF), writes seed_v2_excluded.csv and adds only the new key to the
# criteria record; it stops with nothing written when a repo is missing or
# duplicated, a report file or a database row exists, the database is down,
# the excluded file exists or the JSON could not be rewritten unchanged; a
# second run says "already applied". Temporary folders only; the database
# check is a fake (no MySQL, no network).

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = Path(TESTS_DIR).parent
sys.path.insert(0, TESTS_DIR)
sys.path.insert(0, str(PROJECT_ROOT / "dataset"))

import exclude_seed_repos as esr                     # noqa: E402

HEADER = "name,url,language,stars,forks,last_push,dependency_files"
EXCLUDED_ROWS = {
    "bytedance/fedlearner": "Python", "ivopetiz/algotrading": "Python",
    "doramart/DoraCMS": "JavaScript", "fecommunity/reactpress": "TypeScript",
    "hackclub/sprig": "JavaScript",
}
RECORD = {"dataset": "seed_v2", "counts": {"selected_total": 1000}, "notes": ["a", "b"]}


def seed_line(name, language):
    dep = "requirements.txt" if language == "Python" else "package.json"
    return f"{name},https://github.com/{name},{language},900,90,2026-10-01,{dep}"


class ExcludeTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.reports = self.dir / "reports"
        self.reports.mkdir()
        self.seed = self.dir / "seed_v2.csv"
        self.criteria = self.dir / "seed_v2_criteria.json"
        self.excluded = self.dir / "seed_v2_excluded.csv"
        self.scans = {}
        self.write_seed()
        self.criteria.write_bytes((json.dumps(RECORD, indent=2) + "\n")
                                  .replace("\n", "\r\n").encode("utf-8"))

    def write_seed(self, newline="\r\n", extra=(), skip=()):
        lines = [HEADER]
        excluded = iter(EXCLUDED_ROWS.items())
        for i in range(995):
            lines.append(seed_line(f"own{i}/repo{i}", "Python" if i < 498 else "TypeScript"))
            if i % 200 == 7:                                   # spread through the file
                name, language = next(excluded, (None, None))
                if name and name not in skip:
                    lines.append(seed_line(name, language))
        lines.extend(extra)
        self.seed.write_bytes((newline.join(lines) + newline).encode("utf-8"))

    def db_check(self, urls):
        if self.scans == "down":
            raise ConnectionError("refused")
        return {url: self.scans.get(url, []) for url in urls}

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = esr.main(list(argv), seed_csv=self.seed, criteria=self.criteria,
                            excluded=self.excluded, reports_dir=self.reports,
                            db_check=self.db_check, today=date(2026, 11, 19))
        return code, out.getvalue()

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.dir.iterdir() if p.is_file()}


class TestExclude(ExcludeTestCase):

    def test_dry_run_writes_nothing(self):
        before = self.snapshot()
        code, out = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(self.snapshot(), before)
        self.assertIn("all 5 found once among 1000 rows", out)
        self.assertIn("Repos after: 995 (python 498, js_ts 497)", out)
        self.assertIn("Dry run. Nothing was written.", out)

    def test_apply_keeps_every_other_line(self):
        for newline in ("\r\n", "\n"):
            with self.subTest(newline=repr(newline)):
                self.excluded.unlink(missing_ok=True)
                self.criteria.write_text(json.dumps(RECORD, indent=2) + "\n", encoding="utf-8")
                self.write_seed(newline)
                before = self.seed.read_bytes().splitlines(keepends=True)
                code, out = self.run_main("--apply")
                self.assertEqual(code, 0, out)
                after = self.seed.read_bytes().splitlines(keepends=True)
                expected = [line for line in before
                            if not any(f",https://github.com/{n}," in line.decode()
                                       for n in EXCLUDED_ROWS)]
                self.assertEqual(after, expected)
                self.assertEqual(len(after), 996)                       # header + 995
                self.assertTrue(all(line.endswith(newline.encode()) for line in after))

    def test_excluded_csv(self):
        self.run_main("--apply")
        raw = self.excluded.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))               # no BOM
        self.assertIn(b"\r\n", raw)                                     # same line ending
        with open(self.excluded, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual(list(rows[0]), ["name", "url", "language", "reason"])
        self.assertEqual([r["name"] for r in rows],                     # seed order
                         ["bytedance/fedlearner", "ivopetiz/algotrading", "doramart/DoraCMS",
                          "fecommunity/reactpress", "hackclub/sprig"])
        reasons = {r["name"]: r["reason"] for r in rows}
        self.assertEqual(reasons["fecommunity/reactpress"], esr.NOT_FOUND)
        self.assertEqual(reasons["hackclub/sprig"], esr.ILLEGAL_NAMES)
        self.assertEqual({r["name"]: r["language"] for r in rows}, EXCLUDED_ROWS)

    def test_criteria_gets_only_the_new_key(self):
        self.run_main("--apply")
        text = self.criteria.read_bytes().decode("utf-8")
        self.assertIn("\r\n", text)                                     # line endings kept
        self.assertNotIn("\n", text.replace("\r\n", ""))
        record = json.loads(text)
        new = record.pop(esr.KEY)
        self.assertEqual(record, RECORD)                                # old fields unchanged
        self.assertEqual(list(json.loads(text))[-1], esr.KEY)          # added at the end
        self.assertEqual(new["final_count"], 995)
        self.assertEqual(new["final_by_group"], {"python": 498, "js_ts": 497})
        self.assertEqual(new["date"], "2026-11-19")
        self.assertEqual(len(new["repos"]), 5)
        self.assertIn("995", new["note"])

    def test_second_run_is_already_applied(self):
        self.run_main("--apply")
        before = self.snapshot()
        code, out = self.run_main("--apply")
        self.assertEqual(code, 0)
        self.assertIn("Already applied", out)
        self.assertEqual(self.snapshot(), before)


class TestRefusals(ExcludeTestCase):

    def assert_refused(self, text, *argv):
        before = self.snapshot()
        code, out = self.run_main("--apply", *argv)
        self.assertEqual(code, 2, out)
        self.assertIn("Stopped, nothing written", out)
        self.assertIn(text, out)
        self.assertEqual(self.snapshot(), before)

    def test_missing_repo(self):
        self.write_seed(skip=("hackclub/sprig",),
                        extra=[seed_line("filler/x", "Python")])
        self.assert_refused("https://github.com/hackclub/sprig (0x)")

    def test_duplicate_repo(self):
        self.write_seed(extra=[seed_line("doramart/DoraCMS", "JavaScript")])
        self.assert_refused("https://github.com/doramart/DoraCMS (2x)")

    def test_wrong_row_count(self):
        self.write_seed(extra=[seed_line("filler/x", "Python")])
        self.assert_refused("has 1001 rows, expected 1000")

    def test_report_file_exists(self):
        (self.reports / "hackclub-sprig.json").write_text("{}", encoding="utf-8")
        self.assert_refused("hackclub-sprig.json")

    def test_database_row_exists(self):
        self.scans = {"https://github.com/ivopetiz/algotrading": [455]}
        self.assert_refused("https://github.com/ivopetiz/algotrading (scan [455])")

    def test_database_down(self):
        self.scans = "down"
        self.assert_refused("database not reachable (ConnectionError: refused)")

    def test_excluded_file_exists(self):
        self.excluded.write_text("old", encoding="utf-8")
        self.assert_refused("seed_v2_excluded.csv already exists")

    def test_criteria_not_in_dump_form(self):
        self.criteria.write_text(json.dumps(RECORD), encoding="utf-8")   # one line
        self.assert_refused("not in json.dumps(indent=2) form")

    def test_failed_write_keeps_the_old_file(self):
        before = self.seed.read_bytes()
        with mock.patch.object(esr.os, "replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                esr.write_atomic(self.seed, b"new")
        self.assertEqual(self.seed.read_bytes(), before)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()),
                         ["reports", "seed_v2.csv", "seed_v2_criteria.json"])


if __name__ == "__main__":
    unittest.main()
