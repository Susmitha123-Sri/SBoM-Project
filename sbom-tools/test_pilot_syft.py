# sbom-tools/test_pilot_syft.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# dataset/pilot_syft.py: the 8/4/8 sample and its reproducibility, preview
# runs nothing and writes nothing, git and Syft commands, lock files,
# package counts by type, sizes and timings, temporary clones outside the
# project and always deleted, failures recorded without stopping the run,
# the results CSV and the summary. git and Syft are a fake runner: a real
# subprocess call fails the test. No database is used.

import contextlib
import csv
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "dataset"))

import pilot_syft                                    # noqa: E402
from pilot_syft import (                             # noqa: E402
    BUNDLED_SYFT, COLUMNS, SAMPLE_SIZES, count_packages, group_of, sample,
)

SEED_COLUMNS = ["name", "url", "language", "stars", "forks", "last_push", "dependency_files"]


def seed_rows():
    """12 pyproject-only, 6 requirements-only, 4 both, 12 JS/TS repos."""
    rows = []

    def add(name, language, files):
        rows.append({"name": name, "url": f"https://github.com/{name}", "language": language,
                     "stars": "1000", "forks": "100", "last_push": "2026-10-01",
                     "dependency_files": files})

    for i in range(12):
        add(f"py/pyproject-{i:02d}", "Python", "pyproject.toml")
    for i in range(6):
        add(f"py/requirements-{i:02d}", "Python", "requirements.txt")
    for i in range(4):
        add(f"py/both-{i:02d}", "Python", "pyproject.toml;requirements.txt")
    for i in range(12):
        add(f"js/app-{i:02d}", "TypeScript" if i % 2 else "JavaScript", "package.json")
    return rows


def write_seed(path, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SEED_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


class FakeRunner:
    """
    Stands in for subprocess.run. "git clone" creates the clone folder with
    the files in clones[url] (default: one file, no lock file) plus a
    read-only pack file; clones[url] = "fail" / "timeout" simulate errors.
    Syft returns syft[url] artifacts, or "fail" / "badjson" / "timeout".
    Clone takes 3 s and Syft 2 s on the fake clock.
    """

    def __init__(self, clock, clones=None, syft=None):
        self.clock = clock
        self.clones = clones or {}
        self.syft = syft or {}
        self.calls = []
        self.dir_to_url = {}
        self.clone_dirs = []

    def __call__(self, cmd, **kwargs):
        self.calls.append({"cmd": list(cmd), **kwargs})
        if cmd[1] == "clone":
            return self.clone(cmd, kwargs)
        return self.scan(cmd, kwargs)

    def clone(self, cmd, kwargs):
        url, dest = cmd[-2], Path(cmd[-1])
        behaviour = self.clones.get(url, ["README.md"])
        self.clock.now += 3
        if behaviour == "timeout":
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        if behaviour == "fail":
            return subprocess.CompletedProcess(cmd, 128, "", "Cloning...\nfatal: repository not found\n")
        pack = dest / ".git" / "objects" / "pack" / "pack-1.pack"
        pack.parent.mkdir(parents=True)
        pack.write_bytes(b"x" * 1024 * 1024)            # 1 MB
        os.chmod(pack, stat.S_IREAD)                     # read-only, like git on Windows
        for name in behaviour:
            (dest / name).write_bytes(b"y" * 1024 * 512)  # 0.5 MB each
        self.dir_to_url[str(dest)] = url
        self.clone_dirs.append(dest)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def scan(self, cmd, kwargs):
        target = cmd[1][len("dir:"):]
        url = self.dir_to_url[target]
        behaviour = self.syft.get(url, [])
        self.clock.now += 2
        if behaviour == "timeout":
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout"))
        if behaviour == "fail":
            return subprocess.CompletedProcess(cmd, 1, "", "error: could not catalog\n")
        if behaviour == "badjson":
            return subprocess.CompletedProcess(cmd, 0, "not json", "")
        return subprocess.CompletedProcess(cmd, 0, json.dumps({"artifacts": behaviour}), "")


def artifacts(*items):
    """artifacts(("requests", "2.31.0", "python"), ...)"""
    return [{"name": n, "version": v, "type": t} for n, v, t in items]


def no_subprocess(*args, **kwargs):
    raise AssertionError("a real subprocess was started")


class PilotTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.seed_csv = self.dir / "seed_v2.csv"
        write_seed(self.seed_csv, seed_rows())
        self.out = self.dir / "pilot_syft_results.csv"
        self.tmp_root = self.dir / "clones"
        self.tmp_root.mkdir()
        self.clock = FakeClock()
        patcher = mock.patch.object(subprocess, "run", no_subprocess)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *args, runner=None):
        argv = ["--seed-csv", str(self.seed_csv), "--out", str(self.out), *args]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = pilot_syft.main(argv, run=runner, clock=self.clock.monotonic,
                                   tmp_root=self.tmp_root)
        return code, out.getvalue()

    def runner(self, **kwargs):
        return FakeRunner(self.clock, **kwargs)

    def results(self):
        with open(self.out, encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def picked(self, seed=42):
        return sample(seed_rows(), seed)


# ============================================================
# Sample
# ============================================================
class TestSample(PilotTestCase):

    def test_groups(self):
        self.assertEqual(group_of({"language": "Python", "dependency_files": "pyproject.toml"}),
                         "py_pyproject")
        self.assertEqual(group_of({"language": "Python", "dependency_files": "requirements.txt"}),
                         "py_requirements")
        self.assertIsNone(group_of({"language": "Python",
                                    "dependency_files": "pyproject.toml;requirements.txt"}))
        self.assertEqual(group_of({"language": "TypeScript", "dependency_files": "package.json"}),
                         "js_ts")
        self.assertIsNone(group_of({"language": "Go", "dependency_files": "go.mod"}))

    def test_8_4_8_from_the_right_groups(self):
        picked = self.picked()
        self.assertEqual(len(picked), 20)
        self.assertEqual({g: sum(r["group"] == g for r in picked) for g in SAMPLE_SIZES},
                         {"py_pyproject": 8, "py_requirements": 4, "js_ts": 8})
        self.assertFalse(any("/both-" in r["name"] for r in picked))
        self.assertEqual(len({r["name"] for r in picked}), 20)

    def test_same_seed_same_sample_whatever_the_row_order(self):
        reordered = list(reversed(seed_rows()))
        self.assertEqual([r["name"] for r in self.picked()],
                         [r["name"] for r in sample(reordered, 42)])

    def test_other_seed_other_sample(self):
        self.assertNotEqual([r["name"] for r in self.picked(42)],
                            [r["name"] for r in self.picked(7)])

    def test_too_small_group_exits_2(self):
        write_seed(self.seed_csv, [r for r in seed_rows() if "requirements" not in r["name"]][:30])
        code, out = self.run_cli()
        self.assertEqual(code, 2)
        self.assertIn("py_requirements has 0 repos", out)

    def test_missing_seed_csv_exits_2(self):
        self.seed_csv.unlink()
        code, _ = self.run_cli()
        self.assertEqual(code, 2)


# ============================================================
# Preview
# ============================================================
class TestPreview(PilotTestCase):

    def test_preview_lists_20_and_runs_nothing(self):
        runner = self.runner()
        code, out = self.run_cli(runner=runner)
        self.assertEqual(code, 0)
        self.assertEqual(runner.calls, [])
        self.assertEqual(len(re.findall(r"^\s+\d+\. ", out, re.M)), 20)
        for r in self.picked():
            self.assertIn(r["name"], out)
        self.assertIn("Preview only: nothing cloned or written", out)
        self.assertFalse(self.out.exists())
        self.assertEqual(list(self.tmp_root.iterdir()), [])

    def test_preview_with_default_runner_starts_no_subprocess(self):
        code, _ = self.run_cli()                 # subprocess.run is patched to fail
        self.assertEqual(code, 0)


# ============================================================
# Run
# ============================================================
class TestRun(PilotTestCase):

    def test_commands(self):
        runner = self.runner()
        code, _ = self.run_cli("--run", runner=runner)
        self.assertEqual(code, 0)
        self.assertEqual(len(runner.calls), 40)
        git_calls = [c for c in runner.calls if c["cmd"][1] == "clone"]
        syft_calls = [c for c in runner.calls if c["cmd"][1] != "clone"]
        self.assertEqual(len(git_calls), 20)

        first = git_calls[0]
        self.assertIn("git", Path(first["cmd"][0]).name.lower())
        self.assertEqual(first["cmd"][1:8], ["clone", "--depth", "1", "--single-branch",
                                             "--no-tags", "-c", "core.longpaths=true"])
        self.assertEqual(first["cmd"][8], self.picked()[0]["url"])
        self.assertEqual(first["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(first["env"]["GIT_LFS_SKIP_SMUDGE"], "1")
        self.assertEqual(first["timeout"], 600)

        for call in syft_calls:
            self.assertEqual(call["cmd"][0], str(BUNDLED_SYFT))
            self.assertTrue(call["cmd"][1].startswith("dir:"))
            self.assertEqual(call["cmd"][2:], ["-o", "json", "-q"])
            self.assertEqual(call["env"]["SYFT_CHECK_FOR_APP_UPDATE"], "false")
        self.assertFalse(any("grype" in str(c["cmd"]).lower() for c in runner.calls))

    def test_lock_files_packages_sizes_and_seconds(self):
        repo = self.picked()[0]["url"]
        runner = self.runner(
            clones={repo: ["pyproject.toml", "poetry.lock", "uv.lock"]},
            syft={repo: artifacts(("requests", "2.31.0", "python"),
                                  ("requests", "2.31.0", "python"),     # duplicate
                                  ("urllib3", "2.2.1", "python"),
                                  ("actions/checkout", "v4", "github-action"))})
        code, out = self.run_cli("--run", runner=runner)
        self.assertEqual(code, 0)
        row = self.results()[0]
        self.assertEqual(row["status"], "ok")
        self.assertEqual(row["lock_files"], "poetry.lock;uv.lock")
        self.assertEqual(row["total_packages"], "3")
        self.assertEqual(row["packages_by_type"], "python=2;github-action=1")
        self.assertEqual(row["clone_mb"], "2.5")                  # 1 MB pack + 3 x 0.5 MB
        self.assertEqual((row["clone_seconds"], row["syft_seconds"], row["total_seconds"]),
                         ("3.0", "2.0", "5.0"))
        self.assertIn(f"[1/20] {self.picked()[0]['name']}: 3 packages (python 2, github-action 1), "
                      "lock: poetry.lock, uv.lock, 5 s, 2.5 MB", out)

    def test_count_packages(self):
        counts = count_packages({"artifacts": artifacts(("a", "1", "npm"), ("a", "1", "npm"),
                                                        ("a", "2", "npm"), ("b", "1", "python"))})
        self.assertEqual(counts, {"npm": 2, "python": 1})
        self.assertEqual(count_packages({"artifacts": None}), {})

    def test_temporary_clones_outside_project_and_deleted(self):
        runner = self.runner()
        self.run_cli("--run", runner=runner)
        self.assertEqual(len(runner.clone_dirs), 20)
        for d in runner.clone_dirs:
            self.assertFalse(d.resolve().is_relative_to(PROJECT_ROOT.resolve()))
            self.assertTrue(d.name == "repo" and d.parent.name.startswith("pilot_syft_"))
            self.assertFalse(d.exists())
        self.assertEqual(list(self.tmp_root.iterdir()), [])

    def test_refuses_temp_folder_inside_project(self):
        before = sorted(p.name for p in (PROJECT_ROOT / "dataset").iterdir())
        runner = self.runner()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = pilot_syft.main(["--seed-csv", str(self.seed_csv), "--out", str(self.out),
                                    "--run"], run=runner, clock=self.clock.monotonic,
                                   tmp_root=PROJECT_ROOT / "dataset")
        self.assertEqual(code, 2)
        self.assertIn("inside the project", out.getvalue())
        self.assertEqual(runner.calls, [])
        self.assertEqual(sorted(p.name for p in (PROJECT_ROOT / "dataset").iterdir()), before)

    def test_missing_syft_exits_2(self):
        runner = self.runner()
        code, out = self.run_cli("--run", "--syft", str(self.dir / "nope.exe"), runner=runner)
        self.assertEqual(code, 2)
        self.assertIn("Syft not found", out)
        self.assertEqual(runner.calls, [])


class TestFailures(PilotTestCase):

    def test_each_failure_is_recorded_and_the_run_continues(self):
        urls = [r["url"] for r in self.picked()]
        runner = self.runner(
            clones={urls[0]: "fail", urls[1]: "timeout"},
            syft={urls[2]: "fail", urls[3]: "badjson", urls[4]: "timeout"})
        code, out = self.run_cli("--run", runner=runner)
        self.assertEqual(code, 0)
        rows = self.results()
        self.assertEqual(len(rows), 20)
        self.assertEqual([r["status"] for r in rows[:6]],
                         ["clone_failed", "timeout", "syft_failed", "syft_failed", "timeout", "ok"])
        self.assertEqual(rows[0]["error"], "fatal: repository not found")
        self.assertEqual(rows[2]["error"], "error: could not catalog")
        self.assertEqual(rows[3]["error"], "Syft output is not valid JSON")
        self.assertIn("Repos scanned: 15 ok, 5 failed", out)
        self.assertEqual(list(self.tmp_root.iterdir()), [])     # failed clones deleted too

    def test_interrupt_writes_finished_repos(self):
        urls = [r["url"] for r in self.picked()]
        runner = self.runner()
        real_clone = runner.clone

        def clone(cmd, kwargs):
            if cmd[-2] == urls[2]:
                raise KeyboardInterrupt
            return real_clone(cmd, kwargs)

        runner.clone = clone
        code, out = self.run_cli("--run", runner=runner)
        self.assertEqual(code, 130)
        self.assertIn("Interrupted after 2 of 20 repos", out)
        self.assertEqual(len(self.results()), 2)
        self.assertEqual(list(self.tmp_root.iterdir()), [])


# ============================================================
# Output
# ============================================================
class TestOutput(PilotTestCase):

    def test_results_columns(self):
        self.run_cli("--run", runner=self.runner())
        with open(self.out, encoding="utf-8") as f:
            self.assertEqual(f.readline().strip(), ",".join(COLUMNS))
        rows = self.results()
        self.assertEqual([r["name"] for r in rows], [r["name"] for r in self.picked()])
        self.assertEqual(rows[0]["dependency_files"], self.picked()[0]["dependency_files"])
        self.assertEqual([p.name for p in self.dir.iterdir() if p.suffix == ".tmp"], [])

    def test_refuses_existing_results_without_overwrite(self):
        self.out.write_text("keep me", encoding="utf-8")
        runner = self.runner()
        code, out = self.run_cli("--run", runner=runner)
        self.assertEqual(code, 2)
        self.assertIn("--overwrite", out)
        self.assertEqual(runner.calls, [])
        self.assertEqual(self.out.read_text(encoding="utf-8"), "keep me")

    def test_overwrite_replaces(self):
        self.out.write_text("old", encoding="utf-8")
        code, _ = self.run_cli("--run", "--overwrite", runner=self.runner())
        self.assertEqual(code, 0)
        self.assertEqual(len(self.results()), 20)

    def test_summary(self):
        picked = self.picked()
        urls = [r["url"] for r in picked]
        syft = {u: artifacts(*[(f"p{k}", "1", "npm") for k in range(10)]) for u in urls}
        syft[urls[0]] = []                                       # zero packages
        syft[urls[1]] = artifacts(("x", "1", "python"))
        clones = {u: ["package.json", "package-lock.json"] for u in urls[12:16]}
        code, out = self.run_cli("--run", runner=self.runner(clones=clones, syft=syft))
        self.assertEqual(code, 0)
        self.assertIn(f"Repos with zero packages: 1 ({picked[0]['name']})", out)
        self.assertIn("Median packages per repo: 10", out)
        self.assertIn("Median seconds per repo: 5", out)
        self.assertIn("py_pyproject     8 ok, median 10 packages, lock file in 0/8", out)
        self.assertIn("js_ts            8 ok, median 10 packages, lock file in 4/8", out)


class TestSafety(unittest.TestCase):

    def test_no_database_scanner_or_project_folders(self):
        source = Path(pilot_syft.__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"^\s*(import|from)\s+(db_storage|sbom|pymysql|mysql)\b",
                                    source, re.M))
        code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("repo-cache", code)
        self.assertNotIn('"reports"', code)

    def test_default_paths(self):
        self.assertEqual(pilot_syft.DEFAULT_OUT, PROJECT_ROOT / "dataset" / "pilot_syft_results.csv")
        self.assertEqual(pilot_syft.DEFAULT_SEED_CSV, PROJECT_ROOT / "dataset" / "seed_v2.csv")
        self.assertEqual(BUNDLED_SYFT.parent, PROJECT_ROOT / "sbom-tools" / "syft")


if __name__ == "__main__":
    unittest.main()
