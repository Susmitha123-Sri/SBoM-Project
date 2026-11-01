# dataset/pilot_syft.py
#
# Read-only Syft pilot on 20 repos from dataset/seed_v2.csv, to see what the
# real collection will find before it starts: packages per repo by type,
# which lock files exist (lock files give transitive packages), time per
# repo and clone size. Syft only, no Grype.
#
# Never touches MySQL, repo-cache/, reports/ or any existing file. Clones go
# to a temporary folder outside the project and are deleted after each repo.
#
#   sample   seed 42 (--seed), each group sorted by name, then sampled:
#              py_pyproject     8  Python, dependency_files exactly pyproject.toml
#              py_requirements  4  Python, dependency_files exactly requirements.txt
#              js_ts            8  JavaScript or TypeScript
#
# Preview (default): lists the 20 repos; clones nothing, writes nothing.
#     python dataset/pilot_syft.py
# Clone + Syft each repo, then write dataset/pilot_syft_results.csv:
#     python dataset/pilot_syft.py --run [--overwrite]

import argparse
import csv
import io
import json
import os
import random
import shutil
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SEED_CSV = PROJECT_ROOT / "dataset" / "seed_v2.csv"
DEFAULT_OUT = PROJECT_ROOT / "dataset" / "pilot_syft_results.csv"
BUNDLED_SYFT = PROJECT_ROOT / "sbom-tools" / "syft" / ("syft.exe" if os.name == "nt" else "syft")

DEFAULT_SEED = 42
DEFAULT_TIMEOUT = 600          # seconds per clone and per Syft run

# group -> how many repos
SAMPLE_SIZES = {"py_pyproject": 8, "py_requirements": 4, "js_ts": 8}
JS_TS = ("JavaScript", "TypeScript")

LOCK_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "Pipfile.lock", "uv.lock", "pdm.lock")

OK, CLONE_FAILED, TIMEOUT, SYFT_FAILED = "ok", "clone_failed", "timeout", "syft_failed"

COLUMNS = ["name", "language", "group", "dependency_files", "lock_files", "status",
           "total_packages", "packages_by_type", "clone_seconds", "syft_seconds",
           "total_seconds", "clone_mb", "error"]


def log(message):
    print(message, flush=True)


# ============================
# SAMPLE (no I/O besides reading the seed list)
# ============================
def group_of(row):
    """Pilot group of a seed_v2 row, or None if it is in no group."""
    language = row.get("language")
    files = row.get("dependency_files")
    if language == "Python" and files == "pyproject.toml":
        return "py_pyproject"
    if language == "Python" and files == "requirements.txt":
        return "py_requirements"
    if language in JS_TS:
        return "js_ts"
    return None


def load_seed_list(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def sample(rows, seed=DEFAULT_SEED):
    """
    The pilot repos, group by group in SAMPLE_SIZES order. Each group is
    sorted by name first, so the row order of the CSV doesn't matter.
    Raises ValueError if a group has too few repos.
    """
    selected = []
    for group, size in SAMPLE_SIZES.items():
        members = sorted((r for r in rows if group_of(r) == group),
                         key=lambda r: (r["name"].lower(), r["name"]))
        if len(members) < size:
            raise ValueError(f"group {group} has {len(members)} repos, the pilot needs {size}")
        picked = random.Random(f"{seed}-{group}").sample(members, size)
        selected.extend(dict(r, group=group) for r in picked)
    return selected


# ============================
# ONE REPO
# ============================
def _clear_readonly(func, path, _exc):
    """rmtree error handler: git makes pack files read-only on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def remove_tree(path):
    """Delete a folder, read-only files included. True if it is gone."""
    for _ in range(2):
        if not os.path.exists(path):
            return True
        if sys.version_info >= (3, 12):
            shutil.rmtree(path, onexc=_clear_readonly)
        else:
            shutil.rmtree(path, onerror=_clear_readonly)
    return not os.path.exists(path)


def folder_mb(path):
    """Total size of all files under path (symlinks not followed), in MB."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total / (1024 * 1024)


def lock_files_in(repo_dir):
    return [name for name in LOCK_FILES if (Path(repo_dir) / name).is_file()]


def count_packages(syft_json):
    """Counter of package types, unique by (name, version, type)."""
    unique = {(a.get("name"), a.get("version"), a.get("type") or "unknown")
              for a in syft_json.get("artifacts") or [] if isinstance(a, dict)}
    return Counter(t for _, _, t in unique)


def last_line(text):
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    return lines[-1][:200] if lines else ""


def scan_repo(repo, work_dir, run, clock, syft, git, timeout):
    """Clone into work_dir/repo and run Syft. Returns one results row."""
    row = {"name": repo["name"], "language": repo["language"], "group": repo["group"],
           "dependency_files": repo["dependency_files"], "lock_files": "",
           "status": OK, "total_packages": "", "packages_by_type": "",
           "clone_seconds": "", "syft_seconds": "", "total_seconds": "",
           "clone_mb": "", "error": ""}
    clone_dir = Path(work_dir) / "repo"
    start = clock()

    git_env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    git_cmd = [git, "clone", "--depth", "1", "--single-branch", "--no-tags",
               "-c", "core.longpaths=true", repo["url"], str(clone_dir)]
    try:
        result = run(git_cmd, capture_output=True, text=True, encoding="utf-8",
                     errors="replace", timeout=timeout, env=git_env)
    except subprocess.TimeoutExpired:
        row.update(status=TIMEOUT, error=f"clone took more than {timeout} s")
        return finish(row, start, clock)
    row["clone_seconds"] = round(clock() - start, 1)
    if result.returncode != 0:
        row.update(status=CLONE_FAILED, error=last_line(result.stderr) or "git clone failed")
        return finish(row, start, clock)

    row["lock_files"] = ";".join(lock_files_in(clone_dir))
    row["clone_mb"] = round(folder_mb(clone_dir), 1)

    syft_start = clock()
    syft_env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false")
    syft_cmd = [str(syft), f"dir:{clone_dir}", "-o", "json", "-q"]
    try:
        result = run(syft_cmd, capture_output=True, text=True, encoding="utf-8",
                     errors="replace", timeout=timeout, env=syft_env)
    except subprocess.TimeoutExpired:
        row.update(status=TIMEOUT, error=f"Syft took more than {timeout} s")
        return finish(row, start, clock)
    row["syft_seconds"] = round(clock() - syft_start, 1)
    if result.returncode != 0:
        row.update(status=SYFT_FAILED, error=last_line(result.stderr) or "Syft failed")
        return finish(row, start, clock)
    try:
        counts = count_packages(json.loads(result.stdout or ""))
    except (ValueError, AttributeError):
        row.update(status=SYFT_FAILED, error="Syft output is not valid JSON")
        return finish(row, start, clock)

    row["total_packages"] = sum(counts.values())
    row["packages_by_type"] = ";".join(f"{t}={n}" for t, n in counts.most_common())
    return finish(row, start, clock)


def finish(row, start, clock):
    row["total_seconds"] = round(clock() - start, 1)
    return row


def progress_line(i, total, row):
    if row["status"] != OK:
        return f"[{i}/{total}] {row['name']}: {row['status']} ({row['error']}), {row['total_seconds']} s"
    types = ", ".join(f"{t.replace('=', ' ')}" for t in row["packages_by_type"].split(";") if t)
    lock = row["lock_files"].replace(";", ", ") or "none"
    return (f"[{i}/{total}] {row['name']}: {row['total_packages']} packages"
            f"{f' ({types})' if types else ''}, lock: {lock}, "
            f"{row['total_seconds']:.0f} s, {row['clone_mb']} MB")


# ============================
# OUTPUT
# ============================
def write_results(path, rows):
    """Write the results CSV via a .tmp file and rename."""
    path = Path(path)
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(out.getvalue())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _median(values):
    return f"{statistics.median(values):g}" if values else "n/a"


def summary_lines(rows):
    ok = [r for r in rows if r["status"] == OK]
    failed = [r for r in rows if r["status"] != OK]
    zero = [r["name"] for r in ok if r["total_packages"] == 0]
    lines = [
        f"Repos scanned: {len(ok)} ok, {len(failed)} failed"
        + (f" ({', '.join(f'{r['name']} {r['status']}' for r in failed)})" if failed else ""),
        f"Repos with zero packages: {len(zero)}" + (f" ({', '.join(zero)})" if zero else ""),
        f"Median packages per repo: {_median([r['total_packages'] for r in ok])}",
        f"Median seconds per repo: {_median([r['total_seconds'] for r in ok])}",
        "By group:",
    ]
    for group in SAMPLE_SIZES:
        members = [r for r in ok if r["group"] == group]
        with_lock = sum(1 for r in members if r["lock_files"])
        lines.append(f"  {group:<16} {len(members)} ok, median "
                     f"{_median([r['total_packages'] for r in members])} packages, "
                     f"lock file in {with_lock}/{len(members)}")
    return lines


# ============================
# CLI
# ============================
def is_inside_project(path):
    try:
        return Path(path).resolve().is_relative_to(PROJECT_ROOT.resolve())
    except OSError:
        return True


def main(argv=None, run=None, clock=time.monotonic, tmp_root=None):
    parser = argparse.ArgumentParser(
        description="Syft pilot on 20 seed_v2 repos (preview by default, nothing written)."
    )
    parser.add_argument("--run", action="store_true",
                        help="clone and scan the repos, then write the results CSV")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="sampling seed")
    parser.add_argument("--seed-csv", default=str(DEFAULT_SEED_CSV))
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="results CSV (with --run)")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing results CSV")
    parser.add_argument("--syft", default=str(BUNDLED_SYFT), help="Syft executable")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="seconds per clone and per Syft run")
    args = parser.parse_args(argv)

    try:
        repos = sample(load_seed_list(args.seed_csv), args.seed)
    except (OSError, ValueError, KeyError) as e:
        print(f"Error: {e}")
        return 2

    if not args.run:
        print(f"Pilot sample (seed {args.seed}, {len(repos)} repos from {args.seed_csv}):")
        for i, r in enumerate(repos, 1):
            print(f"  {i:>2}. {r['group']:<16} {r['name']:<45} {r['language']:<11} "
                  f"{r['stars']:>6} stars  {r['dependency_files']}")
        print("\nPreview only: nothing cloned or written. Re-run with --run to clone and scan.")
        return 0

    out = Path(args.out)
    if out.exists() and not args.overwrite:
        print(f"Error: {out} already exists (use --overwrite to replace it).")
        return 2
    if not Path(args.syft).is_file():
        print(f"Error: Syft not found at {args.syft}")
        return 2
    temp_parent = Path(tmp_root or tempfile.gettempdir())
    if is_inside_project(temp_parent):
        print(f"Error: temporary folder {temp_parent} is inside the project; refusing to clone there.")
        return 2

    run = run or subprocess.run
    git = shutil.which("git") or "git"
    rows = []
    left_behind = []
    interrupted = False

    print(f"Pilot run: {len(repos)} repos, Syft {args.syft}, temporary clones in {temp_parent}",
          flush=True)
    try:
        for i, repo in enumerate(repos, 1):
            work_dir = tempfile.mkdtemp(prefix="pilot_syft_", dir=temp_parent)
            try:
                if is_inside_project(work_dir):            # never expected; checked above
                    raise RuntimeError(f"temporary folder {work_dir} is inside the project")
                row = scan_repo(repo, work_dir, run, clock, args.syft, git, args.timeout)
            finally:
                if not remove_tree(work_dir):
                    left_behind.append(work_dir)
            rows.append(row)
            log(progress_line(i, len(repos), row))
    except KeyboardInterrupt:
        interrupted = True
        print(f"\nInterrupted after {len(rows)} of {len(repos)} repos.")

    print()
    for line in summary_lines(rows):
        print(line)
    if left_behind:
        print("Could not delete these temporary folders; remove them by hand: "
              + ", ".join(left_behind))

    write_results(out, rows)
    print(f"\nWrote {len(rows)} rows to {out}")
    return 130 if interrupted else 0


if __name__ == "__main__":
    sys.exit(main())
