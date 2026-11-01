# dataset/scan_seed_list.py
#
# Scan the repos in dataset/seed_v2.csv into the database with the existing
# SBOMScanner (Syft + Grype, shallow clone, repo-cache), one repo at a time.
#
#   done      reports/<owner>-<repo>.json exists AND the database has a scan
#             row for the repo URL with a versions row per package name in
#             the report. scan() writes the report even when the database
#             insert fails, so a report alone is "incomplete" and is scanned
#             again. Rerunning resumes where the last run stopped.
#   order     pending repos alternate Python / JavaScript-TypeScript, so a
#             --limit test run gets both.
#   safety    a repo-cache/<owner>-<repo> folder without .git stops the run:
#             git would run in the project repository instead (the old
#             repo-cache entries are empty folders like that).
#   tools     sbom-tools/syft and sbom-tools/grype go on PATH for this
#             process only (and its git / Syft / Grype children).
#
# One line per repo on screen and in logs/scan_seed_list_YYYY-MM-DD.log.
# Failures are logged and the run continues (exit 1 at the end).
#
# Preview (default): counts and lists; scans nothing, writes nothing.
#     python dataset/scan_seed_list.py
# Scan (all pending, or a test run):
#     python dataset/scan_seed_list.py --apply [--limit 20]

import argparse
import csv
import json
import os
import sys
import time
from collections import Counter
from datetime import date
from itertools import zip_longest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SBOM_TOOLS = PROJECT_ROOT / "sbom-tools"
if str(SBOM_TOOLS) not in sys.path:
    sys.path.insert(0, str(SBOM_TOOLS))

DEFAULT_SEED_CSV = PROJECT_ROOT / "dataset" / "seed_v2.csv"
DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"
EXE = ".exe" if os.name == "nt" else ""
SYFT = SBOM_TOOLS / "syft" / f"syft{EXE}"
GRYPE = SBOM_TOOLS / "grype" / f"grype{EXE}"
JS_TS = ("JavaScript", "TypeScript")

DONE, PENDING, INCOMPLETE = "done", "pending", "incomplete"


# ============================
# REPOS AND THEIR STATE
# ============================
def load_seed_list(path):
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def scan_order(repos):
    """Python and JS/TS repos alternating, each in CSV order."""
    python = [r for r in repos if r["language"] not in JS_TS]
    js_ts = [r for r in repos if r["language"] in JS_TS]
    return [r for pair in zip_longest(python, js_ts) for r in pair if r is not None]


def file_name(url):
    """The name SBOMScanner uses for the report and the cache folder."""
    from sbom import generate_safe_filename
    return generate_safe_filename(url, True)


def report_packages(path):
    """(distinct package names, casefolded like MySQL compares them; total) of a report."""
    with open(path, encoding="utf-8") as f:
        report = json.load(f)
    packages = report.get("packages") or []
    names = {str(p.get("package") or "").casefold() for p in packages}
    total = (report.get("summary") or {}).get("total_packages", len(packages))
    return len(names), total


def db_versions_by_target(url=None):
    """{target_name: versions rows of its latest scan row} (one URL, or all)."""
    import db_storage
    sql = """
        SELECT s.target_name, s.scan_id, COUNT(v.version_id) AS n
        FROM scan s LEFT JOIN versions v ON v.scan_id = s.scan_id
        {where}
        GROUP BY s.scan_id, s.target_name
        ORDER BY s.scan_id
    """.format(where="WHERE s.target_name = %s" if url else "")
    conn = db_storage.get_new_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql, (url,) if url else ())
            rows = cursor.fetchall()
    finally:
        conn.close()
    return {r["target_name"]: int(r["n"]) for r in rows}     # the highest scan_id wins


def repo_state(repo, reports_dir, versions_by_target):
    path = Path(reports_dir) / f"{file_name(repo['url'])}.json"
    if not path.exists():
        return PENDING
    try:
        names, _ = report_packages(path)
    except (OSError, ValueError):
        return INCOMPLETE
    stored = versions_by_target.get(repo["url"])
    return DONE if stored is not None and stored >= names else INCOMPLETE


def unsafe_cache_folder(repo, cache_dir):
    """The repo's cache folder if it exists without .git (git would use the project repo)."""
    folder = Path(cache_dir) / file_name(repo["url"])
    return folder if folder.exists() and not (folder / ".git").exists() else None


def put_tools_on_path(env=None):
    """Bundled Syft and Grype first on PATH (this process and its children)."""
    env = os.environ if env is None else env
    tools = [str(SYFT.parent), str(GRYPE.parent)]
    rest = [p for p in env.get("PATH", "").split(os.pathsep) if p and p not in tools]
    env["PATH"] = os.pathsep.join(tools + rest)


class RunLog:
    """Lines on screen and appended to the day's log file."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def line(self, message):
        print(message, flush=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(message + "\n")


def first_line(error):
    text = str(error).strip().splitlines()
    return f"{type(error).__name__}: {text[0][:200] if text else ''}".rstrip(": ")


# ============================
# CLI
# ============================
def main(argv=None, scanner_class=None, clock=time.monotonic, reports_dir=None,
         cache_dir=None, log_dir=None, today=None):
    parser = argparse.ArgumentParser(
        description="Scan the seed_v2 repos with SBOMScanner (preview by default)."
    )
    parser.add_argument("--apply", action="store_true",
                        help="Scan the pending repos. Without this flag only a preview is shown.")
    parser.add_argument("--limit", type=int, default=None, help="scan at most N pending repos")
    parser.add_argument("--seed-csv", default=str(DEFAULT_SEED_CSV))
    parser.add_argument("--show", type=int, default=20, help="pending repos listed in the preview")
    args = parser.parse_args(argv)
    if args.limit is not None and args.limit < 1:
        print("Error: --limit must be at least 1.")
        return 2

    if args.apply:
        put_tools_on_path()
    import sbom
    reports_dir = Path(reports_dir or sbom.Config.REPORTS_DIR)
    cache_dir = Path(cache_dir or sbom.Config.REPO_CACHE_DIR)

    try:
        repos = load_seed_list(args.seed_csv)
    except OSError as e:
        print(f"Error: {e}")
        return 2
    try:
        stored = db_versions_by_target()
    except Exception as e:
        print(f"Error: database not reachable ({first_line(e)}). Is MySQL running?")
        return 2

    states = {r["url"]: repo_state(r, reports_dir, stored) for r in repos}
    done = [r for r in repos if states[r["url"]] == DONE]
    pending = scan_order([r for r in repos if states[r["url"]] != DONE])
    incomplete = sum(1 for r in pending if states[r["url"]] == INCOMPLETE)
    todo = pending[:args.limit] if args.limit else pending

    print(f"Seed list {args.seed_csv}: {len(repos)} repos; done {len(done)}, pending "
          f"{len(pending)} (of which {incomplete} incomplete: report but database rows missing)")

    if not args.apply:
        unsafe = [f for f in (unsafe_cache_folder(r, cache_dir) for r in pending) if f]
        if done:
            print("\nAlready done:")
            for r in done:
                print(f"  {r['name']}")
        if pending:
            shown = pending[:args.show]
            print(f"\nNext {len(shown)} to scan:")
            for r in shown:
                print(f"  {r['name']:<45} {r['language']:<11} {states[r['url']]}")
        for folder in unsafe:
            print(f"Warning: {folder} has no .git; --apply would stop there.")
        print("\nPreview only. Nothing was scanned or written. Re-run with --apply to scan.")
        return 0

    unsafe = [f for f in (unsafe_cache_folder(r, cache_dir) for r in todo) if f]
    if unsafe:
        print("Error: these repo-cache folders exist without .git. git would run in the project "
              "repository instead of the repo, so nothing was scanned. Delete or move them first:")
        for folder in unsafe:
            print(f"  {folder}")
        return 2
    missing = [str(p) for p in (SYFT, GRYPE) if not p.is_file()]
    if missing:
        print("Error: bundled tool not found: " + ", ".join(missing))
        return 2
    if not todo:
        print("Nothing to scan.")
        return 0

    sbom.Config.SYFT_PATH, sbom.Config.GRYPE_PATH = SYFT, GRYPE
    sbom.Config.init_directories()
    scanner = (scanner_class or sbom.SBOMScanner)(use_cache=True, shallow_clone=True,
                                                  skip_vuln=False)
    log = RunLog(Path(log_dir or DEFAULT_LOG_DIR)
                 / f"scan_seed_list_{(today or date.today()).isoformat()}.log")
    log.line(f"Scan started: {len(todo)} of {len(pending)} pending repos")

    results = Counter()
    try:
        for i, repo in enumerate(todo, 1):
            folder = unsafe_cache_folder(repo, cache_dir)
            if folder:
                log.line(f"[{i}/{len(todo)}] {repo['name']}: stopped, {folder} has no .git "
                         "(git would run in the project repository)")
                return 2
            start = clock()
            try:
                scanner.scan(repo["url"])
            except Exception as e:
                status = f"failed ({first_line(e)})"
                results["failed"] += 1
            else:
                report = reports_dir / f"{file_name(repo['url'])}.json"
                packages = report_packages(report)[1] if report.exists() else 0
                if repo_state(repo, reports_dir, db_versions_by_target(repo["url"])) == DONE:
                    status = f"ok, {packages} packages"
                    results["ok"] += 1
                else:
                    status = f"db_incomplete ({packages} packages in the report)"
                    results["db_incomplete"] += 1
            log.line(f"[{i}/{len(todo)}] {repo['name']}: {status}, {clock() - start:.1f} s")
    except KeyboardInterrupt:
        log.line(f"Interrupted after {sum(results.values())} of {len(todo)} repos.")
        return 130

    log.line(f"Scan finished: ok {results['ok']}, failed {results['failed']}, "
             f"db_incomplete {results['db_incomplete']}; still pending "
             f"{len(pending) - results['ok']}")
    return 1 if results["failed"] or results["db_incomplete"] else 0


if __name__ == "__main__":
    sys.exit(main())
