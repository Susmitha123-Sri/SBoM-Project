# dataset/build_seed_dataset.py
#
# One CSV for analysis: every repo of dataset/seed_v2.csv with the packages of
# its scan report (reports/<owner>-<repo>.json, written by SBOMScanner).
# Reads files only: no MySQL, no network; reports/ and seed_v2.csv are never
# changed.
#
#   rows          one per (repo, package); a repo without packages gets one row
#   scan_status   scanned | no_packages (report with 0 packages) |
#                 not_scanned (no report) | report_error (report unreadable)
#   report        the .json (has the summary for a consistency check); the
#                 .csv only if the .json is missing or unreadable
#   uniqueness    (name, version, type) within a repo; db_row marks the row
#                 the database keeps (one per package name per repo, the last)
#
# Preview (default): counts and the first rows; writes nothing.
#     python dataset/build_seed_dataset.py
# Write dataset/seed_v2_dataset.csv and dataset/seed_v2_dataset_notes.json:
#     python dataset/build_seed_dataset.py --apply [--overwrite]

import argparse
import csv
import hashlib
import json
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "dataset"
SBOM_TOOLS = PROJECT_ROOT / "sbom-tools"
if str(SBOM_TOOLS) not in sys.path:
    sys.path.insert(0, str(SBOM_TOOLS))

# Imported here, not inside a function: sbom.py re-wraps sys.stdout on Windows
# at import time. It connects to nothing on import.
from sbom import generate_safe_filename                # noqa: E402

DEFAULT_SEED_CSV = DATASET_DIR / "seed_v2.csv"
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "reports"
OUT_CSV = "seed_v2_dataset.csv"
OUT_NOTES = "seed_v2_dataset_notes.json"

SCANNED, NO_PACKAGES, NOT_SCANNED, REPORT_ERROR = (
    "scanned", "no_packages", "not_scanned", "report_error")
STATUSES = (SCANNED, NO_PACKAGES, NOT_SCANNED, REPORT_ERROR)

SEED_COLUMNS = ["name", "url", "language", "stars", "forks", "last_push", "dependency_files"]
REPO_COLUMNS = ["scan_status", "report_source", "report_file", "report_timestamp",
                "report_total_packages", "report_total_vulnerabilities", "report_warning"]
PACKAGE_COLUMNS = ["package_name", "package_version", "package_type", "ecosystem",
                   "report_latest_version", "report_version_status", "vulnerability_id",
                   "severity", "fixed_version", "has_vulnerability", "db_row"]
COLUMNS = SEED_COLUMNS + REPO_COLUMNS + PACKAGE_COLUMNS

COLUMN_NOTES = {
    "name, url, language, stars, forks, last_push, dependency_files":
        "copied from seed_v2.csv, repeated on every row of the repo",
    "scan_status": "scanned | no_packages (report with 0 packages) | not_scanned (no report "
                   "yet) | report_error (report unreadable; reason in report_warning)",
    "report_source": "json, csv (the .json was missing or unreadable) or none",
    "report_file": "report file name in reports/ (sbom.generate_safe_filename of the url)",
    "report_timestamp": "when the report was written (scan time)",
    "report_total_packages": "packages in the report (summary.total_packages for json)",
    "report_total_vulnerabilities": "Grype matches in the report (json summary; empty for csv)",
    "report_warning": "';'-joined: count_mismatch (summary.total_packages differs from the "
                      "package list), target_mismatch (report target is not the seed url), "
                      "from_csv, duplicates_dropped=N, or the read error",
    "package_name, package_version, package_type": "report 'package', 'version', 'type' "
        "(Syft type: npm, python, github-action, ...). Versions are as sbom.py stores them: "
        "a leading 'v' removed; missing or a 40-character commit hash -> 'unknown'",
    "ecosystem": "the database rule of sbom.py: python/pypi -> python, npm/node -> npm, "
                 "anything else -> none (never looked up)",
    "report_latest_version, report_version_status": "report 'latest_version' and "
        "'version_status' as looked up at report_timestamp. When the lookup failed or the "
        "type is not looked up, the report copies the installed version, so the status is "
        "up_to_date; use the database / daily snapshots for registry data",
    "vulnerability_id": "the first Grype match only, or 'None'",
    "severity": "the highest severity among the package's matches, or 'None'",
    "fixed_version": "report placeholder ('See advisory' or 'N/A'), not a real version",
    "has_vulnerability": "1 if vulnerability_id is not 'None', else 0",
    "db_row": "kept = the row the database stores (one versions row per package name per "
              "repo, names compared case-insensitively, the last occurrence wins); "
              "collapsed = an earlier row with the same name",
}

RULES = [
    "One row per (repo, package). A repo without packages (not_scanned, no_packages, "
    "report_error) has one row with the package columns empty.",
    "Packages are unique per (name, version, type) within a repo; exact duplicates are "
    "dropped and counted (report_warning duplicates_dropped=N).",
    "sbom.py already merges packages by name:version before writing the report, so the "
    "counts are its de-duplicated counts, not raw Syft artifact counts "
    "(dataset/pilot_syft_results.csv). Raw Syft output is not saved.",
    "The database keeps fewer rows: one per package name per repo. Filter db_row = kept to "
    "get the database's row set.",
    "Latest version, version status and vulnerability fields are scan-time values from the "
    "report; see the column notes for their limits.",
    "Built from files only: no MySQL and no network. Rows follow seed_v2.csv order, then "
    "report package order.",
]


# ============================
# REPORTS
# ============================
def report_name(url):
    """The report / cache file name SBOMScanner uses for this repo URL."""
    return generate_safe_filename(url, True)


def _read_json(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("packages", []), list):
        raise ValueError("not a scan report (no packages list)")
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "target": data.get("target"),
        "timestamp": data.get("timestamp"),
        "total_packages": summary.get("total_packages"),
        "total_vulnerabilities": summary.get("total_vulnerabilities"),
        "packages": data.get("packages") or [],
    }


def _read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "package" not in reader.fieldnames:
            raise ValueError("not a scan report (no package column)")
        rows = list(reader)
    first = rows[0] if rows else {}
    return {
        "target": first.get("target"),
        "timestamp": first.get("timestamp"),
        "total_packages": len(rows),
        "total_vulnerabilities": None,
        "packages": rows,
    }


def load_report(reports_dir, file_name):
    """
    (report, source, error). source is "json", "csv" or None (no report);
    report is None if there is none or neither file could be read.
    """
    errors = []
    for source, reader in (("json", _read_json), ("csv", _read_csv)):
        path = Path(reports_dir) / f"{file_name}.{source}"
        if not path.exists():
            continue
        try:
            return reader(path), source, None
        except (OSError, ValueError, UnicodeDecodeError, csv.Error) as e:
            errors.append(f"{path.name}: {type(e).__name__}: {e}"[:300])
    return None, None, "; ".join(errors) or None


# ============================
# ROWS
# ============================
def db_ecosystem(package_type):
    """sbom.py's database rule for packages.ecosystem."""
    if package_type in ("python", "pypi"):
        return "python"
    if package_type in ("npm", "node"):
        return "npm"
    return "none"


def same_repo(a, b):
    def norm(url):
        url = str(url or "").strip().rstrip("/")
        return (url[:-4] if url.endswith(".git") else url).casefold()
    return norm(a) == norm(b)


def text(value):
    return "" if value is None else str(value)


def repo_rows(seed_row, report, source, error, file_name):
    """(rows, stats) for one seed repo; stats counts duplicates_dropped."""
    base = {c: seed_row.get(c, "") for c in SEED_COLUMNS}
    empty = dict.fromkeys(PACKAGE_COLUMNS, "")

    if report is None:
        status = REPORT_ERROR if error else NOT_SCANNED
        row = {**base, **empty, "scan_status": status, "report_source": "none",
               "report_file": file_name if error else "", "report_timestamp": "",
               "report_total_packages": "", "report_total_vulnerabilities": "",
               "report_warning": error or ""}
        return [row], {"duplicates_dropped": 0}

    seen, packages = set(), []
    for pkg in report["packages"]:
        key = (text(pkg.get("package")), text(pkg.get("version")), text(pkg.get("type")))
        if key not in seen:
            seen.add(key)
            packages.append(pkg)
    dropped = len(report["packages"]) - len(packages)

    warnings = []
    total = report["total_packages"]
    if source == "json" and total is not None and total != len(report["packages"]):
        warnings.append("count_mismatch")
    if report["target"] and not same_repo(report["target"], seed_row.get("url")):
        warnings.append("target_mismatch")
    if source == "csv":
        warnings.append("from_csv")
    if dropped:
        warnings.append(f"duplicates_dropped={dropped}")

    repo = {"scan_status": SCANNED if packages else NO_PACKAGES, "report_source": source,
            "report_file": f"{file_name}.{source}", "report_timestamp": text(report["timestamp"]),
            "report_total_packages": text(total),
            "report_total_vulnerabilities": text(report["total_vulnerabilities"]),
            "report_warning": ";".join(warnings)}
    if not packages:
        return [{**base, **repo, **empty}], {"duplicates_dropped": dropped}

    last = {text(p.get("package")).casefold(): i for i, p in enumerate(packages)}
    rows = []
    for i, pkg in enumerate(packages):
        vuln = text(pkg.get("vulnerability_id"))
        rows.append({**base, **repo,
                     "package_name": text(pkg.get("package")),
                     "package_version": text(pkg.get("version")),
                     "package_type": text(pkg.get("type")),
                     "ecosystem": db_ecosystem(pkg.get("type")),
                     "report_latest_version": text(pkg.get("latest_version")),
                     "report_version_status": text(pkg.get("version_status")),
                     "vulnerability_id": vuln,
                     "severity": text(pkg.get("severity")),
                     "fixed_version": text(pkg.get("fixed_version")),
                     "has_vulnerability": "0" if vuln in ("", "None") else "1",
                     "db_row": ("kept" if last[text(pkg.get("package")).casefold()] == i
                                else "collapsed")})
    return rows, {"duplicates_dropped": dropped}


def build(seed_csv, reports_dir):
    """(rows, stats, warnings) for the whole seed list."""
    with open(seed_csv, encoding="utf-8-sig", newline="") as f:
        seed = list(csv.DictReader(f))

    rows, warnings = [], []
    statuses = Counter({s: 0 for s in STATUSES})
    dropped = 0
    for seed_row in seed:
        file_name = report_name(seed_row["url"])
        report, source, error = load_report(reports_dir, file_name)
        repo, stats = repo_rows(seed_row, report, source, error, file_name)
        rows.extend(repo)
        statuses[repo[0]["scan_status"]] += 1
        dropped += stats["duplicates_dropped"]
        if repo[0]["report_warning"]:
            warnings.append({"name": seed_row.get("name"), "warning": repo[0]["report_warning"]})

    stats = {
        "repos": len(seed),
        "repos_by_status": dict(statuses),
        "rows": len(rows),
        "package_rows": sum(1 for r in rows if r["package_name"]),
        "db_kept_rows": sum(1 for r in rows if r["db_row"] == "kept"),
        "duplicates_dropped": dropped,
    }
    return rows, stats, warnings


# ============================
# WRITING
# ============================
def write_atomic(path, write_fn, encoding):
    """write_fn(file) into a temp file next to path, then rename it over path."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as f:
            write_fn(f)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_csv(f, rows):
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def notes(seed_csv, reports_dir, stats, warnings, now):
    seed_csv = Path(seed_csv)
    return {
        "created_at": now.isoformat(timespec="seconds"),
        "output": OUT_CSV,
        "encoding": "UTF-8 with BOM",
        "seed_csv": {"path": str(seed_csv), "bytes": seed_csv.stat().st_size,
                     "sha256": sha256(seed_csv)},
        "reports_dir": str(reports_dir),
        "counts": stats,
        "repos_with_warnings": warnings,
        "columns": COLUMNS,
        "column_notes": COLUMN_NOTES,
        "rules": RULES,
    }


# ============================
# CLI
# ============================
def main(argv=None, now=None, reports_dir=None, out_dir=None):
    parser = argparse.ArgumentParser(
        description="Build dataset/seed_v2_dataset.csv from seed_v2.csv and the scan reports "
                    "(preview by default).")
    parser.add_argument("--apply", action="store_true",
                        help="Write the CSV and the notes. Without this flag only a preview is shown.")
    parser.add_argument("--overwrite", action="store_true", help="replace existing output files")
    parser.add_argument("--seed-csv", default=str(DEFAULT_SEED_CSV))
    parser.add_argument("--show", type=int, default=10, help="rows shown in the preview")
    args = parser.parse_args(argv)

    reports_dir = Path(reports_dir or DEFAULT_REPORTS_DIR)
    out_dir = Path(out_dir or DATASET_DIR)
    out_csv, out_notes = out_dir / OUT_CSV, out_dir / OUT_NOTES

    try:
        rows, stats, warnings = build(args.seed_csv, reports_dir)
    except (OSError, KeyError) as e:
        print(f"Error: cannot read the seed list {args.seed_csv} ({type(e).__name__}: {e}).")
        return 2

    by_status = stats["repos_by_status"]
    print(f"Seed list {args.seed_csv}: {stats['repos']} repos; "
          + ", ".join(f"{s} {by_status[s]}" for s in STATUSES))
    print(f"Rows: {stats['rows']} ({stats['package_rows']} package rows, "
          f"{stats['db_kept_rows']} kept by the database rule, "
          f"{stats['duplicates_dropped']} duplicates dropped)")
    for w in warnings:
        print(f"Warning: {w['name']}: {w['warning']}")

    if not args.apply:
        shown = rows[:args.show]
        print(f"\nFirst {len(shown)} rows (name | scan_status | package | version | type):")
        for r in shown:
            print(f"  {r['name']} | {r['scan_status']} | {r['package_name']} | "
                  f"{r['package_version']} | {r['package_type']}")
        print(f"\nPreview only. Nothing was written. Re-run with --apply to write {out_csv}.")
        return 0

    existing = [str(p) for p in (out_csv, out_notes) if p.exists()]
    if existing and not args.overwrite:
        print("Error: already exists (use --overwrite to replace): " + ", ".join(existing))
        return 2

    write_atomic(out_csv, lambda f: write_csv(f, rows), "utf-8-sig")
    info = notes(args.seed_csv, reports_dir, stats, warnings, now or datetime.now())
    write_atomic(out_notes, lambda f: json.dump(info, f, indent=2, ensure_ascii=False), "utf-8")
    print(f"Wrote {out_csv} ({stats['rows']} rows) and {out_notes}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
