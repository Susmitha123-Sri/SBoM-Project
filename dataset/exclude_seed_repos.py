# dataset/exclude_seed_repos.py
#
# Remove the seed_v2 repos that cannot be scanned (1,000 -> 995) and record why:
#   - git checkout fails on Windows because of illegal file names
#   - the repository no longer exists
#
#   seed_v2.csv            the excluded rows are dropped; every other line is
#                          written back byte for byte (header, line endings)
#   seed_v2_excluded.csv   new: name, url, language, reason
#   seed_v2_criteria.json  one new key, post_selection_exclusions; no existing
#                          key or value changes (selected_total stays 1000)
#
# Checks first, and stops (exit 2, nothing written) unless every excluded repo
# is in seed_v2.csv exactly once and has no report in reports/ and no scan row
# in the database (SELECT only).
#
# Dry run (default): checks and what would change; writes nothing.
#     python dataset/exclude_seed_repos.py
# Apply:
#     python dataset/exclude_seed_repos.py --apply

import argparse
import csv
import io
import json
import os
import sys
import tempfile
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = PROJECT_ROOT / "dataset"
SBOM_TOOLS = PROJECT_ROOT / "sbom-tools"
if str(SBOM_TOOLS) not in sys.path:
    sys.path.insert(0, str(SBOM_TOOLS))

# Imported here, not inside a function: sbom.py re-wraps sys.stdout on Windows
# at import time. It connects to nothing on import.
from sbom import generate_safe_filename               # noqa: E402

DEFAULT_SEED_CSV = DATASET_DIR / "seed_v2.csv"
DEFAULT_CRITERIA = DATASET_DIR / "seed_v2_criteria.json"
DEFAULT_EXCLUDED = DATASET_DIR / "seed_v2_excluded.csv"
DEFAULT_REPORTS = PROJECT_ROOT / "reports"
EXPECTED_ROWS = 1000
JS_TS = ("JavaScript", "TypeScript")
KEY = "post_selection_exclusions"
EXCLUDED_COLUMNS = ["name", "url", "language", "reason"]

ILLEGAL_NAMES = ("git checkout fails on Windows: file names that are illegal on Windows "
                 "(colon, trailing space, reserved name aux, question mark)")
NOT_FOUND = "repository not found (deleted, renamed or private)"
EXCLUDED = {
    "https://github.com/bytedance/fedlearner": ILLEGAL_NAMES,
    "https://github.com/doramart/DoraCMS": ILLEGAL_NAMES,
    "https://github.com/ivopetiz/algotrading": ILLEGAL_NAMES,
    "https://github.com/hackclub/sprig": ILLEGAL_NAMES,
    "https://github.com/fecommunity/reactpress": NOT_FOUND,
}
NOTE = ("5 repos removed after selection because they cannot be scanned (4: git checkout "
        "fails on Windows because of illegal file names; 1: repository not found). "
        "seed_v2.csv now has 995 repos; selected_total above is the original selection of 1000.")


class CheckFailed(Exception):
    pass


# ============================
# READING
# ============================
def read_seed(path):
    """(lines as bytes with their endings, header fields, [(line index, row dict)])."""
    lines = Path(path).read_bytes().splitlines(keepends=True)
    if not lines:
        raise CheckFailed(f"{path} is empty")
    header = next(csv.reader([lines[0].decode("utf-8")]))
    rows = []
    for i, line in enumerate(lines[1:], 1):
        text = line.decode("utf-8").rstrip("\r\n")
        if text:
            rows.append((i, dict(zip(header, next(csv.reader([text]))))))
    return lines, header, rows


def newline_of(lines):
    return b"\r\n" if lines[0].endswith(b"\r\n") else b"\n"


def group_counts(rows):
    js_ts = sum(1 for _, r in rows if r.get("language") in JS_TS)
    return {"python": len(rows) - js_ts, "js_ts": js_ts}


def db_scan_rows(urls):
    """{url: [scan_id, ...]} from sbom_common (SELECT only)."""
    import db_storage
    conn = db_storage.get_new_connection()
    try:
        with conn.cursor() as cursor:
            found = {}
            for url in urls:
                cursor.execute("SELECT scan_id FROM scan WHERE target_name IN (%s, %s, %s)",
                               (url, url + ".git", url + "/"))
                found[url] = [r["scan_id"] for r in cursor.fetchall()]
            return found
    finally:
        conn.close()


# ============================
# WRITING
# ============================
def write_atomic(path, data):
    """Write bytes to a temp file next to path, then rename it over path."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def excluded_csv_bytes(rows, newline):
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=newline.decode())
    writer.writerow(EXCLUDED_COLUMNS)
    for r in rows:
        writer.writerow([r["name"], r["url"], r["language"], EXCLUDED[r["url"]]])
    return out.getvalue().encode("utf-8")


# ============================
# CLI
# ============================
def main(argv=None, seed_csv=None, criteria=None, excluded=None, reports_dir=None,
         db_check=None, today=None):
    parser = argparse.ArgumentParser(
        description="Remove the 5 unscannable repos from seed_v2.csv (dry run by default).")
    parser.add_argument("--apply", action="store_true",
                        help="Write the changes. Without this flag nothing is written.")
    args = parser.parse_args(argv)

    seed_csv = Path(seed_csv or DEFAULT_SEED_CSV)
    criteria = Path(criteria or DEFAULT_CRITERIA)
    excluded = Path(excluded or DEFAULT_EXCLUDED)
    reports_dir = Path(reports_dir or DEFAULT_REPORTS)
    db_check = db_check or db_scan_rows
    today = today or date.today()

    try:
        lines, header, rows = read_seed(seed_csv)
        criteria_text = criteria.read_bytes().decode("utf-8")   # keeps \r\n (read_text would not)
        record = json.loads(criteria_text)
        in_seed = [r for _, r in rows if r.get("url") in EXCLUDED]

        # ---- already applied? ----
        if not in_seed and excluded.exists() and KEY in record:
            print(f"Already applied: {len(rows)} repos in {seed_csv.name}, "
                  f"{excluded.name} and the {KEY} record exist. Nothing to do.")
            return 0

        # ---- checks ----
        print("Checks:")
        counts = {url: sum(1 for _, r in rows if r.get("url") == url) for url in EXCLUDED}
        bad = {url: n for url, n in counts.items() if n != 1}
        if bad:
            raise CheckFailed("each excluded repo must be in the seed list exactly once: "
                              + ", ".join(f"{u} ({n}x)" for u, n in bad.items()))
        if len(rows) != EXPECTED_ROWS:
            raise CheckFailed(f"{seed_csv.name} has {len(rows)} rows, expected {EXPECTED_ROWS}")
        print(f"  seed list: all {len(EXCLUDED)} found once among {len(rows)} rows")

        reports = [f"{generate_safe_filename(url, True)}.{ext}" for url in EXCLUDED
                   for ext in ("json", "csv")]
        present = [name for name in reports if (reports_dir / name).exists()]
        if present:
            raise CheckFailed(f"report files exist in {reports_dir}: " + ", ".join(present))
        print(f"  reports: none of the {len(reports)} report files exist in {reports_dir}")

        try:
            scans = db_check(list(EXCLUDED))
        except Exception as e:
            raise CheckFailed(f"database not reachable ({type(e).__name__}: {e}); "
                              "start MySQL and run again") from e
        with_rows = {url: ids for url, ids in scans.items() if ids}
        if with_rows:
            raise CheckFailed("scan rows exist in the database: "
                              + ", ".join(f"{u} (scan {ids})" for u, ids in with_rows.items()))
        print("  database: no scan rows for any of them")

        if KEY in record:
            raise CheckFailed(f"{criteria.name} already has {KEY}")
        if criteria_text.replace("\r\n", "\n") != json.dumps(record, indent=2) + "\n":
            raise CheckFailed(f"{criteria.name} is not in json.dumps(indent=2) form; rewriting "
                              "it could change existing fields")
        if excluded.exists():
            raise CheckFailed(f"{excluded} already exists")
        print(f"  {criteria.name}: formatting can be kept; {excluded.name} does not exist yet")
    except CheckFailed as e:
        print(f"Stopped, nothing written: {e}")
        return 2

    # ---- what changes ----
    drop = {i for i, r in rows if r.get("url") in EXCLUDED}
    removed = [r for i, r in rows if i in drop]
    kept = [(i, r) for i, r in rows if i not in drop]
    final = group_counts(kept)
    exclusion = {
        "date": today.isoformat(),
        "final_count": len(kept),
        "final_by_group": final,
        "excluded_file": "dataset/" + excluded.name,
        "repos": [{"name": r["name"], "url": r["url"], "language": r["language"],
                   "reason": EXCLUDED[r["url"]]} for r in removed],
        "note": NOTE,
    }

    print(f"\nRows to remove from {seed_csv.name} ({len(removed)}):")
    for i, r in rows:
        if i in drop:
            print(f"  line {i + 1}: {r['name']} ({r['language']}): {EXCLUDED[r['url']]}")
    print(f"Repos after: {len(kept)} (python {final['python']}, js_ts {final['js_ts']})")
    print(f"New file {excluded.name}: {len(removed)} rows, columns {', '.join(EXCLUDED_COLUMNS)}")
    print(f"New key in {criteria.name}:")
    print("  " + json.dumps({KEY: exclusion}, indent=2).replace("\n", "\n  "))

    if not args.apply:
        print("\nDry run. Nothing was written. Re-run with --apply to write.")
        return 0

    newline = newline_of(lines)
    seed_bytes = b"".join(line for i, line in enumerate(lines) if i not in drop)
    record[KEY] = exclusion
    json_newline = "\r\n" if "\r\n" in criteria_text else "\n"
    criteria_bytes = (json.dumps(record, indent=2) + "\n").replace("\n", json_newline).encode("utf-8")

    write_atomic(excluded, excluded_csv_bytes(removed, newline))
    write_atomic(criteria, criteria_bytes)
    write_atomic(seed_csv, seed_bytes)

    _, new_header, new_rows = read_seed(seed_csv)
    left = [r["url"] for _, r in new_rows if r.get("url") in EXCLUDED]
    if new_header != header or len(new_rows) != len(kept) or left:
        print(f"Error: {seed_csv.name} check after writing failed "
              f"({len(new_rows)} rows, excluded left: {left}).")
        return 1
    print(f"\nWrote {seed_csv.name} ({len(new_rows)} repos), {excluded.name} and {criteria.name}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
