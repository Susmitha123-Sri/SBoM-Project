# sbom-tools/build_reference_list.py
#
# Build a bigger list of known package names (pypi, npm, maven) for
# name_match.py, from local files only:
#
#   data-prep/external/Package-List/*.csv   Package-List-20260117 (Google Drive,
#                                           oraoraoraaa/Package-List-Miner)
#   data-prep/external/purl2cpe.db.zip      scanoss/purl2cpe
#   data-prep/release_cache.json            the existing release cache
#
# You download the external files; this script never uses the network and
# never writes to the database. Pass "" to leave a source out, e.g.
#   --package-lists ""
#
# Preview (default, writes nothing): counts per ecosystem and source,
# purl2cpe relation counts, and how name_match results for our packages
# would change against the bigger list (reads packages, read-only).
#     python sbom-tools/build_reference_list.py
# Write data-prep/reference_names.csv (name,ecosystem,source):
#     python sbom-tools/build_reference_list.py --apply
# Then match against it:
#     python sbom-tools/name_match.py --candidates data-prep/reference_names.csv

import argparse
import csv
import os
import sys
from collections import Counter
from pathlib import Path

from name_match import (MATCH_STATUSES, MATCHED, CandidateIndex, load_aliases,
                        load_candidates, match_packages)
from reference_sources import (TARGET_ECOSYSTEMS, iter_package_lists, package_list_files,
                               purl_ecosystem, purl_package_name, parse_purl, read_purl2cpe)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = PROJECT_ROOT / "data-prep" / "external"
DEFAULT_PACKAGE_LISTS = EXTERNAL / "Package-List"
DEFAULT_PURL2CPE = EXTERNAL / "purl2cpe.db.zip"
DEFAULT_RELEASE_CACHE = PROJECT_ROOT / "data-prep" / "release_cache.json"
DEFAULT_OUT = PROJECT_ROOT / "data-prep" / "reference_names.csv"

OUT_COLUMNS = ["name", "ecosystem", "source"]
EXAMPLES = 10


def small_sources(release_cache, purl2cpe):
    """{(ecosystem, name): set of sources} from the release cache and purl2cpe."""
    names = {}
    if release_cache is not None:
        for name, eco in release_cache:
            if eco in TARGET_ECOSYSTEMS:
                names.setdefault((eco, name), set()).add("release-cache")
    if purl2cpe is not None:
        for purls in purl2cpe.products.values():
            for base in purls:
                p = parse_purl(base)
                eco = purl_ecosystem(p.type)
                if eco in TARGET_ECOSYSTEMS:
                    names.setdefault((eco, purl_package_name(p)), set()).add("purl2cpe")
    return names


def check_inputs(args):
    """Paths of the sources in use; raises FileNotFoundError for a missing one."""
    used = {}
    if args.package_lists:
        package_list_files(args.package_lists)          # raises if the folder is missing
        used["package-list"] = args.package_lists
    for key, value, what in (("purl2cpe", args.purl2cpe, "purl2cpe zip"),
                             ("release-cache", args.release_cache, "release cache")):
        if value:
            if not Path(value).is_file():
                raise FileNotFoundError(f"{what} not found: {value}")
            used[key] = value
    if not used:
        raise FileNotFoundError("no sources given")
    return used


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build data-prep/reference_names.csv from local reference files (preview by default)."
    )
    parser.add_argument("--package-lists", default=str(DEFAULT_PACKAGE_LISTS),
                        help='folder with the Package-List CSVs ("" to skip)')
    parser.add_argument("--purl2cpe", default=str(DEFAULT_PURL2CPE),
                        help='purl2cpe.db.zip ("" to skip)')
    parser.add_argument("--release-cache", default=str(DEFAULT_RELEASE_CACHE),
                        help='release_cache.json ("" to skip)')
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="output CSV (written with --apply)")
    parser.add_argument("--no-coverage", action="store_true",
                        help="skip the name_match comparison (no database read)")
    parser.add_argument("--apply", action="store_true",
                        help="Actually write the output CSV. Without this flag only a preview is shown.")
    args = parser.parse_args(argv)

    try:
        used = check_inputs(args)
        cache = load_candidates(used["release-cache"]) if "release-cache" in used else None
        purl2cpe = read_purl2cpe(used["purl2cpe"]) if "purl2cpe" in used else None
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        return 2

    print("Sources: " + ", ".join(f"{k} ({v})" for k, v in used.items()))
    small = small_sources(cache, purl2cpe)

    # ---------- our packages and the keys a match could share ----------
    aliases = load_aliases()
    keys_of = CandidateIndex([], aliases).keys
    rows, our_keys = [], set()
    if not args.no_coverage:
        from db_storage import get_db_storage
        rows = get_db_storage().package_match_rows()
        for r in rows:
            our_keys |= keys_of(str(r["package_name"]))
    related = set()          # known names sharing a key with one of our packages

    # ---------- stream everything, writing as we go ----------
    counts = Counter()       # (source, ecosystem) -> names
    for (eco, _name), sources in small.items():
        for source in sources:
            counts[(source, eco)] += 1
    written = Counter()      # ecosystem -> rows in the output
    out_path = Path(args.out)
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    out_file = writer = None
    if args.apply:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_file = open(tmp_path, "w", encoding="utf-8", newline="")
        writer = csv.writer(out_file)
        writer.writerow(OUT_COLUMNS)

    try:
        if "package-list" in used:
            # Registry names are unique per ecosystem, so these rows are
            # written as read; the small sources are merged into them
            for name, eco, _url in iter_package_lists(used["package-list"]):
                counts[("package-list", eco)] += 1
                sources = {"package-list"} | small.pop((eco, name), set())
                written[eco] += 1
                if writer:
                    writer.writerow([name, eco, "+".join(sorted(sources))])
                if our_keys and keys_of(name) & our_keys:
                    related.add((name, eco))

        for (eco, name), sources in sorted(small.items()):
            written[eco] += 1
            if writer:
                writer.writerow([name, eco, "+".join(sorted(sources))])
            if our_keys and keys_of(name) & our_keys:
                related.add((name, eco))
    except BaseException:
        if out_file:
            out_file.close()
            os.remove(tmp_path)
        raise

    if out_file:
        out_file.close()
        os.replace(tmp_path, out_path)

    # ---------- report ----------
    print("\nNames per source and ecosystem (a name can come from several sources):")
    for source in ("package-list", "purl2cpe", "release-cache"):
        if source in used:
            print(f"  {source:<14} " + ", ".join(
                f"{eco} {counts[(source, eco)]}" for eco in TARGET_ECOSYSTEMS))
    print(f"Reference list: {sum(written.values())} rows ("
          + ", ".join(f"{eco} {written[eco]}" for eco in TARGET_ECOSYSTEMS) + ")")

    if purl2cpe is not None:
        print(f"\npurl2cpe: {len(purl2cpe.products)} products, {purl2cpe.bad_rows} unparsable rows")
        print("  (purl, cpe) relations: " + ", ".join(
            f"{t} {purl2cpe.relations_by_type[t]}" for t in TARGET_ECOSYSTEMS))
        print("  distinct base PURLs:   " + ", ".join(
            f"{t} {purl2cpe.purls_by_type[t]}" for t in TARGET_ECOSYSTEMS))
        other = {t: n for t, n in purl2cpe.purls_by_type.most_common() if t not in TARGET_ECOSYSTEMS}
        print(f"  other PURL types (distinct): {dict(list(other.items())[:8])}")

    if rows:
        before_index = CandidateIndex(cache or [], aliases)
        after_index = CandidateIndex(
            related | {(name, eco) for (eco, name) in small_sources(cache, purl2cpe)}, aliases)
        before = {r["package_id"]: r for r in match_packages(rows, before_index)}
        after = {r["package_id"]: r for r in match_packages(rows, after_index)}
        print(f"\nname_match for our {len(rows)} packages, release cache only -> reference list:")
        for status in MATCH_STATUSES:
            print(f"  {status:<10} {sum(r['match_status'] == status for r in before.values()):>5}"
                  f" -> {sum(r['match_status'] == status for r in after.values()):>5}")
        changed = [pid for pid in after if after[pid]["match_status"] != before[pid]["match_status"]]
        newly = [pid for pid in changed if after[pid]["match_status"] == MATCHED]
        print(f"  changed status: {len(changed)}, newly matched: {len(newly)}")
        for pid in changed[:EXAMPLES]:
            a, b = after[pid], before[pid]
            print(f"    {a['package_name']} ({a['ecosystem']}): {b['match_status']} -> "
                  f"{a['match_status']} {a['matched_name']} ({a['match_ecosystem']}) | {a['reason']}")

    if not args.apply:
        print(f"\nPreview only. Nothing was written. Re-run with --apply to write {out_path}.")
        return 0
    print(f"\nWrote {sum(written.values())} names to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
