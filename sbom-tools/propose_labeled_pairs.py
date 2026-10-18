# sbom-tools/propose_labeled_pairs.py
#
# Propose candidate pairs for labeled_pairs, from local reference files, into
# a REVIEW CSV. It never writes to the database: importing reviewed pairs is
# a separate step that needs approval.
#
# Evidence used ("match" means the same project, possibly in two ecosystems):
#   match      purl2cpe             PURLs of one purl2cpe product
#                                   (pkg:pypi/django <-> pkg:github/django/django),
#                                   and a PURL <-> its CPE product name
#   match      cross-eco-repo       Package-List names in different ecosystems
#                                   with the same GitHub repository
#   non-match  same-name-different-repo
#                                   the same name (ignoring case/separators) in
#                                   two ecosystems with different repositories
#   non-match  matcher-review-contradicted
#                                   a name_match "review" pair whose two names
#                                   have different repositories
#
# Every row is only a proposal: the "reviewed" column is left blank.
#
# Inputs (you download them; no network):
#   data-prep/external/Package-List/*.csv   ("" to skip)
#   data-prep/external/purl2cpe.db.zip      ("" to skip)
#   --repo-urls data-prep/repo_urls.csv     repository URLs looked up by
#                                           fetch_repo_urls.py (off by default)
# By default only pairs involving names related to our packages are kept
# (reads packages, read-only); --all keeps everything (needs much memory with
# the full Package-List).
#
# Preview (default, writes nothing):
#     python sbom-tools/propose_labeled_pairs.py
# Write data-prep/labeled_pairs_review.csv:
#     python sbom-tools/propose_labeled_pairs.py --apply

import argparse
import csv
import os
import random
import re
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path

from name_match import (REVIEW, CandidateIndex, best_match, collapse, ecosystem_of,
                        load_aliases)
from reference_sources import (TARGET_ECOSYSTEMS, iter_package_lists, normalize_repo_url,
                               package_list_files, parse_purl, purl_ecosystem,
                               purl_package_name, read_purl2cpe)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXTERNAL = PROJECT_ROOT / "data-prep" / "external"
DEFAULT_PACKAGE_LISTS = EXTERNAL / "Package-List"
DEFAULT_PURL2CPE = EXTERNAL / "purl2cpe.db.zip"
DEFAULT_OUT = PROJECT_ROOT / "data-prep" / "labeled_pairs_review.csv"

MATCH = "match"
NON_MATCH = "non-match"
LABELS = (MATCH, NON_MATCH)          # the only labels labeled_pairs allows

# Proposed confidence per evidence source (how much the evidence alone says)
SOURCE_CONFIDENCE = {
    "purl2cpe": 0.95,
    "cross-eco-repo": 0.90,
    "same-name-different-repo": 0.80,
    "matcher-review-contradicted": 0.70,
}
MAX_PAIRS_PER_GROUP = 10             # per purl2cpe product / repository / name

# purl2cpe puts every PURL of one CPE product in one group, so a pair whose
# names don't look alike (jinja2 ~ jinja, libxml++2.6 ~ ...:libxml) is often
# a different package of the same product: much lower confidence
HIGH = "high"
LOW = "low"
PURL2CPE_LOW_SIMILARITY_CONFIDENCE = 0.50

COLUMNS = ["name_a", "ecosystem_a", "name_b", "ecosystem_b", "label", "source",
           "package_id", "note", "evidence", "proposed_confidence", "name_similarity",
           "reviewed"]


def name_part(name):
    """The part of a name to compare: npm @scope/NAME, Maven group:ARTIFACT[:version]."""
    text = str(name or "").strip()
    if text.startswith("@") and "/" in text:
        return text.split("/", 1)[1]
    if ":" in text:
        return text.split(":")[1]
    return text


def name_tokens(name):
    """
    Words of a name: collapse() (lowercase, - _ . space -> "-") split on "-"
    and "/". "+" and digits stay inside a word: jinja2 is one word,
    libxml++2.6 is [libxml++, 2, 6].
    """
    return [t for t in re.split(r"[-/]+", collapse(name_part(name))) if t]


def name_similarity(a, b):
    """
    "high" when the names have the same words, or one name's words appear as a
    contiguous run in the other's (node-lodash ~ lodash, log4j-core ~ log4j,
    django ~ django/django); "low" otherwise (jinja2 ~ jinja, re ~ regex).
    """
    ta, tb = name_tokens(a), name_tokens(b)
    if not ta or not tb:
        return LOW
    short, long_ = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    for i in range(len(long_) - len(short) + 1):
        if long_[i:i + len(short)] == short:
            return HIGH
    return LOW


def row_order(r):
    """Output order: high name similarity first, then label, source and names."""
    return (0 if r["name_similarity"] == HIGH else 1, r["label"], r["source"],
            r["ecosystem_a"], r["name_a"], r["ecosystem_b"], r["name_b"])


class PairSet:
    """Proposed pairs, one per unordered pair of (name, ecosystem)."""

    def __init__(self, ours):
        self.ours = ours              # {(ecosystem, name): package_id}
        self.pairs = {}               # frozenset(side_a, side_b) -> row
        self.conflicts = 0

    def add(self, a, eco_a, b, eco_b, label, source, evidence, note=""):
        side_a, side_b = (eco_a, a), (eco_b, b)
        if side_a == side_b:
            return
        # Our package first, so package_id points at name_a
        if side_b in self.ours and side_a not in self.ours:
            side_a, side_b = side_b, side_a
        key = frozenset((side_a, side_b))
        similarity = name_similarity(side_a[1], side_b[1])
        confidence = SOURCE_CONFIDENCE[source]
        if source == "purl2cpe" and similarity == LOW:
            confidence = PURL2CPE_LOW_SIMILARITY_CONFIDENCE
        row = {
            "name_a": side_a[1], "ecosystem_a": side_a[0],
            "name_b": side_b[1], "ecosystem_b": side_b[0],
            "label": label, "source": source,
            "package_id": self.ours.get(side_a, ""),
            "note": note, "evidence": evidence,
            "proposed_confidence": confidence, "name_similarity": similarity,
            "reviewed": "",
        }
        existing = self.pairs.get(key)
        if existing is None:
            self.pairs[key] = row
        elif existing["label"] != label:
            # Match evidence (same product / repository) outweighs a
            # non-match guess; keep it and say there was a conflict
            self.conflicts += 1
            keep, other = (existing, row) if existing["label"] == MATCH else (row, existing)
            keep["note"] = (keep["note"] + "; " if keep["note"] else "") + \
                f"conflicting {other['source']} evidence: {other['evidence']}"
            self.pairs[key] = keep

    def rows(self):
        return sorted(self.pairs.values(), key=row_order)


def capped_pairs(members, limit=MAX_PAIRS_PER_GROUP):
    """Up to limit pairs from a group, in a fixed order."""
    out = []
    for x, y in combinations(sorted(members), 2):
        out.append((x, y))
        if len(out) >= limit:
            break
    return out


def sample(rows, max_pairs, seed):
    """At most max_pairs rows, half per label where possible, reproducible."""
    if max_pairs is None or len(rows) <= max_pairs:
        return rows
    rng = random.Random(seed)
    by_label = {label: [r for r in rows if r["label"] == label] for label in LABELS}
    quota = {label: min(len(v), max_pairs // 2) for label, v in by_label.items()}
    spare = max_pairs - sum(quota.values())
    for label in LABELS:                          # give unused quota to the other label
        extra = min(spare, len(by_label[label]) - quota[label])
        quota[label] += extra
        spare -= extra
    picked = []
    for label in LABELS:
        picked += rng.sample(by_label[label], quota[label])
    return sorted(picked, key=row_order)


def read_repo_urls(path):
    """
    (name, ecosystem, normalized repository) for every "ok" row of a
    fetch_repo_urls.py results file (the last row per name wins). Raises
    FileNotFoundError when the file is missing.
    """
    from fetch_repo_urls import OK, load_results

    if not Path(path).is_file():
        raise FileNotFoundError(f"repo URLs file not found: {path}")
    rows = []
    for (eco, name), row in sorted(load_results(path).items()):
        repo = normalize_repo_url(row.get("repository_url")) if row.get("status") == OK else None
        if repo:
            rows.append((name, eco, repo))
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Propose labeled_pairs candidates into a review CSV (preview by default)."
    )
    parser.add_argument("--package-lists", default=str(DEFAULT_PACKAGE_LISTS),
                        help='folder with the Package-List CSVs ("" to skip)')
    parser.add_argument("--purl2cpe", default=str(DEFAULT_PURL2CPE),
                        help='purl2cpe.db.zip ("" to skip)')
    parser.add_argument("--repo-urls", default="",
                        help="repo_urls.csv from fetch_repo_urls.py (off by default)")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="review CSV (written with --apply)")
    parser.add_argument("--all", action="store_true",
                        help="keep pairs for all names, not only names related to our packages")
    parser.add_argument("--max-pairs", type=int, default=5000, help="at most this many rows")
    parser.add_argument("--seed", type=int, default=42, help="seed for sampling down to --max-pairs")
    parser.add_argument("--examples", type=int, default=10)
    parser.add_argument("--apply", action="store_true",
                        help="Actually write the review CSV. Without this flag only a preview is shown.")
    args = parser.parse_args(argv)

    try:
        if args.package_lists:
            package_list_files(args.package_lists)
        if not (args.package_lists or args.purl2cpe or args.repo_urls):
            raise FileNotFoundError("no sources given")
        purl2cpe = read_purl2cpe(args.purl2cpe) if args.purl2cpe else None
        repo_url_rows = read_repo_urls(args.repo_urls) if args.repo_urls else []
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        return 2

    from db_storage import get_db_storage
    packages = get_db_storage().package_match_rows()

    aliases = load_aliases()
    keys_of = CandidateIndex([], aliases).keys
    ours = {}
    relevant = None if args.all else set()
    for r in packages:
        eco = ecosystem_of(r["ecosystem"]) or r["ecosystem"]
        ours[(eco, r["package_name"])] = r["package_id"]
        if relevant is not None:
            relevant |= keys_of(str(r["package_name"]))

    def is_relevant(name):
        return relevant is None or bool(keys_of(name) & relevant)

    pairs = PairSet(ours)

    # ---------- purl2cpe: one product = one project ----------
    if purl2cpe is not None:
        for (vendor, product), purls in sorted(purl2cpe.products.items()):
            members = sorted({(purl_ecosystem(p.type), purl_package_name(p))
                              for p in map(parse_purl, purls)})
            targets = [m for m in members if m[0] in TARGET_ECOSYSTEMS]
            if not targets:
                continue
            if not (is_relevant(product) or any(is_relevant(n) for _, n in members)):
                continue
            evidence = f"same purl2cpe product {vendor}:{product}"
            for x, y in capped_pairs(members):
                if x[0] in TARGET_ECOSYSTEMS or y[0] in TARGET_ECOSYSTEMS:
                    pairs.add(x[1], x[0], y[1], y[0], MATCH, "purl2cpe", evidence)
            for eco, name in targets[:MAX_PAIRS_PER_GROUP]:
                pairs.add(name, eco, product, "cpe", MATCH, "purl2cpe",
                          f"CPE product of {name}: cpe vendor {vendor}",
                          note="name_b is a CPE product name")

    # ---------- repositories: Package-List and/or repo_urls.csv ----------
    by_name = {}             # collapse(name) -> {(ecosystem, name): repo}
    by_repo = {}             # repo -> {(ecosystem, name)}
    from_lookup = set()      # (ecosystem, name) whose repo came from repo_urls.csv

    def add_repo(name, eco, repo, looked_up=False):
        group = by_name.setdefault(collapse(name), {})
        if repo or (eco, name) not in group:
            group[(eco, name)] = repo
        if repo:
            by_repo.setdefault(repo, set()).add((eco, name))
            if looked_up:
                from_lookup.add((eco, name))

    if args.package_lists:
        wanted_repos = set()
        for name, eco, url in iter_package_lists(args.package_lists):
            if is_relevant(name):
                repo = normalize_repo_url(url)
                add_repo(name, eco, repo)
                if repo:
                    wanted_repos.add(repo)
        # Second pass: every name sharing a repository with a relevant one
        if wanted_repos:
            for name, eco, url in iter_package_lists(args.package_lists):
                repo = normalize_repo_url(url)
                if repo in wanted_repos:
                    by_repo.setdefault(repo, set()).add((eco, name))

    for name, eco, repo in repo_url_rows:
        if is_relevant(name):
            add_repo(name, eco, repo, looked_up=True)

    def where(*sides):
        return " (repo_urls.csv)" if any(side in from_lookup for side in sides) else ""

    for repo, members in sorted(by_repo.items()):
        if len({eco for eco, _ in members}) < 2:
            continue
        for x, y in capped_pairs(members):
            if x[0] != y[0]:
                pairs.add(x[1], x[0], y[1], y[0], MATCH, "cross-eco-repo",
                          f"same repository {repo}{where(x, y)}")

    for key, group in sorted(by_name.items()):
        members = sorted(((eco, name, repo) for (eco, name), repo in group.items()),
                         key=lambda m: (m[0], m[1], m[2] or ""))
        found = 0
        for x, y in combinations(members, 2):
            if x[0] != y[0] and x[2] and y[2] and x[2] != y[2]:
                pairs.add(x[1], x[0], y[1], y[0], NON_MATCH, "same-name-different-repo",
                          f"same name, different repositories ({x[2]} vs {y[2]})"
                          + where(x[:2], y[:2]))
                found += 1
                if found >= MAX_PAIRS_PER_GROUP:
                    break

    # ---------- name_match review pairs the sources contradict ----------
    repo_of = {side: repo for group in by_name.values() for side, repo in group.items() if repo}
    if repo_of:
        index = CandidateIndex(list({(name, eco) for eco, name in repo_of}), aliases)
        for r in packages:
            eco = ecosystem_of(r["ecosystem"]) or r["ecosystem"]
            mine = repo_of.get((eco, r["package_name"]))
            best = best_match(r["package_name"], r["ecosystem"], index)
            if best["match_status"] != REVIEW or not mine:
                continue
            theirs = repo_of.get((best["match_ecosystem"], best["matched_name"]))
            if theirs and theirs != mine:
                pairs.add(r["package_name"], eco, best["matched_name"], best["match_ecosystem"],
                          NON_MATCH, "matcher-review-contradicted",
                          f"name_match review ({best['confidence']:.2f}: {best['reason']}); "
                          f"repositories differ ({mine} vs {theirs})")

    # ---------- report / write ----------
    all_rows = pairs.rows()
    rows = sample(all_rows, args.max_pairs, args.seed)

    print(f"{len(packages)} packages; {'all names' if args.all else 'names related to our packages'}")
    print(f"Proposed pairs: {len(all_rows)} (conflicting evidence resolved: {pairs.conflicts})"
          + (f", sampled to {len(rows)} (--max-pairs {args.max_pairs}, --seed {args.seed})"
             if len(rows) < len(all_rows) else ""))
    for (label, source), n in sorted(Counter((r["label"], r["source"]) for r in rows).items()):
        print(f"  {label:<10} {source:<28} {n}")
    print(f"With a package_id (name_a is one of our packages): {sum(bool(r['package_id']) for r in rows)}")
    similarity = Counter(r["name_similarity"] for r in rows)
    purl_similarity = Counter(r["name_similarity"] for r in rows if r["source"] == "purl2cpe")
    print(f"Name similarity: high {similarity[HIGH]}, low {similarity[LOW]} "
          f"(purl2cpe: high {purl_similarity[HIGH]}, low {purl_similarity[LOW]})")

    def show(title, shown):
        if shown:
            print(f"\nExamples: {title}")
            for r in shown:
                print(f"  {r['name_a']} ({r['ecosystem_a']}) ~ {r['name_b']} ({r['ecosystem_b']})"
                      f" [{r['source']}, {r['name_similarity']}, {r['proposed_confidence']}]"
                      f" {r['evidence']}")

    for label in LABELS:
        show(label, [r for r in rows if r["label"] == label][:args.examples])
    show("low name similarity",
         [r for r in rows if r["name_similarity"] == LOW][:args.examples])

    if not args.apply:
        print(f"\nPreview only. Nothing was written. Re-run with --apply to write {args.out}.")
        return 0

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_name(out_path.name + ".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, out_path)
    finally:
        if tmp_path.exists():
            os.remove(tmp_path)
    print(f"\nWrote {len(rows)} proposed pairs to {out_path} (review them before any import).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
