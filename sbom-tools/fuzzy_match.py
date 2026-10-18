# sbom-tools/fuzzy_match.py
#
# Fuzzy name suggestions for packages that name_match.py left "unmatched".
# A suggestion is only ever a hint for review: confidence is capped at 0.70,
# so the status is "review", never "matched". Standard library only (difflib).
#
# Rules:
#   - only rows with match_status = 'unmatched'; matched / review rows are
#     never touched (the UPDATE itself checks the status)
#   - only pypi / npm / maven packages: "none" is on no registry, so any
#     registry name would be a different project
#   - names shorter than 4 characters (after collapse) are never fuzzy matched
#   - similarity = difflib ratio of the collapsed names; below the minimum
#     (default 0.90) there is no suggestion
#   - rejected outright: names that differ only by a trailing number or
#     version (jinja2 ~ jinja, mysql2 ~ mysql, pkg-1 ~ pkg-2) and type-stub
#     variants (types-x, x-stubs, x-types, @types/x)
#   - confidence 0.50 at the minimum up to 0.70 at similarity 1; a candidate
#     in another ecosystem loses 0.30 (name_match.ECOSYSTEM_PENALTY), so it
#     can only be listed as a competitor, never suggested
#   - ambiguous when another name in the same ecosystem scores within 0.02:
#     confidence drops to 0.50 and both names are in the reason
#
# Preview (default, writes nothing):
#     python sbom-tools/fuzzy_match.py
#     python sbom-tools/fuzzy_match.py --out fuzzy_preview.csv
# Write the suggestions (only the 7 match columns of still-unmatched rows):
#     python sbom-tools/fuzzy_match.py --apply
# Undo: run name_match.py --apply again (it recomputes every row).

import argparse
import csv
import difflib
import random
import re
import sys
from collections import Counter
from pathlib import Path

from name_match import (ECOSYSTEM_PENALTY, MATCHED_MIN, UNMATCHED, collapse, ecosystem_of,
                        load_candidates, normalized_name, status_for)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CANDIDATES = PROJECT_ROOT / "data-prep" / "reference_names.csv"
DEFAULT_REVIEW_CSV = PROJECT_ROOT / "data-prep" / "labeled_pairs_review.csv"

FUZZY = "fuzzy"
NO_MATCH = "none"
FUZZY_ECOSYSTEMS = ("pypi", "npm", "maven")

MIN_SIMILARITY = 0.90
LOWEST_ALLOWED_MIN_SIMILARITY = 0.80
CONFIDENCE_FLOOR = 0.50          # = the review cut-off
CONFIDENCE_CAP = 0.70            # never reaches matched (0.90)
AMBIGUITY_MARGIN = 0.02
MIN_LENGTH = 4
COMPETITORS_SHOWN = 3
NEAR_MISS_FLOOR = 0.75           # near misses below the minimum are named in the reason

REPORT_THRESHOLDS = (0.80, 0.85, 0.90, 0.95)
BACKGROUND_PAIRS = 4000          # random pairs per ecosystem for the false-positive estimate
BACKGROUND_SEED = 1

VERSION_TAIL = re.compile(r"-?v?\d+(?:[.-]\d+)*$")

# Outcomes without a suggestion
NOT_ON_REGISTRY = "not on a registry"
TOO_SHORT = "too short"
EXACT_EXISTS = "exact name exists"
BELOW_MINIMUM = "no candidate above minimum"
OTHER_ECOSYSTEM = "only other ecosystems"
SUGGESTED = "suggested"


def compare_key(name, ecosystem=None):
    """The form names are compared in: collapse(normalized_name(...))."""
    return collapse(normalized_name(name, ecosystem))


def stem(key):
    """key without a trailing number / version (jinja2 -> jinja, pkg-1.2 -> pkg)."""
    return VERSION_TAIL.sub("", key)


def version_only(a, b):
    """True when two different keys are equal once a trailing version is removed."""
    if a == b:
        return False
    sa, sb = stem(a), stem(b)
    return bool(sa) and sa == sb


def stub_variant(a, b):
    """True when one key is the type-stub package of the other."""
    for x, y in ((a, b), (b, a)):
        if x in (f"types-{y}", f"{y}-stubs", f"{y}-types", f"@types/{y}"):
            return True
    return False


def confidence_for(similarity, threshold, same_ecosystem=True):
    """0.50 at the threshold, 0.70 at similarity 1, minus the ecosystem penalty."""
    if threshold >= 1:
        base = CONFIDENCE_CAP
    else:
        base = CONFIDENCE_FLOOR + (CONFIDENCE_CAP - CONFIDENCE_FLOOR) * (
            (similarity - threshold) / (1 - threshold))
    confidence = min(max(base, 0.0), CONFIDENCE_CAP)
    if not same_ecosystem:
        confidence -= ECOSYSTEM_PENALTY
    return round(max(confidence, 0.0), 4)


class FuzzyIndex:
    """Known (name, ecosystem) pairs with their compare keys."""

    def __init__(self, candidates):
        seen = set()
        self.entries = []
        for name, eco in candidates:
            eco = ecosystem_of(eco) or eco
            if eco not in FUZZY_ECOSYSTEMS or not str(name or "").strip():
                continue
            if (eco, name) in seen:
                continue
            seen.add((eco, name))
            self.entries.append((name, eco, compare_key(name, eco)))
        self.entries.sort(key=lambda e: (e[1], e[0]))

    def __len__(self):
        return len(self.entries)

    def scores(self, key, threshold):
        """
        (above, best_below, exact): candidates with similarity >= threshold as
        (similarity, name, ecosystem, key), the best one below the threshold,
        and candidates whose key equals key.
        """
        matcher = difflib.SequenceMatcher(None, autojunk=False)
        matcher.set_seq2(key)          # b is analysed once; each candidate is seq1
        # real_quick_ratio / quick_ratio are upper bounds of ratio(), so they
        # can skip a candidate safely; the lower floor keeps near misses for
        # the "best below" text
        floor = min(threshold, NEAR_MISS_FLOOR)
        above, exact = [], []
        best_below = None
        for name, eco, cand_key in self.entries:
            if cand_key == key:
                exact.append((1.0, name, eco, cand_key))
                continue
            matcher.set_seq1(cand_key)
            if matcher.real_quick_ratio() < floor or matcher.quick_ratio() < floor:
                continue
            s = matcher.ratio()
            if s >= threshold:
                above.append((s, name, eco, cand_key))
            elif best_below is None or s > best_below[0]:
                best_below = (s, name, eco, cand_key)
        return above, best_below, exact


def describe(cands, limit=COMPETITORS_SHOWN):
    return ", ".join(f"'{n}' ({e}) {s:.3f}" for s, n, e, _ in cands[:limit])


def suggest(name, ecosystem, index, threshold=MIN_SIMILARITY):
    """
    Fuzzy suggestion for one unmatched package. Returns a dict with
    outcome, match_type ("fuzzy" or "none"), confidence, match_status,
    matched_name, match_ecosystem, normalized_name, similarity, competitors
    and reason. match_status is "review" for a suggestion, else "unmatched".
    """
    eco = ecosystem_of(ecosystem) or ecosystem
    result = {
        "outcome": None, "match_type": NO_MATCH, "confidence": 0.0,
        "match_status": UNMATCHED, "matched_name": None, "match_ecosystem": None,
        "normalized_name": normalized_name(name, eco), "similarity": None,
        "competitors": "", "reason": "",
    }

    def done(outcome, reason):
        result["outcome"], result["reason"] = outcome, reason
        return result

    if eco not in FUZZY_ECOSYSTEMS:
        return done(NOT_ON_REGISTRY, f"not on a registry (ecosystem {eco}): no fuzzy match")
    key = compare_key(name, eco)
    if len(key) < MIN_LENGTH:
        return done(TOO_SHORT, f"too short for fuzzy matching ({len(key)} < {MIN_LENGTH} characters)")

    above, best_below, exact = index.scores(key, threshold)
    if exact:
        return done(EXACT_EXISTS, f"exact name exists: {describe(exact)}; "
                                  "left to name_match, not fuzzy")

    rejected = [(s, n, e, k, "version-only") for s, n, e, k in above if version_only(key, k)]
    rejected += [(s, n, e, k, "type stub") for s, n, e, k in above
                 if not version_only(key, k) and stub_variant(key, k)]
    rejected_keys = {(n, e) for _, n, e, _, _ in rejected}
    scored = [c for c in above if (c[1], c[2]) not in rejected_keys]
    rejected_text = ("; rejected: " + ", ".join(
        f"'{n}' ({e}) {s:.3f} ({why})" for s, n, e, _, why in rejected[:COMPETITORS_SHOWN])
        if rejected else "")

    if not scored:
        best = f"; best below: '{best_below[1]}' ({best_below[2]}) {best_below[0]:.3f}" \
            if best_below else ""
        return done(BELOW_MINIMUM, f"no candidate >= {threshold:.2f}{best}{rejected_text}")

    # Highest similarity first; at equal similarity the package's own ecosystem
    scored.sort(key=lambda c: (-c[0], 0 if c[2] == eco else 1, c[1].lower(), c[2]))
    same = [c for c in scored if c[2] == eco]
    if not same:
        return done(OTHER_ECOSYSTEM,
                    f"only candidates in other ecosystems (-{ECOSYSTEM_PENALTY:.2f}, below review): "
                    f"{describe(scored)}{rejected_text}")

    top = same[0]
    others = [c for c in scored if c is not top]
    confidence = confidence_for(top[0], threshold, same_ecosystem=True)
    rivals = [c for c in same[1:] if top[0] - c[0] <= AMBIGUITY_MARGIN]
    reason = f"fuzzy similarity {top[0]:.3f} to '{top[1]}' ({top[2]})"
    if rivals:
        confidence = CONFIDENCE_FLOOR
        reason += f"; ambiguous: {describe(rivals)} within {AMBIGUITY_MARGIN}"
    if others:
        reason += f"; competing: {describe(others)}"
    reason += rejected_text

    status = status_for(confidence)
    assert status != "matched" and confidence < MATCHED_MIN   # the cap
    result.update({
        "match_type": FUZZY, "confidence": confidence, "match_status": status,
        "matched_name": top[1], "match_ecosystem": top[2], "similarity": round(top[0], 4),
        "competitors": describe(others, limit=len(others)),
    })
    return done(SUGGESTED, reason)


# ============================
# THRESHOLD REPORT (read-only, proposals only)
# ============================
def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def threshold_report(review_csv, index, thresholds=REPORT_THRESHOLDS):
    """Lines describing proposed pairs and random name pairs at each threshold."""
    with open(review_csv, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    lines = [f"{Path(review_csv).name}: {len(rows)} PROPOSED pairs, not reviewed: indicative only"]

    def key(name, eco):
        return compare_key(name, ecosystem_of(eco) or None)

    groups = {"match, same ecosystem": [], "match, cross-ecosystem": [], "non-match": []}
    for r in rows:
        s = similarity(key(r["name_a"], r["ecosystem_a"]), key(r["name_b"], r["ecosystem_b"]))
        if r["label"] == "match":
            same = (ecosystem_of(r["ecosystem_a"]) or r["ecosystem_a"]) == \
                   (ecosystem_of(r["ecosystem_b"]) or r["ecosystem_b"])
            groups["match, same ecosystem" if same else "match, cross-ecosystem"].append(s)
        elif r["label"] == "non-match":
            groups["non-match"].append(s)

    header = "  " + " " * 26 + "".join(f">= {t:.2f}   " for t in thresholds)
    lines.append(header)
    for label, ss in groups.items():
        if ss:
            lines.append(f"  {label:<24} n={len(ss):<4}" + "".join(
                f"{sum(s >= t for s in ss) / len(ss):>8.1%}   " for t in thresholds))
    identical = sum(s == 1.0 for s in groups["non-match"])
    if groups["non-match"] and identical == len(groups["non-match"]):
        lines.append("  All proposed non-matches have identical names, so they cannot measure "
                     "fuzzy precision.")

    rng = random.Random(BACKGROUND_SEED)
    by_eco = {}
    for _, eco, k in index.entries:
        by_eco.setdefault(eco, []).append(k)
    pairs = []
    for eco in sorted(by_eco):
        keys = by_eco[eco]
        if len(keys) < 2:
            continue
        for _ in range(BACKGROUND_PAIRS):
            a, b = rng.sample(keys, 2)
            if a != b:
                pairs.append((a, b))
    if pairs:
        scores = [similarity(a, b) for a, b in pairs]
        lines.append(f"  random distinct known names, same ecosystem (n={len(pairs)}, seed "
                     f"{BACKGROUND_SEED}): " + ", ".join(
                         f">= {t:.2f}: {sum(s >= t for s in scores)}" for t in thresholds))
    return lines


# ============================
# CLI
# ============================
OUT_COLUMNS = ["package_id", "package_name", "ecosystem", "outcome", "match_type",
               "confidence", "match_status", "matched_name", "match_ecosystem",
               "similarity", "competitors", "reason"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fuzzy suggestions for unmatched packages (preview by default)."
    )
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES),
                        help="known names (name,ecosystem CSV or release cache JSON)")
    parser.add_argument("--min-similarity", type=float, default=MIN_SIMILARITY,
                        help=f"minimum difflib similarity ({LOWEST_ALLOWED_MIN_SIMILARITY}-1)")
    parser.add_argument("--examples", type=int, default=None,
                        help="list at most N rows per outcome (default: all)")
    parser.add_argument("--out", help="write every unmatched row with its reason to this CSV")
    parser.add_argument("--review-csv", default=None,
                        help='proposed pairs for the threshold report ("" to skip; '
                             'default data-prep/labeled_pairs_review.csv if present)')
    parser.add_argument("--apply", action="store_true",
                        help="Actually write the suggestions. Without this flag only a preview is shown.")
    args = parser.parse_args(argv)

    if not LOWEST_ALLOWED_MIN_SIMILARITY <= args.min_similarity <= 1:
        print(f"Error: --min-similarity must be between {LOWEST_ALLOWED_MIN_SIMILARITY} and 1")
        return 2
    review_csv = args.review_csv
    if review_csv is None:
        review_csv = str(DEFAULT_REVIEW_CSV) if DEFAULT_REVIEW_CSV.is_file() else ""
    try:
        index = FuzzyIndex(load_candidates(args.candidates))
        if review_csv and not Path(review_csv).is_file():
            raise FileNotFoundError(f"review CSV not found: {review_csv}")
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        return 2

    from db_storage import get_db_storage
    db = get_db_storage()
    rows = [r for r in db.package_match_status_rows() if r["match_status"] == UNMATCHED]

    results = []
    for r in rows:
        s = suggest(r["package_name"], r["ecosystem"], index, args.min_similarity)
        results.append({"package_id": r["package_id"], "package_name": r["package_name"],
                        "ecosystem": r["ecosystem"], **s})
    suggestions = [r for r in results if r["outcome"] == SUGGESTED]

    print(f"{len(index)} known names ({dict(Counter(e for _, e, _ in index.entries))}); "
          f"minimum similarity {args.min_similarity:.2f}")
    print(f"Unmatched packages: {len(rows)}; would get a fuzzy suggestion: {len(suggestions)}")
    outcomes = Counter(r["outcome"] for r in results)
    for outcome in (SUGGESTED, NOT_ON_REGISTRY, TOO_SHORT, EXACT_EXISTS, OTHER_ECOSYSTEM,
                    BELOW_MINIMUM):
        print(f"  {outcome:<28} {outcomes.get(outcome, 0)}")

    for outcome in (SUGGESTED, OTHER_ECOSYSTEM, BELOW_MINIMUM, EXACT_EXISTS, TOO_SHORT,
                    NOT_ON_REGISTRY):
        shown = [r for r in results if r["outcome"] == outcome]
        if args.examples is not None:
            shown = shown[:args.examples]
        if not shown:
            continue
        print(f"\n{outcome}:")
        for r in shown:
            target = (f" -> {r['matched_name']} ({r['match_ecosystem']}) "
                      f"{r['confidence']:.2f} {r['match_status']}" if r["matched_name"] else "")
            print(f"  {r['package_name']} ({r['ecosystem']}){target} | {r['reason']}")

    if review_csv:
        print()
        for line in threshold_report(review_csv, index):
            print(line)

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=OUT_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
        print(f"\nWrote {len(results)} rows to {args.out}")

    if not args.apply:
        print("\nPreview only. Nothing was changed. Re-run with --apply to write the suggestions.")
        return 0

    written = db.update_unmatched_package_matches(suggestions)
    print(f"\nWrote fuzzy suggestions for {written} packages"
          + (f" ({len(suggestions) - written} skipped: no longer unmatched)"
             if written < len(suggestions) else "") + ".")
    return 0


if __name__ == "__main__":
    sys.exit(main())
