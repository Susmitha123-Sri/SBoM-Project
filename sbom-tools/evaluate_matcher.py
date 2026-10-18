# sbom-tools/evaluate_matcher.py
#
# Read-only evaluation of name_match.match_pair against the PROPOSED pairs in
# data-prep/labeled_pairs_review.csv (written by propose_labeled_pairs.py and
# never reviewed by a person). No database: it only reads that CSV and writes
# at most one CSV, always inside data-prep/.
#
# Numbers (per group, for each evaluable pair: proposed label L, matcher
# status S = name_match.status_for(match_pair(...)["confidence"])):
#   strict view  predicted positive = S is "matched"
#   loose view   predicted positive = S is "matched" or "review"
#   TP = L match and positive      FN = L match and not positive
#   FP = L non-match and positive  TN = L non-match and not positive
#   precision-like = TP/(TP+FP), recall-like = TP/(TP+FN),
#   non-match agreement = TN/(TN+FP); "n/a" when the denominator is 0.
# These are AGREEMENT WITH PROPOSED LABELS, not true precision / recall.
#
#     python sbom-tools/evaluate_matcher.py                 # report + data-prep/matcher_evaluation.csv
#     python sbom-tools/evaluate_matcher.py --out ""        # report only
#     python sbom-tools/evaluate_matcher.py --examples 0    # list every disagreement

import argparse
import csv
import os
import sys
from collections import Counter
from pathlib import Path

from name_match import MATCHED, REVIEW, UNMATCHED, ecosystem_of, match_pair, status_for

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_PREP = PROJECT_ROOT / "data-prep"          # the only folder this script writes to
REVIEW_FILE = "labeled_pairs_review.csv"
OUT_FILE = "matcher_evaluation.csv"

EVALUABLE_ECOSYSTEMS = ("pypi", "npm", "maven")
MATCH, NON_MATCH = "match", "non-match"
STATUSES = (MATCHED, REVIEW, UNMATCHED)
STRICT, LOOSE = "strict", "loose"
VIEWS = {
    STRICT: ("positive = matched only", (MATCHED,)),
    LOOSE: ("positive = matched or review", (MATCHED, REVIEW)),
}
HEADING = "AGREEMENT WITH PROPOSED LABELS (not true precision/recall)"
EXAMPLES = 20

OUT_COLUMNS = ["name_a", "ecosystem_a", "name_b", "ecosystem_b", "proposed_label", "source",
               "name_similarity", "evaluable", "not_evaluable_reason", "relation", "match_type",
               "confidence", "status", "agrees_matched_only", "agrees_matched_or_review",
               "reason"]


# ============================
# ONE PAIR
# ============================
def eco(value):
    text = str(value or "").strip()
    return ecosystem_of(text) or text.lower()


def evaluate_row(row):
    """The row with the matcher's verdict added (or why it can't be evaluated)."""
    ea, eb = eco(row.get("ecosystem_a")), eco(row.get("ecosystem_b"))
    out = {
        "name_a": row.get("name_a", ""), "ecosystem_a": row.get("ecosystem_a", ""),
        "name_b": row.get("name_b", ""), "ecosystem_b": row.get("ecosystem_b", ""),
        "proposed_label": (row.get("label") or "").strip(),
        "source": (row.get("source") or "").strip(),
        "name_similarity": (row.get("name_similarity") or "").strip() or "missing",
        "evaluable": False, "not_evaluable_reason": "", "relation": "",
        "match_type": "", "confidence": "", "status": "",
        "agrees_matched_only": "", "agrees_matched_or_review": "", "reason": "",
    }
    if not ea or not eb:
        out["not_evaluable_reason"] = "missing ecosystem"
        return out
    unsupported = sorted({e for e in (ea, eb) if e not in EVALUABLE_ECOSYSTEMS})
    if unsupported:
        out["not_evaluable_reason"] = ("identifier type not handled by name_match: "
                                       + "+".join(unsupported))
        return out

    result = match_pair(out["name_a"], ea, out["name_b"], eb)
    status = status_for(result["confidence"])
    out.update({
        "evaluable": True,
        "relation": "same-ecosystem" if ea == eb else "cross-ecosystem",
        "match_type": result["match_type"], "confidence": result["confidence"],
        "status": status, "reason": result["reason"],
    })
    for view, column in ((STRICT, "agrees_matched_only"), (LOOSE, "agrees_matched_or_review")):
        positive = status in VIEWS[view][1]
        out[column] = positive == (out["proposed_label"] == MATCH)
    return out


# ============================
# NUMBERS
# ============================
def rate(numerator, denominator):
    """A fraction, or None when the denominator is 0."""
    return numerator / denominator if denominator else None


def fmt_rate(value):
    return "n/a" if value is None else f"{value:.1%}"


def confusion(rows, view):
    """{"TP", "FP", "FN", "TN"} and the three rates for evaluable rows."""
    positives = VIEWS[view][1]
    c = Counter()
    for r in rows:
        positive = r["status"] in positives
        if r["proposed_label"] == MATCH:
            c["TP" if positive else "FN"] += 1
        elif r["proposed_label"] == NON_MATCH:
            c["FP" if positive else "TN"] += 1
    return {
        "TP": c["TP"], "FP": c["FP"], "FN": c["FN"], "TN": c["TN"],
        "precision_like": rate(c["TP"], c["TP"] + c["FP"]),
        "recall_like": rate(c["TP"], c["TP"] + c["FN"]),
        "non_match_agreement": rate(c["TN"], c["TN"] + c["FP"]),
    }


def status_counts(rows, label):
    """n and {status: count} for evaluable rows with this proposed label."""
    picked = [r for r in rows if r["proposed_label"] == label]
    return len(picked), Counter(r["status"] for r in picked)


def group_lines(title, rows):
    """Report lines for one group of evaluable rows."""
    lines = [f"  {title}  (n={len(rows)})"]
    for label in (MATCH, NON_MATCH):
        n, counts = status_counts(rows, label)
        lines.append(f"    proposed {label:<10} n={n:<4} " + "  ".join(
            f"{s} {counts.get(s, 0)}" for s in STATUSES))
    for view, (description, _) in VIEWS.items():
        c = confusion(rows, view)
        lines.append(f"    {description:<29} TP {c['TP']}  FP {c['FP']}  FN {c['FN']}  TN {c['TN']}"
                     f"  | precision-like {fmt_rate(c['precision_like'])}"
                     f"  recall-like {fmt_rate(c['recall_like'])}"
                     f"  non-match agreement {fmt_rate(c['non_match_agreement'])}")
    return lines


def disagreements(rows):
    """Evaluable rows that disagree in at least one view; proposed matches first."""
    found = [r for r in rows if r["evaluable"]
             and not (r["agrees_matched_only"] and r["agrees_matched_or_review"])]
    return sorted(found, key=lambda r: (r["proposed_label"] != MATCH, r["source"],
                                        r["ecosystem_a"], r["name_a"], r["ecosystem_b"],
                                        r["name_b"]))


def report(results, review_path, examples=EXAMPLES):
    """The full screen report as a list of lines."""
    evaluable = [r for r in results if r["evaluable"]]
    not_evaluable = Counter(r["not_evaluable_reason"] for r in results if not r["evaluable"])
    proposed_matches = sum(r["proposed_label"] == MATCH for r in results)
    unhandled_matches = sum(r["proposed_label"] == MATCH and not r["evaluable"] for r in results)

    lines = [
        "LIMITS (read before the numbers):",
        f"  1. The labels in {Path(review_path).name} are PROPOSALS made by "
        "propose_labeled_pairs.py; no person has reviewed them.",
        "  2. Non-match results are partly circular: proposed non-matches are the same name in "
        "two ecosystems, which name_match caps at 0.70 (review) by design. So the loose view "
        "counts them as positives and the strict view can never call them matched.",
        f"  3. Most proposed matches use identifier types name_match does not handle: "
        f"{unhandled_matches} of {proposed_matches} proposed matches are not evaluable.",
        f"  4. Only {', '.join(EVALUABLE_ECOSYSTEMS)} pairs are evaluated.",
        "",
        f"Pairs: {len(results)}; evaluable: {len(evaluable)}; not evaluable: "
        f"{len(results) - len(evaluable)}",
    ]
    for reason, n in not_evaluable.most_common():
        lines.append(f"  not evaluable: {n:>4}  {reason}")

    lines += ["", HEADING]
    lines += group_lines("all evaluable pairs", evaluable)

    def section(title, key):
        out = ["", f"{HEADING}, by {title}"]
        for value in sorted({r[key] for r in evaluable}):
            out += group_lines(f"{title} = {value}", [r for r in evaluable if r[key] == value])
        return out

    lines += section("relation", "relation")
    lines += section("source", "source")
    lines += section("name_similarity", "name_similarity")

    found = disagreements(results)
    shown = found if not examples else found[:examples]
    lines += ["", f"Disagreements (in at least one view): {len(found)}"
              + (f", showing {len(shown)}" if len(shown) < len(found) else "")]
    for r in shown:
        views = ", ".join(v for v, col in ((STRICT, "agrees_matched_only"),
                                           (LOOSE, "agrees_matched_or_review")) if not r[col])
        lines.append(f"  proposed {r['proposed_label']}: {r['name_a']} ({r['ecosystem_a']}) ~ "
                     f"{r['name_b']} ({r['ecosystem_b']}) [{r['source']}] -> {r['status']} "
                     f"{r['confidence']} (disagrees: {views}) | {r['reason']}")
    return lines


# ============================
# FILES
# ============================
def inside_data_prep(path):
    """True when path resolves to a location inside DATA_PREP."""
    try:
        Path(path).resolve().relative_to(Path(DATA_PREP).resolve())
        return True
    except ValueError:
        return False


def write_csv(path, results):
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=OUT_COLUMNS)
            writer.writeheader()
            writer.writerows(results)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            os.remove(tmp)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only: compare name_match with the PROPOSED labeled pairs."
    )
    parser.add_argument("--review-csv", default=None,
                        help=f"proposed pairs (default data-prep/{REVIEW_FILE})")
    parser.add_argument("--out", default=None,
                        help=f'result CSV inside data-prep/ (default data-prep/{OUT_FILE}; "" = none)')
    parser.add_argument("--examples", type=int, default=EXAMPLES,
                        help="disagreements to list on screen (0 = all; the CSV has all)")
    args = parser.parse_args(argv)

    review_path = Path(args.review_csv) if args.review_csv else Path(DATA_PREP) / REVIEW_FILE
    out_path = None if args.out == "" else (Path(args.out) if args.out else Path(DATA_PREP) / OUT_FILE)

    if not review_path.is_file():
        print(f"Error: review CSV not found: {review_path}")
        return 2
    if out_path is not None and not inside_data_prep(out_path):
        print(f"Error: --out must be inside {Path(DATA_PREP).resolve()} (got {out_path.resolve()})")
        return 2

    with open(review_path, encoding="utf-8", newline="") as f:
        results = [evaluate_row(row) for row in csv.DictReader(f)]

    for line in report(results, review_path, args.examples):
        print(line)

    if out_path is not None:
        write_csv(out_path, results)
        print(f"\nWrote {len(results)} rows to {out_path}")
    print("\nRead-only: no database was used and labeled_pairs was not touched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
