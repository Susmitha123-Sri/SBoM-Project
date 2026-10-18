# sbom-tools/name_match.py
#
# Rule-based package name matching: is name A (from an SBOM / the packages
# table) the same package as name B (a known registry name)? Every answer
# says how it matched (match_type), how sure it is (confidence, 0-1) and why
# (reason). Fuzzy matching and evaluation against labeled_pairs come later.
#
# Layers, checked in order (first hit wins):
#
#   exact            identical strings                                  1.00
#   normalized       same ignoring case; for PyPI, same PEP 503 name    0.95
#                    outside PyPI, differs only in separators - _ .     0.75
#   alias            listed together in name_aliases.json               0.90
#   scope_stripped   npm @scope/x <-> x, Maven group:artifact <-> art.  0.60
#                    (never @types/x: type definitions, not package x)
#   prefix_stripped  python-x <-> x                                     0.60
#                    libx / lib-x <-> x (x at least 4 characters)       0.50
#   none             nothing applies                                    0.00
#
# Then, when both ecosystems are known and differ, 0.30 is subtracted (floor
# 0). "none" (on no registry) counts as known, so a no-registry package never
# auto-matches a same-named PyPI/npm project. A missing ecosystem gets no
# penalty; the reason says it is unknown.
#
# Status: matched >= 0.90, review >= 0.50, else unmatched.
#
# The module is pure (no database, no network). The CLI fills the
# packages.match columns and NEVER writes labeled_pairs:
#
#   Back up first, e.g.:
#       mysqldump -u root -p sbom_common --result-file=backups/sbom_common_before_step3.sql
#   Preview (default, changes nothing):
#       python sbom-tools/name_match.py
#       python sbom-tools/name_match.py --out match_preview.csv
#   Write for real:
#       python sbom-tools/name_match.py --apply
#   Undo (or restore the backup):
#       UPDATE packages SET normalized_name=NULL, matched_name=NULL,
#         match_ecosystem=NULL, match_method=NULL, match_score=NULL,
#         match_status=NULL, matched_at=NULL;

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

from packaging.utils import canonicalize_name

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ALIASES = Path(__file__).resolve().with_name("name_aliases.json")
DEFAULT_CANDIDATES = PROJECT_ROOT / "data-prep" / "release_cache.json"

# ============================
# MATCH TYPES AND CONFIDENCE
# ============================
EXACT = "exact"
NORMALIZED = "normalized"
ALIAS = "alias"
SCOPE_STRIPPED = "scope_stripped"
PREFIX_STRIPPED = "prefix_stripped"
NO_MATCH = "none"
MATCH_TYPES = [EXACT, NORMALIZED, ALIAS, SCOPE_STRIPPED, PREFIX_STRIPPED, NO_MATCH]

EXACT_CONFIDENCE = 1.00
NORMALIZED_CONFIDENCE = 0.95
SEPARATORS_ONLY_CONFIDENCE = 0.75   # outside PyPI separators are significant
ALIAS_CONFIDENCE = 0.90             # default; an alias entry may set its own
SCOPE_CONFIDENCE = 0.60
PYTHON_PREFIX_CONFIDENCE = 0.60
LIB_PREFIX_CONFIDENCE = 0.50
LIB_MIN_REST = 4                    # "librt" -> "rt" is too short to trust

ECOSYSTEM_PENALTY = 0.30

# ============================
# STATUS (packages.match_status)
# ============================
MATCHED = "matched"
REVIEW = "review"
UNMATCHED = "unmatched"
MATCH_STATUSES = [MATCHED, REVIEW, UNMATCHED]
MATCHED_MIN = 0.90
REVIEW_MIN = 0.50

# ============================
# ECOSYSTEMS
# ============================
# Spellings found in packages.ecosystem / CSVs -> one name. "none" means
# "on no registry" and is a known value; anything else is unknown (None).
ECOSYSTEMS = {
    "pypi": "pypi", "python": "pypi",
    "npm": "npm", "node": "npm",
    "maven": "maven",
    "github": "github", "github-action": "github",
    "none": "none",
}

SEPARATORS = re.compile(r"[-_.\s]+")


def ecosystem_of(value):
    """Known ecosystem name ("pypi", "npm", "maven", "github", "none") or None."""
    return ECOSYSTEMS.get(str(value or "").strip().lower())


def normalized_name(name, ecosystem=None):
    """
    The name in the form its ecosystem compares names (packages.normalized_name):
    PyPI PEP 503; npm lowercase (separators are significant there); Maven
    lowercase group:artifact without a version; otherwise lowercase.
    """
    text = str(name or "").strip()
    eco = ecosystem_of(ecosystem)
    if eco == "pypi":
        return canonicalize_name(text)
    if eco == "maven":
        return ":".join(text.lower().split(":")[:2])
    return text.lower()


def collapse(name):
    """Lowercase with every run of separators as one "-" (the loosest form)."""
    return SEPARATORS.sub("-", str(name or "").strip().lower())


def status_for(confidence):
    if confidence >= MATCHED_MIN:
        return MATCHED
    if confidence >= REVIEW_MIN:
        return REVIEW
    return UNMATCHED


# ============================
# ALIASES (name_aliases.json)
# ============================
class AliasFileError(ValueError):
    pass


class AliasTable:
    """Per ecosystem: normalized alias -> normalized canonical, plus display names."""

    def __init__(self):
        self.to_canonical = {}     # eco -> {alias key: canonical key}
        self.canonicals = {}       # eco -> {canonical key: canonical display name}
        self.confidence = {}       # (eco, alias key) -> confidence
        self.notes = {}            # (eco, alias key) -> note

    def canonical(self, eco, key):
        """Canonical key for key, if key is an alias or a canonical; else None."""
        if key in self.to_canonical.get(eco, {}):
            return self.to_canonical[eco][key]
        if key in self.canonicals.get(eco, {}):
            return key
        return None

    def ecosystems(self):
        return sorted(set(self.to_canonical) | set(self.canonicals))


_alias_cache = {}


def load_aliases(path=None):
    """
    Read and validate an alias file (default: name_aliases.json next to this
    module). Cached per path. Raises AliasFileError for an unknown ecosystem,
    an alias equal to its canonical name, or one alias for two canonicals.
    """
    path = Path(path or DEFAULT_ALIASES).resolve()
    if path in _alias_cache:
        return _alias_cache[path]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise AliasFileError(f"{path}: cannot read alias file: {e}") from e

    table = AliasTable()
    for i, entry in enumerate(data.get("aliases", [])):
        where = f"{path.name} entry {i + 1}"
        eco = ecosystem_of(entry.get("ecosystem"))
        if eco is None or eco == "none":
            raise AliasFileError(f"{where}: unknown ecosystem {entry.get('ecosystem')!r}")
        canonical = str(entry.get("canonical") or "").strip()
        aliases = entry.get("aliases") or []
        if not canonical or not aliases:
            raise AliasFileError(f"{where}: needs a canonical name and at least one alias")
        confidence = float(entry.get("confidence", ALIAS_CONFIDENCE))
        if not 0 < confidence <= 1:
            raise AliasFileError(f"{where}: confidence must be in (0, 1]")

        ckey = normalized_name(canonical, eco)
        if ckey in table.to_canonical.get(eco, {}):
            raise AliasFileError(f"{where}: {canonical!r} is already an alias of another name")
        table.canonicals.setdefault(eco, {})[ckey] = canonical

        for alias in aliases:
            key = normalized_name(alias, eco)
            if key == ckey:
                raise AliasFileError(f"{where}: alias {alias!r} is the canonical name itself")
            if key in table.canonicals.get(eco, {}):
                raise AliasFileError(f"{where}: alias {alias!r} is itself a canonical name")
            existing = table.to_canonical.get(eco, {}).get(key)
            if existing is not None and existing != ckey:
                raise AliasFileError(
                    f"{where}: alias {alias!r} already belongs to "
                    f"{table.canonicals[eco][existing]!r}")
            table.to_canonical.setdefault(eco, {})[key] = ckey
            table.confidence[(eco, key)] = confidence
            table.notes[(eco, key)] = entry.get("note") or ""

    _alias_cache[path] = table
    return table


# ============================
# ONE PAIR
# ============================
def _rule_ecosystem(eco_a, eco_b):
    """Which ecosystem's naming rules apply: PyPI's if either side is PyPI."""
    if "pypi" in (eco_a, eco_b):
        return "pypi"
    if eco_a == eco_b:
        return eco_a
    return eco_a or eco_b


def _same(x, y, rule_eco):
    """Equal names under the rule ecosystem (PEP 503 for PyPI, else case-insensitive)."""
    if rule_eco == "pypi":
        return canonicalize_name(x) == canonicalize_name(y)
    return x.strip().casefold() == y.strip().casefold()


def _npm_scope(name):
    """("scope", "rest") for "@scope/rest", else None."""
    if name.startswith("@") and "/" in name:
        scope, rest = name[1:].split("/", 1)
        if scope and rest:
            return scope, rest
    return None


def _maven_parts(name):
    """("group", "artifact") for "group:artifact[:version]", else None."""
    parts = name.split(":")
    if len(parts) >= 2 and parts[0] and parts[1]:
        return parts[0], parts[1]
    return None


def _strip_lib(name):
    lowered = name.lower()
    if lowered.startswith("lib") and len(name) > 3:
        return name[3:].lstrip("-_")
    return None


def _layer(a, eco_a, b, eco_b, aliases):
    """(match_type, base confidence, reason) before the ecosystem penalty."""
    rule = _rule_ecosystem(eco_a, eco_b)
    notes = []

    # ---- exact ----
    if a == b:
        return EXACT, EXACT_CONFIDENCE, "identical name"

    # ---- normalized ----
    if rule == "pypi" and canonicalize_name(a) == canonicalize_name(b):
        return (NORMALIZED, NORMALIZED_CONFIDENCE,
                f"same PyPI project after PEP 503 normalization ({canonicalize_name(a)})")
    if a.casefold() == b.casefold():
        return NORMALIZED, NORMALIZED_CONFIDENCE, "same name ignoring case"
    if collapse(a) == collapse(b):
        why = ("npm treats these as different packages" if rule == "npm"
               else "separators may be significant outside PyPI")
        return (NORMALIZED, SEPARATORS_ONLY_CONFIDENCE,
                f"differs only in separators (- _ .); {why}")

    # ---- alias ----
    for eco in ([rule] if rule else aliases.ecosystems()):
        ka, kb = normalized_name(a, eco), normalized_name(b, eco)
        ca, cb = aliases.canonical(eco, ka), aliases.canonical(eco, kb)
        if ca is not None and ca == cb:
            alias_key = ka if ka != ca else kb
            display = aliases.canonicals[eco][ca]
            alias_name = a if alias_key == ka else b
            note = aliases.notes.get((eco, alias_key))
            return (ALIAS, aliases.confidence.get((eco, alias_key), ALIAS_CONFIDENCE),
                    f"{alias_name} is an alias of {display} ({eco}"
                    + (f", {note}" if note else "") + ", name_aliases.json)")

    # ---- scope / group stripping ----
    for x, y in ((a, b), (b, a)):
        scoped = _npm_scope(x)
        if scoped and not _npm_scope(y):
            scope, rest = scoped
            if _same(rest, y, rule):
                if scope.lower() == "types":
                    notes.append(f"{x} is the TypeScript type definitions for {y}, "
                                 "not the package itself (@types/ is never stripped)")
                else:
                    return (SCOPE_STRIPPED, SCOPE_CONFIDENCE,
                            f"same name after removing the npm scope @{scope}/ ({x} vs {y})")
        maven = _maven_parts(x)
        if maven and ":" not in y and _same(maven[1], y, rule):
            return (SCOPE_STRIPPED, SCOPE_CONFIDENCE,
                    f"same artifact after removing the Maven group {maven[0]}: ({x} vs {y})")

    # ---- prefix stripping ----
    for x, y in ((a, b), (b, a)):
        if x.lower().startswith("python-") and _same(x[len("python-"):], y, rule):
            return (PREFIX_STRIPPED, PYTHON_PREFIX_CONFIDENCE,
                    f"same name after removing the python- prefix ({x} vs {y}); "
                    "often a different project")
        rest = _strip_lib(x)
        if rest and _same(rest, y, rule):
            if len(rest) >= LIB_MIN_REST:
                return (PREFIX_STRIPPED, LIB_PREFIX_CONFIDENCE,
                        f"same name after removing the lib prefix ({x} vs {y}); "
                        "often a different project")
            notes.append(f"{x} minus lib is only {rest!r}: too short to strip")

    return NO_MATCH, 0.0, "no rule matched" + ("; " + "; ".join(notes) if notes else "")


def match_pair(name_a, eco_a, name_b, eco_b, aliases=None):
    """
    Is name_a (ecosystem eco_a) the same package as name_b (eco_b)?
    Returns {"match_type", "confidence", "reason"}.
    """
    aliases = aliases if aliases is not None else load_aliases()
    a, b = str(name_a or "").strip(), str(name_b or "").strip()
    ea, eb = ecosystem_of(eco_a), ecosystem_of(eco_b)

    match_type, confidence, reason = _layer(a, ea, b, eb, aliases)

    if match_type != NO_MATCH:
        if ea and eb and ea != eb:
            confidence = max(confidence - ECOSYSTEM_PENALTY, 0.0)
            reason += f"; ecosystem differs ({ea} vs {eb}): -{ECOSYSTEM_PENALTY:.2f}"
        elif not ea or not eb:
            reason += "; ecosystem unknown (no penalty)"

    return {
        "match_type": match_type,
        "confidence": round(confidence, 4),
        "reason": reason,
    }


# ============================
# BEST OF MANY CANDIDATES
# ============================
class CandidateIndex:
    """
    Known names, indexed by every key a match can share (loose form, stripped
    forms, alias canonical), so best_match() only scores likely candidates.
    """

    def __init__(self, candidates, aliases=None):
        self.aliases = aliases if aliases is not None else load_aliases()
        self.candidates = sorted({(str(n).strip(), ecosystem_of(e) or e)
                                  for n, e in candidates if str(n or "").strip()})
        self._by_key = {}
        for cand in self.candidates:
            for key in self.keys(cand[0]):
                self._by_key.setdefault(key, set()).add(cand)

    def keys(self, name):
        keys = {collapse(name)}
        scoped = _npm_scope(name)
        if scoped:
            keys.add(collapse(scoped[1]))
        maven = _maven_parts(name)
        if maven:
            keys.add(collapse(maven[1]))
        if name.lower().startswith("python-"):
            keys.add(collapse(name[len("python-"):]))
        rest = _strip_lib(name)
        if rest:
            keys.add(collapse(rest))
        for eco in self.aliases.ecosystems():
            canonical = self.aliases.canonical(eco, normalized_name(name, eco))
            if canonical is not None:
                keys.add(f"alias:{eco}:{canonical}")
        return keys

    def lookup(self, name):
        found = set()
        for key in self.keys(str(name or "").strip()):
            found |= self._by_key.get(key, set())
        return sorted(found)

    def __len__(self):
        return len(self.candidates)


def best_match(name, ecosystem, index, candidates=None):
    """
    Best known name for one package. Returns match_pair()'s keys plus
    matched_name, match_ecosystem, match_status and candidates_considered.
    candidates: score these instead of index.lookup() (for tests).
    """
    eco = ecosystem_of(ecosystem)
    pool = index.lookup(name) if candidates is None else candidates

    scored = []
    for cand_name, cand_eco in pool:
        result = match_pair(name, ecosystem, cand_name, cand_eco, index.aliases)
        if result["match_type"] != NO_MATCH:
            scored.append((result, cand_name, cand_eco))

    if not scored:
        return {
            "match_type": NO_MATCH,
            "confidence": 0.0,
            "reason": "no known name matched" if len(index) else "no candidate names given",
            "matched_name": None,
            "match_ecosystem": None,
            "match_status": UNMATCHED,
            "candidates_considered": len(pool),
        }

    scored.sort(key=lambda s: (-s[0]["confidence"],
                               0 if s[2] == eco else 1,
                               s[1].lower(), str(s[2])))
    result, cand_name, cand_eco = scored[0]
    status = status_for(result["confidence"])
    reason = result["reason"]

    # Another candidate with the same top confidence makes the answer
    # ambiguous, unless the tie was broken by "same ecosystem as the package"
    ties = [s for s in scored[1:]
            if s[0]["confidence"] == result["confidence"]
            and (s[1], s[2]) != (cand_name, cand_eco)
            and not (cand_eco == eco and s[2] != eco)]
    if ties:
        other = ties[0]
        reason += f"; ambiguous: {other[1]} ({other[2]}) scores the same"
        if status == MATCHED:
            status = REVIEW

    return {
        **result,
        "reason": reason,
        "matched_name": cand_name,
        "match_ecosystem": cand_eco,
        "match_status": status,
        "candidates_considered": len(pool),
    }


# ============================
# CANDIDATE FILES
# ============================
def load_candidates(path):
    """
    Known (name, ecosystem) pairs from a release cache (.json, keys
    "ecosystem:name"; null entries, i.e. not found, are skipped) or a CSV
    with name and ecosystem columns.
    Raises FileNotFoundError / ValueError.
    """
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"candidates file not found: {path}")

    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        pairs = []
        for key, entry in data.items():
            # The release cache stores null for "not on this registry":
            # those keys are lookups that failed, not known names
            if entry is None:
                continue
            eco, sep, name = str(key).partition(":")
            if sep and name:
                pairs.append((name, eco))
        return pairs

    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or "name" not in reader.fieldnames:
            raise ValueError(f"{path}: CSV needs a 'name' column (and 'ecosystem')")
        return [(r["name"], r.get("ecosystem")) for r in reader if (r.get("name") or "").strip()]


# ============================
# CLI
# ============================
def match_packages(rows, index):
    """One result per packages row (package_id, package_name, ecosystem)."""
    results = []
    for row in rows:
        best = best_match(row["package_name"], row["ecosystem"], index)
        results.append({
            "package_id": row["package_id"],
            "package_name": row["package_name"],
            "ecosystem": row["ecosystem"],
            "normalized_name": normalized_name(row["package_name"], row["ecosystem"]),
            **best,
        })
    return results


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Fill packages match columns by rule-based name matching (preview by default)."
    )
    parser.add_argument("--candidates", default=str(DEFAULT_CANDIDATES),
                        help="known names: a release cache .json or a name,ecosystem CSV")
    parser.add_argument("--aliases", default=str(DEFAULT_ALIASES), help="alias JSON file")
    parser.add_argument("--ecosystem", help="only match packages of this ecosystem")
    parser.add_argument("--examples", type=int, default=10, help="examples per match type")
    parser.add_argument("--out", help="write every result, with its reason, to this CSV")
    parser.add_argument("--apply", action="store_true",
                        help="Actually write the match columns. Without this flag only a preview is shown.")
    args = parser.parse_args(argv)

    try:
        aliases = load_aliases(args.aliases)
        candidates = load_candidates(args.candidates)
    except (OSError, ValueError) as e:
        print(f"Error: {e}")
        return 2

    from db_storage import get_db_storage
    db = get_db_storage()

    rows = db.package_match_rows()
    if args.ecosystem:
        wanted = ecosystem_of(args.ecosystem) or args.ecosystem
        rows = [r for r in rows if (ecosystem_of(r["ecosystem"]) or r["ecosystem"]) == wanted]

    index = CandidateIndex(candidates, aliases)
    results = match_packages(rows, index)

    print(f"{len(rows)} packages, {len(index)} known names "
          f"({dict(Counter(e for _, e in index.candidates))})")

    types = Counter(r["match_type"] for r in results)
    statuses = Counter(r["match_status"] for r in results)
    print("\nBy match type:")
    for t in MATCH_TYPES:
        print(f"  {t:<16} {types.get(t, 0)}")
    print("By status:")
    for s in MATCH_STATUSES:
        print(f"  {s:<16} {statuses.get(s, 0)}")
    print(f"Ambiguous (two different names score the same): "
          f"{sum('ambiguous' in r['reason'] for r in results)}")
    print("Status by package ecosystem: " + ", ".join(
        f"{eco}: {dict(Counter(r['match_status'] for r in results if r['ecosystem'] == eco))}"
        for eco in sorted({str(r['ecosystem']) for r in results})))

    for t in MATCH_TYPES:
        shown = [r for r in results if r["match_type"] == t][:args.examples]
        if not shown:
            continue
        print(f"\nExamples: {t}")
        for r in shown:
            target = (f"{r['matched_name']} ({r['match_ecosystem']})"
                      if r["matched_name"] else "-")
            print(f"  {r['package_name']} ({r['ecosystem']}) -> {target}: "
                  f"{r['confidence']:.2f} {r['match_status']} | {r['reason']}")

    if args.out:
        fields = ["package_id", "package_name", "ecosystem", "normalized_name",
                  "matched_name", "match_ecosystem", "match_type", "confidence",
                  "match_status", "reason", "candidates_considered"]
        with open(args.out, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(results)
        print(f"\nWrote {len(results)} results to {args.out}")

    if not args.apply:
        print("\nPreview only. Nothing was changed. Re-run with --apply to write.")
        return 0

    written = db.update_package_matches(results)
    print(f"\nWrote match columns for {written} packages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
