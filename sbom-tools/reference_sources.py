# sbom-tools/reference_sources.py
#
# Readers for external reference data, read from local files only (you
# download them; nothing here touches the network). All readers stream, so
# the multi-million-row package lists are never loaded at once.
#
#   Package-List CSVs  (oraoraoraaa/Package-List-Miner, "Package-List-20260117"
#                       on Google Drive): one CSV per ecosystem with columns
#                       ID, Platform, Name, Homepage URL, Repository URL.
#                       Platform is PyPI / NPM / Maven; Maven names are
#                       groupId:artifactId; a missing URL is the string "nan".
#   purl2cpe.db.zip    (scanoss/purl2cpe): SQLite table
#                       purl2cpe(purl TEXT, cpe TEXT), every PURL of a product
#                       paired with every CPE (version) of that product.

import csv
import re
import sqlite3
import tempfile
import zipfile
from collections import Counter, namedtuple
from pathlib import Path
from urllib.parse import unquote

# Ecosystems the reference list covers, and their Package-List Platform names
TARGET_ECOSYSTEMS = ("pypi", "npm", "maven")
PLATFORMS = {"pypi": "pypi", "npm": "npm", "maven": "maven"}

PACKAGE_LIST_COLUMNS = ("Platform", "Name", "Repository URL")

# PURL types that are registries we match against; others (deb, docker,
# nuget...) are kept as their own type name
PURL_ECOSYSTEMS = {"pypi": "pypi", "npm": "npm", "maven": "maven", "github": "github"}

MISSING = {"", "nan", "none", "null", "n/a"}


def clean(value):
    """Stripped text, or None for empty / "nan" / "None"."""
    text = str(value).strip() if value is not None else ""
    return None if text.lower() in MISSING else text


# ============================
# REPOSITORY URLS
# ============================
GITHUB_REPO = re.compile(r"github\.com[/:]+([^/\s#?]+)/([^/\s#?]+)", re.IGNORECASE)


def normalize_repo_url(url):
    """
    "github.com/owner/repo" (lowercase, no .git / slash / scheme), or None for
    a missing or non-GitHub URL. The same rule the cross-ecosystem study uses
    to decide that two packages come from one repository.
    """
    text = clean(url)
    if not text:
        return None
    m = GITHUB_REPO.search(text)
    if not m:
        return None
    owner, repo = m.group(1).lower(), m.group(2).lower()
    repo = re.sub(r"\.git$", "", repo).rstrip(".")
    if not owner or not repo:
        return None
    return f"github.com/{owner}/{repo}"


# ============================
# PACKAGE-LIST CSVs
# ============================
def read_package_list_csv(path, ecosystems=TARGET_ECOSYSTEMS):
    """
    Yield (name, ecosystem, repository_url) for every row of one Package-List
    CSV whose Platform is one of ecosystems. Raises ValueError when the file
    lacks the expected columns.
    """
    with open(path, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        missing = [c for c in PACKAGE_LIST_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{path}: not a Package-List CSV (missing columns {missing})")
        for row in reader:
            eco = PLATFORMS.get(str(row.get("Platform") or "").strip().lower())
            name = clean(row.get("Name"))
            if eco is None or eco not in ecosystems or not name:
                continue
            yield name, eco, clean(row.get("Repository URL"))


def package_list_files(folder):
    """The *.csv files of a Package-List folder, sorted by name."""
    folder = Path(folder)
    if not folder.is_dir():
        raise FileNotFoundError(f"Package-List folder not found: {folder}")
    return sorted(p for p in folder.glob("*.csv") if p.is_file())


def iter_package_lists(folder, ecosystems=TARGET_ECOSYSTEMS):
    """(name, ecosystem, repository_url) from every CSV in the folder."""
    for path in package_list_files(folder):
        yield from read_package_list_csv(path, ecosystems)


# ============================
# PURL / CPE
# ============================
Purl = namedtuple("Purl", "type namespace name version")
Cpe = namedtuple("Cpe", "part vendor product version")


def parse_purl(purl):
    """
    Purl(type, namespace, name, version) from "pkg:type/namespace/name@version
    ?qualifiers#subpath" (namespace and version may be None). Percent-escapes
    are decoded (npm "%40scope" -> "@scope"). Raises ValueError otherwise.
    """
    text = str(purl or "").strip()
    if not text.lower().startswith("pkg:"):
        raise ValueError(f"not a PURL: {purl!r}")
    body = text[4:].split("#", 1)[0].split("?", 1)[0].strip("/")
    ptype, _, rest = body.partition("/")
    segments = [s for s in rest.split("/") if s]
    if not ptype or not segments:
        raise ValueError(f"PURL without a name: {purl!r}")

    last = segments[-1]
    version = None
    if "@" in last:
        last, version = last.rsplit("@", 1)
        version = unquote(version) or None
    name = unquote(last)
    if not name:
        raise ValueError(f"PURL without a name: {purl!r}")
    namespace = "/".join(unquote(s) for s in segments[:-1]) or None
    return Purl(ptype.lower(), namespace, name, version)


def purl_ecosystem(ptype):
    """Our ecosystem name for a PURL type (pypi/npm/maven/github), else the type."""
    return PURL_ECOSYSTEMS.get(str(ptype).lower(), str(ptype).lower())


def purl_package_name(p):
    """
    The package's name as its registry writes it: npm "@scope/name",
    Maven "group:artifact", GitHub "owner/repo", PyPI "name".
    """
    if p.type == "maven" and p.namespace:
        return f"{p.namespace}:{p.name}"
    if p.type in ("npm", "github") and p.namespace:
        return f"{p.namespace}/{p.name}"
    return p.name


def parse_cpe(cpe):
    """Cpe(part, vendor, product, version) from a CPE 2.3 string. Raises ValueError."""
    text = str(cpe or "").strip()
    # Split on ":" not preceded by a backslash (CPE escapes ":" as "\:")
    fields = re.split(r"(?<!\\):", text)
    if len(fields) < 6 or fields[0] != "cpe" or fields[1] != "2.3":
        raise ValueError(f"not a CPE 2.3 string: {cpe!r}")

    def unescape(s):
        return re.sub(r"\\(.)", r"\1", s)

    return Cpe(fields[2], unescape(fields[3]), unescape(fields[4]), unescape(fields[5]))


class Purl2Cpe:
    """
    What purl2cpe.db holds, reduced to what matching needs:
      products            {(vendor, product): set of base PURLs (no version)}
      relations_by_type   Counter of (purl, cpe) rows per PURL type
      purls_by_type       Counter of distinct base PURLs per PURL type
      bad_rows            rows whose PURL or CPE could not be parsed
    """

    def __init__(self):
        self.products = {}
        self.relations_by_type = Counter()
        self.purls_by_type = Counter()
        self.bad_rows = 0

    def add(self, purl, cpe):
        try:
            p = parse_purl(purl)
            c = parse_cpe(cpe)
        except ValueError:
            self.bad_rows += 1
            return
        self.relations_by_type[p.type] += 1
        base = f"pkg:{p.type}/" + (f"{p.namespace}/" if p.namespace else "") + p.name
        self.products.setdefault((c.vendor, c.product), set()).add(base)

    def finish(self):
        distinct = set()
        for purls in self.products.values():
            distinct |= purls
        for base in distinct:
            self.purls_by_type[parse_purl(base).type] += 1
        return self


def read_purl2cpe(zip_path):
    """
    Read purl2cpe.db from purl2cpe.db.zip (extracted to a temporary folder,
    opened read-only). Returns a Purl2Cpe. Raises FileNotFoundError /
    ValueError for a missing file or a zip without a .db inside.
    """
    zip_path = Path(zip_path)
    if not zip_path.is_file():
        raise FileNotFoundError(f"purl2cpe zip not found: {zip_path}")

    data = Purl2Cpe()
    with zipfile.ZipFile(zip_path) as zf, tempfile.TemporaryDirectory() as tmp:
        members = [m for m in zf.namelist() if m.lower().endswith(".db")]
        if not members:
            raise ValueError(f"{zip_path}: no .db file inside")
        db_path = zf.extract(members[0], tmp)
        conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
        try:
            for purl, cpe in conn.execute("SELECT purl, cpe FROM purl2cpe"):
                data.add(purl, cpe)
        finally:
            conn.close()
    return data.finish()
