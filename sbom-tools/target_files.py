# sbom-tools/target_files.py
#
# Find the file behind a CSV/JSON scan target (scan.target_name).
#
# /upload-sbom stores only the uploaded file's bare name (e.g.
# "sbom_dataset_mixed.csv"), so opening that name directly depends on
# whichever folder the app was started from. These helpers look in the
# project's own folders instead, so it works from any working directory.

from pathlib import Path

from werkzeug.utils import secure_filename

PROJECT_ROOT = Path(__file__).resolve().parent.parent
UPLOAD_DIR = PROJECT_ROOT / "uploaded_sboms"
UPLOAD_EXTENSIONS = (".csv", ".json")

# Searched in this order
TARGET_FILE_DIRS = [
    UPLOAD_DIR,
    PROJECT_ROOT / "dataset",
    PROJECT_ROOT,
]


def candidate_paths(target, search_dirs=None):
    """Full paths checked for this target, in order."""
    target_path = Path(str(target).strip())

    # An absolute path stored in the DB is used as-is
    if target_path.is_absolute():
        return [target_path]

    # Relative names are looked up by file name only, so a stored name
    # like "../x.csv" can't point outside the project folders
    name = target_path.name
    dirs = TARGET_FILE_DIRS if search_dirs is None else search_dirs
    return [Path(d) / name for d in dirs]


def resolve_target_file(target, search_dirs=None):
    """
    Return the full Path of the target's file.

    Raises FileNotFoundError naming every full path that was checked.
    """
    tried = candidate_paths(target, search_dirs)

    for path in tried:
        if path.is_file():
            return path.resolve()

    raise FileNotFoundError(
        f"File for target '{target}' not found. Looked in: "
        + ", ".join(str(p) for p in tried)
    )


def safe_upload_name(original_name):
    """
    Safe file name for an upload: secure_filename() on the name part, with a
    lower-case .csv/.json extension (the rescan matches those exactly).
    "My SBOM (1).CSV" -> "My_SBOM_1.csv"; a name with nothing safe left
    becomes "upload.csv". Raises ValueError for other extensions.
    """
    original = Path(str(original_name or "").replace("\\", "/"))
    ext = original.suffix.lower()
    if ext not in UPLOAD_EXTENSIONS:
        raise ValueError(f"Unsupported upload type: {original_name!r}")

    stem = secure_filename(original.stem) or "upload"
    return stem + ext


def save_upload(data, original_name, upload_dir=None):
    """
    Save uploaded bytes into uploaded_sboms/ without overwriting anything.

    Returns (saved_name, renamed):
      - name free                 -> saved under the safe name, renamed=False
      - same name, same contents  -> existing file reused,      renamed=False
      - same name, different file -> saved as name_1.csv, name_2.csv, ...,
                                     renamed=True (caller must tell the user)
    saved_name is the bare file name, which is what gets stored as the
    scan's target_name so resolve_target_file() finds this exact file.
    """
    folder = Path(upload_dir) if upload_dir is not None else UPLOAD_DIR
    folder.mkdir(parents=True, exist_ok=True)

    name = safe_upload_name(original_name)
    stem, ext = Path(name).stem, Path(name).suffix

    n = 0
    while True:
        candidate = name if n == 0 else f"{stem}_{n}{ext}"
        path = folder / candidate
        try:
            # "x" = create only; never replaces a file, even if two uploads race
            with open(path, "xb") as f:
                f.write(data)
            return candidate, n > 0
        except FileExistsError:
            if path.read_bytes() == data:
                return candidate, n > 0
            n += 1
