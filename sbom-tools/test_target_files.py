# sbom-tools/test_target_files.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# No network or database access; files are created in a temp folder.

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from target_files import (
    PROJECT_ROOT,
    TARGET_FILE_DIRS,
    resolve_target_file,
    safe_upload_name,
    save_upload,
)


class TestResolveTargetFile(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.uploads = self.root / "uploaded_sboms"
        self.dataset = self.root / "dataset"
        self.uploads.mkdir()
        self.dataset.mkdir()
        self.dirs = [self.uploads, self.dataset, self.root]

    def make(self, folder, name):
        path = folder / name
        path.write_text("package_name,current_version\nrequests,2.0.0\n")
        return path.resolve()

    def test_bare_name_found_in_uploaded_sboms(self):
        """Bare name "sbom_dataset_mixed.csv" is found in uploaded_sboms/"""
        expected = self.make(self.uploads, "sbom_dataset_mixed.csv")
        self.assertEqual(resolve_target_file("sbom_dataset_mixed.csv", self.dirs), expected)

    def test_bare_name_found_in_dataset(self):
        """Bare name "sbom_dataset_pypi.csv" is found in dataset/"""
        expected = self.make(self.dataset, "sbom_dataset_pypi.csv")
        self.assertEqual(resolve_target_file("sbom_dataset_pypi.csv", self.dirs), expected)

    def test_uploaded_sboms_wins_over_dataset(self):
        """uploaded_sboms/ is searched before dataset/"""
        expected = self.make(self.uploads, "same.csv")
        self.make(self.dataset, "same.csv")
        self.assertEqual(resolve_target_file("same.csv", self.dirs), expected)

    def test_independent_of_working_directory(self):
        """Same result whatever folder the app is started from"""
        expected = self.make(self.uploads, "sbom.json")
        start = os.getcwd()
        self.addCleanup(os.chdir, start)
        for cwd in (self.root, self.dataset, Path(tempfile.gettempdir())):
            os.chdir(cwd)
            self.assertEqual(resolve_target_file("sbom.json", self.dirs), expected)

    def test_absolute_path_used_as_is(self):
        """An absolute path stored in the DB is used directly"""
        other = self.root / "elsewhere"
        other.mkdir()
        expected = self.make(other, "abs.csv")
        self.assertEqual(resolve_target_file(str(expected), self.dirs), expected)

    def test_missing_file_error_names_full_paths(self):
        """Missing file: error lists every full path that was checked"""
        with self.assertRaises(FileNotFoundError) as ctx:
            resolve_target_file("sbom_dataset_mixed.csv", self.dirs)
        message = str(ctx.exception)
        self.assertIn("sbom_dataset_mixed.csv", message)
        for d in self.dirs:
            self.assertIn(str(d / "sbom_dataset_mixed.csv"), message)

    def test_relative_path_cannot_escape_project_folders(self):
        """"../secret.csv" is looked up as "secret.csv" inside the folders"""
        self.make(self.uploads, "secret.csv")
        found = resolve_target_file("../secret.csv", self.dirs)
        self.assertEqual(found.parent, self.uploads.resolve())

    def test_default_dirs_are_inside_project(self):
        """Default search folders: uploaded_sboms/, dataset/, project root"""
        self.assertEqual(
            TARGET_FILE_DIRS,
            [PROJECT_ROOT / "uploaded_sboms", PROJECT_ROOT / "dataset", PROJECT_ROOT],
        )
        self.assertTrue((PROJECT_ROOT / "ui_app.py").is_file())


class TestSafeUploadName(unittest.TestCase):

    def test_names(self):
        """Unsafe names are cleaned; extension kept and lower-cased"""
        cases = {
            "sbom_dataset_mixed.csv": "sbom_dataset_mixed.csv",
            "My SBOM (1).CSV": "My_SBOM_1.csv",
            "../../etc/passwd.csv": "passwd.csv",
            r"C:\Users\me\Downloads\sbom.json": "sbom.json",
            "漢字.csv": "upload.csv",
        }
        for original, expected in cases.items():
            with self.subTest(original=original):
                self.assertEqual(safe_upload_name(original), expected)

    def test_other_extensions_rejected(self):
        """Only .csv and .json are accepted"""
        for bad in ("evil.exe", "sbom.csv.exe", "noext", ""):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                safe_upload_name(bad)


class TestSaveUpload(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.uploads = Path(tmp.name) / "uploaded_sboms"   # created on first save

    def test_new_file_saved_and_found_by_rescan_lookup(self):
        """New upload is saved; stored name resolves to that exact file"""
        data = b"package_name,current_version\nrequests,2.0.0\n"
        name, renamed = save_upload(data, "My SBOM.CSV", self.uploads)

        self.assertEqual((name, renamed), ("My_SBOM.csv", False))
        found = resolve_target_file(name, [self.uploads])
        self.assertEqual(found, (self.uploads / "My_SBOM.csv").resolve())
        self.assertEqual(found.read_bytes(), data)

    def test_same_file_uploaded_again_is_reused(self):
        """Re-uploading identical contents reuses the file (no _1 copy)"""
        data = b"a,b\n1,2\n"
        save_upload(data, "sbom.csv", self.uploads)
        name, renamed = save_upload(data, "sbom.csv", self.uploads)

        self.assertEqual((name, renamed), ("sbom.csv", False))
        self.assertEqual(sorted(p.name for p in self.uploads.iterdir()), ["sbom.csv"])

    def test_different_file_same_name_not_overwritten(self):
        """Different contents, same name -> saved as sbom_1.csv, original untouched"""
        save_upload(b"first\n", "sbom.csv", self.uploads)
        name, renamed = save_upload(b"second\n", "sbom.csv", self.uploads)

        self.assertEqual((name, renamed), ("sbom_1.csv", True))
        self.assertEqual((self.uploads / "sbom.csv").read_bytes(), b"first\n")
        self.assertEqual((self.uploads / "sbom_1.csv").read_bytes(), b"second\n")

    def test_third_different_file_gets_next_suffix(self):
        """Third different file -> sbom_2.csv; re-upload of #2 -> sbom_1.csv"""
        save_upload(b"one\n", "sbom.csv", self.uploads)
        save_upload(b"two\n", "sbom.csv", self.uploads)
        self.assertEqual(save_upload(b"three\n", "sbom.csv", self.uploads), ("sbom_2.csv", True))
        self.assertEqual(save_upload(b"two\n", "sbom.csv", self.uploads), ("sbom_1.csv", True))

    def test_path_in_name_stays_inside_upload_folder(self):
        """"../../x.json" is saved inside uploaded_sboms/ as x.json"""
        name, _ = save_upload(b"{}", "../../x.json", self.uploads)
        self.assertEqual(name, "x.json")
        self.assertTrue((self.uploads / "x.json").is_file())
        self.assertFalse((self.uploads.parent / "x.json").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
