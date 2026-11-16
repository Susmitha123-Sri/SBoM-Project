# sbom-tools/test_sbom_update_repo.py
#
# Run all tests from the project root:
#   python -m unittest discover -v -s sbom-tools -p "test_*.py"
#
# SBOMScanner._update_repo never runs git fetch / reset / pull in a folder
# that is not its own repository: with no .git (or a broken one, where
# git rev-parse --show-toplevel names the parent project) git -C would walk
# up and reset the project repository. Such a cache folder is deleted (only
# inside repo-cache) and re-cloned instead. NO real git runs here:
# subprocess.run and _clone_repo are mocks.

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS_DIR)

import sbom                                          # noqa: E402

URL = "https://github.com/owner/repo.git"


class UpdateRepoTestCase(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.cache_dir = self.dir / "repo-cache"
        self.cache = self.cache_dir / "owner-repo"
        self.cache.mkdir(parents=True)
        (self.cache / "README.md").write_text("partial clone", encoding="utf-8")

        self.git_calls = []
        self.toplevel = None                   # what rev-parse --show-toplevel prints
        self.clones = []

        def fake_run(cmd, *args, **kwargs):
            self.git_calls.append([str(c) for c in cmd])
            out = str(self.toplevel) + "\n" if "rev-parse" in cmd else ""
            return SimpleNamespace(returncode=0, stdout=out, stderr="")

        def fake_clone(scanner, repo_url, destination):
            self.clones.append((repo_url, Path(destination)))
            Path(destination).mkdir(parents=True)

        for patcher in (
            mock.patch.object(sbom.Config, "REPO_CACHE_DIR", self.cache_dir),
            mock.patch.object(sbom.subprocess, "run", fake_run),
            mock.patch.object(sbom.SBOMScanner, "_clone_repo", fake_clone),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

        self.scanner = sbom.SBOMScanner.__new__(sbom.SBOMScanner)   # no Syft / Grype checks
        self.scanner.git_command = ["git"]
        self.scanner.use_cache = True
        self.scanner.shallow_clone = True

    def git_verbs(self):
        return [c[3] for c in self.git_calls]     # git -C <path> <verb> ...

    def prepare(self):
        with mock.patch("builtins.print"):
            return self.scanner._clone_and_scan_github("owner", "repo")


class TestUpdateRepo(UpdateRepoTestCase):

    def test_folder_without_git_is_recloned_without_any_git_command(self):
        path, name, cleanup = self.prepare()
        self.assertEqual(self.git_calls, [])                    # no fetch, reset or rev-parse
        self.assertEqual(self.clones, [(URL, self.cache)])
        self.assertFalse((self.cache / "README.md").exists())   # old folder removed first
        self.assertEqual((path, name, cleanup), (str(self.cache), "owner/repo", False))

    def test_broken_git_folder_is_recloned(self):
        (self.cache / ".git").mkdir()                           # left by a failed clone
        self.toplevel = self.dir                                # git walked up to the parent
        self.prepare()
        self.assertEqual(self.git_verbs(), ["rev-parse"])       # never fetch / reset
        self.assertEqual(self.clones, [(URL, self.cache)])
        self.assertFalse((self.cache / "README.md").exists())

    def test_folder_outside_repo_cache_is_never_deleted(self):
        outside = self.dir / "project"
        outside.mkdir()
        with self.assertRaises(ValueError):
            self.scanner._update_repo(outside)
        self.assertTrue(outside.exists())
        self.assertEqual(self.git_calls, [])

    def test_own_repository_is_updated_as_before(self):
        (self.cache / ".git").mkdir()
        self.toplevel = self.cache.as_posix()                   # git prints C:/... style paths
        self.prepare()
        self.assertEqual(self.git_verbs(), ["rev-parse", "fetch", "reset"])
        self.assertEqual(self.clones, [])
        self.assertTrue((self.cache / "README.md").exists())


if __name__ == "__main__":
    unittest.main()
