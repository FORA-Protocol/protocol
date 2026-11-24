"""Tests for npm_installed.py, run through its command line.

Each test copies the script into a throwaway repository, writes a package directory
with a lockfile and the hidden lockfile npm records in node_modules, in the shape
`npm ci` writes them, and runs the script on it.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

from ratchet_harness import GateRepo

if TYPE_CHECKING:
    import subprocess

LOCKED: dict[str, dict[str, object]] = {
    "": {"name": "pkg"},
    "node_modules/typescript": {"version": "6.0.3", "dev": True},
    "node_modules/@biomejs/cli-linux-x64": {
        "version": "2.4.12",
        "dev": True,
        "optional": True,
    },
    "node_modules/@biomejs/cli-darwin-arm64": {
        "version": "2.4.12",
        "dev": True,
        "optional": True,
    },
}


class NpmInstalledTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = GateRepo(Path(tmp))
        self.repo.copy("npm_installed.py")
        self.pkg = Path(tmp) / "pkg"
        (self.pkg / "node_modules").mkdir(parents=True)
        (self.pkg / "package-lock.json").write_text(json.dumps({"packages": LOCKED}))

    def install(self, packages: dict[str, dict[str, object]]) -> None:
        """Write npm's record of `packages`, and each one's package.json, as npm ci does."""
        hidden = self.pkg / "node_modules" / ".package-lock.json"
        hidden.write_text(json.dumps({"packages": packages}))
        for name, entry in packages.items():
            self.write_manifest(name, str(entry["version"]))

    def write_manifest(self, name: str, version: str) -> None:
        manifest = self.pkg / name / "package.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(
            json.dumps({"name": name.rsplit("node_modules/", 1)[-1], "version": version})
        )

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return self.repo.script("npm_installed.py", "pkg")

    def test_passes_when_the_install_matches_without_other_platforms_binaries(
        self,
    ) -> None:
        self.install({k: v for k, v in LOCKED.items() if k and "linux" not in k})
        proc = self.run_check()
        self.assertEqual(proc.returncode, 0, proc.stdout)

    def test_fails_on_a_version_the_lockfile_does_not_pin(self) -> None:
        self.install({"node_modules/typescript": {"version": "6.0.2"}})
        proc = self.run_check()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("node_modules/typescript is 6.0.2, the lockfile pins 6.0.3", proc.stdout)
        # The caller prints the one install command for every directory.
        self.assertNotIn("npm ci", proc.stdout)

    def test_fails_on_a_package_the_lockfile_does_not_hold(self) -> None:
        self.install(
            {
                "node_modules/typescript": {"version": "6.0.3"},
                "node_modules/zod": {"version": "4.4.3"},
            }
        )
        proc = self.run_check()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("node_modules/zod 4.4.3 is installed but not in the lockfile", proc.stdout)

    def test_fails_when_a_required_package_is_missing(self) -> None:
        self.install({})
        proc = self.run_check()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("node_modules/typescript 6.0.3 is not installed", proc.stdout)
        self.assertNotIn("cli-linux-x64", proc.stdout)

    def test_fails_on_an_installed_package_json_edited_after_install(self) -> None:
        self.install({k: v for k, v in LOCKED.items() if k and "linux" not in k})
        self.write_manifest("node_modules/typescript", "3.0.0")
        proc = self.run_check()
        self.assertEqual(proc.returncode, 1)
        self.assertIn(
            "node_modules/typescript/package.json says 3.0.0, the lockfile pins 6.0.3",
            proc.stdout,
        )

    def test_fails_on_an_installed_package_with_no_package_json(self) -> None:
        self.install({k: v for k, v in LOCKED.items() if k and "linux" not in k})
        (self.pkg / "node_modules" / "typescript" / "package.json").unlink()
        proc = self.run_check()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("node_modules/typescript has no package.json", proc.stdout)

    def test_fails_when_nothing_is_installed(self) -> None:
        proc = self.run_check()
        self.assertEqual(proc.returncode, 1)
        self.assertIn("node_modules is not installed", proc.stdout)


if __name__ == "__main__":
    unittest.main()
