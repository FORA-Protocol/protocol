"""Tests that run the Go and Python API comparisons with the real apidiff and griffe.

Each test builds a throwaway repository with a release tag and a change after it,
and runs the comparison the way its gate does. The Go tests run gate-api-go.sh
itself, which checks the pinned apidiff and golangci-lint on PATH as every Go gate
does. The Python tests run `api_diff.py python`, the command gate-api-python.sh
runs, with this checkout's sdk/python/.venv linked in: the gate script first
checks that environment against the SDK's lock, which the throwaway repository
does not hold.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from api_harness import ApiTestCase, api_diff_with, changelog
from ratchet_harness import GATES

if TYPE_CHECKING:
    import subprocess

MODULE = "github.com/FORA-Protocol/protocol"
REMOVED = "./sdk/go/core.Removed"
HELPERS = f"{MODULE}/sdk/go/helpers"
GO_MOD = "module {module}\n\ngo 1.26\n"
CORE_AT_TAG = "package core\n\n// Removed is removed after the release.\nfunc Removed() {}\n"
CORE_NOW = "package core\n\n// Kept stays.\nfunc Kept() {}\n"


class ApiCompareTestCase(ApiTestCase):
    def copy_api_diff(self, constant: str, value: str) -> None:
        """Replace the copy of api_diff.py with one whose `constant` is `value`."""
        self.repo.write("scripts/gates/api_diff.py", api_diff_with(constant, value))

    def tag(self, files: dict[str, str]) -> None:
        """Commit `files` as the release v1.2.1."""
        for path, text in files.items():
            self.repo.write(path, text)
        self.repo.commit("the release")
        self.repo.git("tag", "v1.2.1")


class GoCompareTest(ApiCompareTestCase):
    """gate-api-go.sh, with and without a major release that moves the module path."""

    def setUp(self) -> None:
        super().setUp()
        self.repo.copy("gate-api-go.sh", "go-tools.sh", "tool-helper.sh")
        self.repo.write("scripts/gates/baselines/api-go.json", '{\n  "findings": []\n}\n')
        self.tag(
            {
                "go.mod": GO_MOD.format(module=MODULE),
                "sdk/go/core/core.go": CORE_AT_TAG + CORE_NOW.removeprefix("package core\n"),
                "sdk/go/helpers/helpers.go": "package helpers\n\n// H is removed.\nfunc H() {}\n",
            }
        )
        self.repo.git("rm", "-q", "-r", "sdk/go/helpers")
        self.repo.write("sdk/go/core/core.go", CORE_NOW)

    def gate(self, module: str, *listed: str) -> subprocess.CompletedProcess[str]:
        """Release 2.0.0 with go.mod declaring `module`, `listed` under Breaking; run the gate."""
        self.repo.write("go.mod", GO_MOD.format(module=module))
        self.release("2.0.0", None, changelog(("Unreleased", "Breaking", list(listed))))
        self.proc = self.repo.run_command(["scripts/gates/gate-api-go.sh"])
        return self.proc

    def test_a_major_release_that_moves_the_module_path_passes_with_its_removals_listed(
        self,
    ) -> None:
        proc = self.gate(f"{MODULE}/v2", REMOVED, HELPERS)
        self.assert_passes(proc)
        self.assertIn(f"api: {REMOVED} is listed under Breaking", proc.stderr)
        self.assertIn(f"api: {HELPERS} is listed under Breaking", proc.stderr)

    def test_a_removed_package_the_major_release_does_not_list_fails_in_its_directory(
        self,
    ) -> None:
        self.gate(f"{MODULE}/v2", REMOVED)
        self.assert_reported(HELPERS)
        self.assertIn(f"  sdk/go/helpers: [incompatible] {HELPERS}: removed", self.proc.stdout)

    def test_a_release_on_the_same_module_path_reports_each_unlisted_removal(self) -> None:
        self.gate(MODULE, HELPERS)
        self.assert_reported(REMOVED)
        self.assertIn(f"  sdk/go/core: [incompatible] {REMOVED}: removed", self.proc.stdout)

    def test_apidiff_compares_the_packages_go_packages_names(self) -> None:
        self.copy_api_diff("GO_PACKAGES", "sdk/go/core")
        self.assert_passes(self.gate(MODULE, REMOVED))
        self.assertNotIn("helpers", self.proc.stdout + self.proc.stderr)


class PythonCompareTest(ApiCompareTestCase):
    """api_diff.py python: griffe checks the package PYTHON_PACKAGE names."""

    def setUp(self) -> None:
        super().setUp()
        (self.repo.root / "sdk/python").mkdir(parents=True)
        (self.repo.root / "sdk/python/.venv").symlink_to(GATES.parent.parent / "sdk/python/.venv")
        self.repo.write(".gitignore", ".venv/\n")
        removed = "def removed() -> None:\n    pass\n"
        self.tag(
            {
                "sdk/python/fora_sdk/__init__.py": removed,
                "sdk/python/other/__init__.py": "",
                "sdk/other/fora_sdk/__init__.py": "",
            }
        )
        self.repo.write("sdk/python/fora_sdk/__init__.py", "")
        self.repo.write("sdk/python/other/__init__.py", removed)
        self.release("1.2.1", None)

    def test_griffe_reports_a_removal_from_python_package(self) -> None:
        proc = self.repo.script("api_diff.py", "python")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(
            proc.stdout, "sdk/python/fora_sdk/__init__.py:0: removed: Public object was removed\n"
        )

    def test_griffe_checks_the_package_python_package_names(self) -> None:
        self.copy_api_diff("PYTHON_PACKAGE", "other")
        proc = self.repo.script("api_diff.py", "python")
        self.assertEqual((proc.returncode, proc.stdout), (0, ""), proc.stderr)

    def test_griffe_finds_the_package_under_python_search_path(self) -> None:
        self.copy_api_diff("PYTHON_SEARCH_PATH", "sdk/other")
        proc = self.repo.script("api_diff.py", "python")
        self.assertEqual((proc.returncode, proc.stdout), (0, ""), proc.stderr)


if __name__ == "__main__":
    unittest.main()
