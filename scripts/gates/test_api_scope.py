"""Tests that the scope gate reads the Go and Python API gates' files from api_diff.py.

api_diff.py builds apidiff's and griffe's command lines from GO_PACKAGES,
PYTHON_PACKAGE and PYTHON_SEARCH_PATH alone, and scope_coverage.py imports the same
constants to name the files those gates read. Each test copies api_diff.py, with one
constant changed, into a directory of its own ahead of scripts/gates on the module
path, and runs the scope gate's public-surface check over this repository with the
real go and griffe: the problems surface_problems returns for the files api_go_files
and api_python_files name. That is the part of gate-scope.sh these constants feed;
the whole gate also runs jscpd and API Extractor over the tree, which takes over a
minute. Nothing in the repository is written.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

from api_harness import api_diff_with
from ratchet_harness import GATES
from scope import run, surface

if TYPE_CHECKING:
    import subprocess


# Prints each public-surface problem of the Go and Python API gates, one per line.
DRIVER = """
import sys
sys.path[:0] = sys.argv[1:3]
import scope_coverage as s
read = {"api-go": s.api_go_files(), "api-python": s.api_python_files()}
print("".join(line + "\\n" for line in s.surface_problems(read)), end="")
"""


class ApiScopeTest(unittest.TestCase):
    def problems(self, constant: str = "", value: str = "") -> subprocess.CompletedProcess[str]:
        """Run the surface check with api_diff.py's `constant` set to `value`."""
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        if constant:
            text = api_diff_with(constant, value)
        else:
            text = (GATES / "api_diff.py").read_text(encoding="utf-8")
        Path(tmp, "api_diff.py").write_text(text, encoding="utf-8")
        # scope.run runs it from the repository root, which it only reads.
        return run([sys.executable, "-c", DRIVER, tmp, str(GATES)])

    def assert_missed(self, proc: subprocess.CompletedProcess[str], gate: str, kept: str) -> None:
        """Assert that each file of `gate`'s surface outside `kept` is reported, and no other."""
        self.assertEqual(proc.returncode, 0, proc.stderr)
        missed = sorted(p for p in surface(gate) if not p.startswith(kept))
        self.assertTrue(missed, f"{gate} has a public surface outside {kept}")
        expected = [f"{p}: public surface of {gate}, but {gate} does not read it" for p in missed]
        self.assertEqual(proc.stdout.splitlines(), expected)

    def test_the_constants_as_committed_read_exactly_each_surface(self) -> None:
        proc = self.problems()
        self.assertEqual((proc.returncode, proc.stdout), (0, ""), proc.stderr)

    def test_fewer_go_packages_leave_the_rest_of_the_go_surface_unread(self) -> None:
        proc = self.problems("GO_PACKAGES", "sdk/go/core")
        self.assert_missed(proc, "api-go", "sdk/go/core/")

    def test_another_python_package_leaves_the_rest_of_the_python_surface_unread(self) -> None:
        proc = self.problems("PYTHON_PACKAGE", "fora_sdk.client")
        self.assert_missed(proc, "api-python", "sdk/python/fora_sdk/client/")

    def test_a_search_path_without_the_package_fails_the_check(self) -> None:
        proc = self.problems("PYTHON_SEARCH_PATH", "sdk/python/fora_sdk")
        self.assertNotEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("scope_coverage: sdk/python/.venv/bin/griffe dump fora_sdk", proc.stderr)


if __name__ == "__main__":
    unittest.main()
