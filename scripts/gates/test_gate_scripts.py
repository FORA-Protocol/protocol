"""Tests for the gates' shell scripts, run through their command lines.

The script under test is the Go tool helper, go-tools.sh, with the shared
tool-helper.sh. Each test copies them into a throwaway repository and runs them
with a PATH that holds only the system tools they use and the stubs the test
writes, so a tool installed on the developer's machine cannot change the outcome.
A stub stands in for golangci-lint: it is an external tool, and these tests are
about what the scripts do with its answers.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

from ratchet_harness import GateRepo

if TYPE_CHECKING:
    import subprocess

SCRIPTS = ("tool-helper.sh", "go-tools.sh")

# The system tools the scripts run. Nothing else is on PATH.
SYSTEM_TOOLS = (
    "bash",
    "cksum",
    "cut",
    "dirname",
    "git",
    "python3",
    "sh",
)


class ToolRepo(GateRepo):
    """A throwaway repository with the gate shell scripts and a PATH of its own."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.copy(*SCRIPTS)
        self.bin = root / "bin"
        self.bin.mkdir()
        for tool in SYSTEM_TOOLS:
            found = shutil.which(tool)
            if found is None:
                raise unittest.SkipTest(f"{tool} is not installed")
            (self.bin / tool).symlink_to(found)

    def stub(self, name: str, body: str) -> None:
        """Put an executable `name` on PATH that runs the sh `body`."""
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def sh(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the copied scripts/gates/`script` with this repository's PATH."""
        return self.run_command(
            [str(self.bin / "bash"), f"scripts/gates/{script}", *args],
            env={"PATH": str(self.bin), "HOME": str(self.root)},
        )


class ScriptTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = ToolRepo(Path(tmp))

    def assert_exit(
        self, proc: subprocess.CompletedProcess[str], code: int, *expected: str
    ) -> None:
        """Assert that `proc` exited `code` and printed each of `expected`."""
        self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
        for text in expected:
            self.assertIn(text, proc.stdout + proc.stderr)


class GoToolsTest(ScriptTestCase):
    def test_a_missing_golangci_lint_is_refused_on_stderr_with_the_install_command(self) -> None:
        proc = self.repo.sh("go-tools.sh", "check")
        self.assert_exit(proc, 1)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(
            proc.stderr,
            "go-tools.sh: golangci-lint is not installed, the Go gates pin 2.12.2. "
            "Install it with: scripts/gates/go-tools.sh install\n",
        )

    def test_another_golangci_lint_version_is_refused(self) -> None:
        self.repo.stub("golangci-lint", "echo 2.11.0")
        proc = self.repo.sh("go-tools.sh", "check")
        self.assert_exit(proc, 1, "golangci-lint is 2.11.0, the Go gates pin 2.12.2")

    def test_the_pinned_version_passes(self) -> None:
        self.repo.stub("golangci-lint", "echo 2.12.2")
        self.assert_exit(self.repo.sh("go-tools.sh", "check"), 0)

    def test_ratchet_runs_no_tool_when_the_check_fails(self) -> None:
        tool = ["--", "sh", "-c", "echo ran >ran.txt"]
        proc = self.repo.sh(
            "go-tools.sh", "ratchet", "scripts/gates/gate-x.sh", "lines", "b.json", *tool
        )
        self.assert_exit(proc, 1, "golangci-lint is not installed")
        self.assertFalse((self.repo.root / "ran.txt").exists())

    def test_ratchet_without_its_arguments_is_a_usage_error(self) -> None:
        self.repo.stub("golangci-lint", "echo 2.12.2")
        proc = self.repo.sh("go-tools.sh", "ratchet", "scripts/gates/gate-x.sh", "lines")
        self.assert_exit(proc, 2, "usage: ")

    def test_ratchet_passes_the_gate_script_to_ratchet_py(self) -> None:
        # ratchet.py refuses --base-ref without --gate, and with --gate it treats a
        # gate script that main does not have as a new gate. So the run passes only
        # if the helper handed the gate path on.
        self.repo.stub("golangci-lint", "echo 2.12.2")
        gate = "scripts/gates/gate-x.sh"
        self.repo.branch_off_main("main without the gate")
        self.repo.write(gate, "# scripts/gates/baselines/x.json\n")
        tool = ["--", "python3", "-c", "pass"]
        ratchet = ("ratchet", gate, "lines", "scripts/gates/baselines/x.json")
        self.assert_exit(self.repo.sh("go-tools.sh", *ratchet, "record", *tool), 0)
        proc = self.repo.sh("go-tools.sh", *ratchet, "--base-ref", "main", *tool)
        self.assert_exit(proc, 0)


if __name__ == "__main__":
    unittest.main()
