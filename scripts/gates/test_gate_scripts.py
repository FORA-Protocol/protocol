"""Tests for the gates' shell scripts, run through their command lines.

The scripts under test are the tool helpers (go-tools.sh, python-tools.sh and
node-tools.sh, with their shared tool-helper.sh), tsc-projects.sh and
jscpd-report.sh. Each test copies them into a throwaway repository and runs them
with a PATH that holds only the system tools they use and the stubs the test
writes, so a tool installed on the developer's machine cannot change the outcome.
A stub stands in for golangci-lint, uv, npm, tsc or jscpd: they are external
tools, and these tests are about what the scripts do with their answers.

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

SCRIPTS = (
    "tool-helper.sh",
    "go-tools.sh",
    "python-tools.sh",
    "node-tools.sh",
    "tsc-projects.sh",
    "jscpd-report.sh",
    "npm_installed.py",
)

# The system tools the scripts run. Nothing else is on PATH.
SYSTEM_TOOLS = (
    "bash",
    "cat",
    "cksum",
    "cut",
    "dirname",
    "env",
    "git",
    "grep",
    "mktemp",
    "python3",
    "rm",
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


class PythonToolsTest(ScriptTestCase):
    def test_a_missing_uv_is_refused_with_the_uv_installer(self) -> None:
        proc = self.repo.sh("python-tools.sh", "check")
        self.assert_exit(proc, 1)
        self.assertEqual(
            proc.stderr,
            "python-tools.sh: uv is not installed. Install it with: the uv installer, "
            "https://docs.astral.sh/uv/getting-started/installation/\n",
        )

    def test_an_environment_that_differs_from_the_lock_is_refused_with_uvs_reason(
        self,
    ) -> None:
        self.repo.stub(
            "uv",
            'echo "$*" >uv-args.txt\n'
            'echo " - ruff==0.17.3" >&2\n'
            'echo " + ruff==0.17.4" >&2\n'
            "exit 1",
        )
        proc = self.repo.sh("python-tools.sh", "check")
        self.assert_exit(
            proc,
            1,
            " - ruff==0.17.3\n + ruff==0.17.4\n",
            "python-tools.sh: sdk/python/.venv does not match sdk/python/uv.lock. "
            "Install it with: scripts/gates/python-tools.sh install",
        )
        args = (self.repo.root / "uv-args.txt").read_text().split()
        self.assertEqual(args[:4], ["sync", "--project", "sdk/python", "--locked"])
        self.assertIn("--check", args)
        self.assertIn("gates", args)

    def test_an_environment_that_matches_the_lock_passes(self) -> None:
        self.repo.stub("uv", "exit 0")
        self.assert_exit(self.repo.sh("python-tools.sh", "check"), 0)


class NodeToolsTest(ScriptTestCase):
    def test_a_missing_npm_is_refused(self) -> None:
        proc = self.repo.sh("node-tools.sh", "check")
        self.assert_exit(
            proc, 1, "node-tools.sh: npm is not installed. Install it with: Node.js 22"
        )

    def test_a_package_directory_not_installed_is_refused_with_the_one_install_command(
        self,
    ) -> None:
        self.repo.stub("npm", "exit 0")
        for pkg in ("sdk/ts", "gen/ts", "scripts/sdk-types", "scripts/gates"):
            self.repo.write(f"{pkg}/package-lock.json", json.dumps({"packages": {"": {}}}))
        proc = self.repo.sh("node-tools.sh", "check")
        self.assert_exit(
            proc,
            1,
            "sdk/ts",
            "scripts/gates",
            "node-tools.sh: the gates' npm packages do not match their lockfiles. "
            "Install it with: scripts/gates/node-tools.sh install",
        )
        self.assertEqual(proc.stdout, "")


class TscProjectsTest(ScriptTestCase):
    """tsc-projects.sh against a stub tsc whose exit and output each test sets."""

    def fake_tsc(self, code: int, *, diagnostic: bool) -> None:
        line = 'echo "a.ts(1,1): error TS2322: no."' if diagnostic else ":"
        self.repo.stub("tsc", f'echo "$2" >>projects.txt\n{line}\nexit {code}')

    def projects_run(self) -> list[str]:
        return (self.repo.root / "projects.txt").read_text().split()

    def test_a_clean_run_exits_0(self) -> None:
        self.fake_tsc(0, diagnostic=False)
        proc = self.repo.sh("tsc-projects.sh", "tsc", "p1", "p2")
        self.assert_exit(proc, 0)
        self.assertEqual(self.projects_run(), ["p1", "p2"])

    def test_diagnostics_are_printed_and_the_exit_code_is_forwarded(self) -> None:
        self.fake_tsc(2, diagnostic=True)
        proc = self.repo.sh("tsc-projects.sh", "tsc", "p1", "p2")
        self.assert_exit(proc, 2)
        self.assertEqual(proc.stdout, "a.ts(1,1): error TS2322: no.\n" * 2)
        self.assertEqual(self.projects_run(), ["p1", "p2"])

    def test_a_crash_with_no_diagnostic_stops_with_exit_3(self) -> None:
        for code in (1, 2, 127):
            with self.subTest(code=code):
                (self.repo.root / "projects.txt").unlink(missing_ok=True)
                self.fake_tsc(code, diagnostic=False)
                proc = self.repo.sh("tsc-projects.sh", "tsc", "p1", "p2")
                self.assert_exit(
                    proc,
                    3,
                    f"tsc exited {code} on p1 and reported no diagnostic, "
                    "so it did not check the project",
                )
                self.assertEqual(self.projects_run(), ["p1"])

    def test_a_crash_after_a_project_with_findings_does_not_read_as_found(self) -> None:
        # p1 reports a diagnostic and exits 2, then p2 crashes with exit 2 and no
        # diagnostic. The output holds a diagnostic, so an exit of 2 would pass the
        # tsc format as a run that found something.
        self.repo.stub(
            "tsc",
            '[ "$2" = p1 ] && { echo "a.ts(1,1): error TS2322: no."; exit 2; }\nexit 2',
        )
        proc = self.repo.sh("tsc-projects.sh", "tsc", "p1", "p2")
        self.assert_exit(proc, 3, "tsc exited 2 on p2 and reported no diagnostic")

    def test_the_highest_code_of_the_projects_is_forwarded(self) -> None:
        self.repo.stub(
            "tsc",
            'echo "x.ts(1,1): error TS1: e."\n[ "$2" = p1 ] && exit 2\nexit 1',
        )
        self.assert_exit(self.repo.sh("tsc-projects.sh", "tsc", "p1", "p2"), 2)

    def test_a_crash_fails_the_tsc_format_of_the_ratchet(self) -> None:
        self.fake_tsc(1, diagnostic=False)
        proc = self.repo.run_command(
            [
                str(self.repo.bin / "python3"),
                "scripts/gates/ratchet.py",
                "--format",
                "tsc",
                "--baseline",
                "b.json",
                "--",
                str(self.repo.bin / "bash"),
                "scripts/gates/tsc-projects.sh",
                "tsc",
                "p1",
            ],
            env={"PATH": str(self.repo.bin)},
        )
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("did not check the project", proc.stderr)

    def test_no_project_is_a_usage_error(self) -> None:
        self.assert_exit(self.repo.sh("tsc-projects.sh", "tsc"), 2, "usage: ")


class JscpdReportTest(ScriptTestCase):
    """jscpd-report.sh against a stub jscpd that writes a report, or none."""

    def setUp(self) -> None:
        super().setUp()
        # Two tracked hand-written files, and an untracked copy of one of them.
        self.repo.write("pkg/a.go", "package pkg\n")
        self.repo.write("tools/b.py", "B = 1\n")
        self.repo.write("pkg/untracked.go", "package pkg\n", stage=False)

    def fake_jscpd(self, code: int, report: str | None) -> None:
        write = (
            f"cat >\"$out/jscpd-report.json\" <<'EOF'\n{report}\nEOF" if report is not None else ":"
        )
        # The stub reads the --output directory from its arguments, as jscpd does,
        # and records the arguments that are not options: the files it is given.
        self.repo.stub(
            "jscpd",
            ': >files.txt\nout=\nwhile [ $# -gt 0 ]; do case "$1" in\n'
            "  --output) out=$2; shift ;;\n  --config|--reporters) shift ;;\n"
            '  --*) ;;\n  *) echo "$1" >>files.txt ;;\nesac; shift; done\n'
            f'echo "$out" >outdir.txt\n{write}\nexit {code}',
        )

    def test_jscpd_reads_exactly_the_tracked_hand_written_files(self) -> None:
        self.fake_jscpd(0, "{}")
        self.assert_exit(self.repo.sh("jscpd-report.sh", "jscpd"), 0)
        given = (self.repo.root / "files.txt").read_text().split()
        self.assertEqual(given, ["pkg/a.go", "tools/b.py"])

    def test_no_tracked_file_exits_2(self) -> None:
        self.repo.git("rm", "-q", "--cached", "pkg/a.go", "tools/b.py")
        self.fake_jscpd(0, "{}")
        proc = self.repo.sh("jscpd-report.sh", "jscpd")
        self.assert_exit(proc, 2, "jscpd-report.sh: scope.py listed no file")

    def test_the_report_is_printed_with_jscpds_exit_code(self) -> None:
        for code in (0, 1):
            with self.subTest(code=code):
                self.fake_jscpd(code, '{"duplicates": []}')
                proc = self.repo.sh("jscpd-report.sh", "jscpd")
                self.assert_exit(proc, code)
                self.assertEqual(proc.stdout, '{"duplicates": []}\n')

    def test_no_report_exits_2_whatever_jscpd_exited(self) -> None:
        for code in (0, 1):
            with self.subTest(code=code):
                self.fake_jscpd(code, None)
                proc = self.repo.sh("jscpd-report.sh", "jscpd")
                self.assert_exit(
                    proc, 2, f"jscpd-report.sh: jscpd exited {code} and wrote no report"
                )
                self.assertEqual(proc.stdout, "")

    def test_the_report_directory_is_removed(self) -> None:
        self.fake_jscpd(0, "{}")
        self.assert_exit(self.repo.sh("jscpd-report.sh", "jscpd"), 0)
        outdir = (self.repo.root / "outdir.txt").read_text().strip()
        self.assertTrue(outdir)
        self.assertFalse(Path(outdir).exists())


if __name__ == "__main__":
    unittest.main()
