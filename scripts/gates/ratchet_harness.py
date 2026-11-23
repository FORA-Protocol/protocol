"""Shared fixtures for the gate tests: a throwaway repository and its test case.

Each test copies the gate modules (MODULES) into a throwaway git repository, so
each script finds that repository as its root exactly as it finds this one, and
the --base-ref check reads real commits. A RepoTestCase's repository also holds
the planted sources the recorded tool samples point at (testdata/planted/),
because the ratchet reads the line each finding points at. git runs without the
developer's global and system config, so a setting there, such as commit signing,
cannot change a test's outcome. It also runs without any GIT_* variable of the
process that started the tests: a hook or `git rebase -x` exports GIT_DIR,
GIT_WORK_TREE and GIT_INDEX_FILE, which would point every command meant for the
throwaway repository at the developer's own.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scope import lines
from toolfiles import declared

GATES = Path(__file__).parent
TESTDATA = GATES / "testdata"
PLANTED = TESTDATA / "planted"
MODULES = (
    "ratchet.py",
    "baseline.py",
    "carry.py",
    "formats.py",
    "api_diff.py",
    "api_formats.py",
    "api_rules.py",
    "scope.py",
    "toolfiles.py",
    "inline_suppressions.py",
    "file_length.py",
)


def git_env() -> dict[str, str]:
    """Return this process's environment with no GIT_* variable, and no git config file."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    return {**env, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}


GIT_ENV = git_env()

# The gate script a throwaway repository's --base-ref check finds by the baseline it names.
GATE_SCRIPT = "scripts/gates/gate-test.sh"
BASELINE = "scripts/gates/baselines/gate.json"

# A Go file with two lines a finding can point at, F and H.
F = "func f() { g() }"
H = "func h() { k() }"
A_GO = f"package a\n\n{F}\n{H}\n"


def row(
    path: str, rule: str, message: str, size: int | None = None, *, line: int | None = None
) -> str:
    """Return one row of the `lines` format; with no `line`, the finding is about the file."""
    at = "-" if line is None else line
    return f"{path}\t{at}\t{rule}\t{'-' if size is None else size}\t{message}"


def entry(
    path: str,
    rule: str,
    message: str,
    count: int = 1,
    *,
    source: str = "",
    sizes: list[int] | None = None,
) -> dict[str, object]:
    """Return one baseline entry, in the shape ratchet.py writes it.

    An entry whose size is worse when lower also has `"lower_is_worse": True`.
    """
    e: dict[str, object] = {"path": path, "rule": rule, "message": message}
    if source:
        e["source"] = source
    e["count"] = count
    if sizes is not None:
        e["sizes"] = sizes
    return e


class GateRepo:
    """A throwaway git repository holding a copy of the gate modules."""

    def __init__(self, root: Path) -> None:
        self.root = root
        (root / "scripts" / "gates").mkdir(parents=True)
        for name in MODULES:
            shutil.copy(GATES / name, root / "scripts" / "gates" / name)
        # The modules' bytecode stays out of every commit, as in the repository.
        (root / ".gitignore").write_text("__pycache__/\n")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "gates@test.invalid")
        self.git("config", "user.name", "gate test")

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
            env=GIT_ENV,
        ).stdout

    def write(self, path: str, text: str, *, stage: bool = True) -> None:
        """Write `text` to `path` under the root, and stage it unless `stage` is False."""
        f = self.root / path
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
        if stage:
            self.git("add", path)

    def commit(self, message: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)

    def branch_off_main(self, message: str) -> None:
        """Commit the tree on main as `message`, then continue on a topic branch."""
        self.commit(message)
        self.git("checkout", "-q", "-b", "topic")

    def copy(self, *names: str) -> None:
        """Copy more of scripts/gates/ (by name) into the repository, keeping their mode."""
        for name in names:
            shutil.copy2(GATES / name, self.root / "scripts" / "gates" / name)

    def run_command(
        self, argv: list[str], env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run `argv` from the root, with git kept out of the developer's config and `env` added."""
        return subprocess.run(
            argv,
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
            env={**GIT_ENV, **(env or {})},
        )

    def script(self, name: str, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the copy of the Python script scripts/gates/`name` from the root."""
        return self.run_command(
            [sys.executable, str(self.root / "scripts" / "gates" / name), *args]
        )


class RatchetRepo(GateRepo):
    """A GateRepo with a baseline for ratchet.py."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.baseline = root / BASELINE

    def plant(self) -> None:
        """Copy in the planted sources the recorded tool samples point at."""
        for source in PLANTED.rglob("*.txt"):
            target = self.root / source.relative_to(PLANTED).with_suffix("")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(source, target)

    def introduce_gate(self) -> None:
        """Write the gate script that names the baseline, as a gate script does."""
        self.write(GATE_SCRIPT, f'exec ratchet.py --baseline {BASELINE} "$@" -- tool\n')

    def run(
        self, command: str, findings: list[str], *extra: str, tool_exit: int = 0
    ) -> subprocess.CompletedProcess[str]:
        """Run ratchet `command` against a scanner that prints the `lines` rows `findings`."""
        out = "".join(f + "\n" for f in findings)
        return self.run_output(command, "lines", out, *extra, tool_exit=tool_exit)

    def run_base(
        self, command: str, findings: list[str], *extra: str, ref: str = "main"
    ) -> subprocess.CompletedProcess[str]:
        """Run `run` with --base-ref `ref` and the gate script GATE_SCRIPT."""
        return self.run(command, findings, "--base-ref", ref, "--gate", GATE_SCRIPT, *extra)

    def row_at(self, path: str, rule: str, message: str, text: str, size: int | None = None) -> str:
        """Return the row of a finding at the line `text` of `path`, as the file is now."""
        found = lines((self.root / path).read_text())
        return row(path, rule, message, size, line=found.index(text) + 1)

    def run_output(
        self,
        command: str,
        fmt: str,
        out: str,
        *extra: str,
        tool_exit: int = 1,
        err: str = "",
    ) -> subprocess.CompletedProcess[str]:
        """Run ratchet `command` with format `fmt` against a tool that prints `out`.

        The tool writes `err` to stderr and exits with `tool_exit`. An empty
        `command` leaves it out, as a gate script does when it passes its own
        arguments through.
        """
        code = (
            f"import sys; sys.stdout.write({out!r}); sys.stderr.write({err!r}); "
            f"sys.exit({tool_exit})"
        )
        return self.script(
            "ratchet.py",
            *([command] if command else []),
            "--format",
            fmt,
            "--baseline",
            str(self.baseline),
            *extra,
            "--",
            sys.executable,
            "-c",
            code,
        )

    def gate(self, name: str, *args: str) -> subprocess.CompletedProcess[str]:
        """Run a copy of scripts/gates/gate-`name`.sh with `args`, as run.sh runs it.

        The gate's own baseline becomes `self.baseline`.
        """
        script = f"gate-{name}.sh"
        self.copy(script)
        (baseline,) = declared((GATES / script).read_text()).baselines
        self.baseline = self.root / baseline
        return self.run_command(["bash", f"scripts/gates/{script}", *args])

    def sample(self, name: str) -> str:
        """Return testdata/`name`, with `{root}` spelled as this repository's root.

        The root is resolved, because the tools print resolved paths.
        """
        return (TESTDATA / name).read_text().replace("{root}", str(self.root.resolve()))

    def entries(self) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = json.loads(self.baseline.read_text())["findings"]
        return findings

    def write_entries(self, entries: list[dict[str, object]]) -> None:
        self.baseline.parent.mkdir(parents=True, exist_ok=True)
        self.baseline.write_text(json.dumps({"findings": entries}, indent=2) + "\n")


class RepoTestCase(unittest.TestCase):
    """A test case with a fresh throwaway repository, with the planted sources, in `self.repo`."""

    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = RatchetRepo(Path(tmp))
        self.repo.plant()

    def record(self, fmt: str, out: str, tool_exit: int = 1) -> None:
        """Record a baseline from a tool that prints `out`, and assert that it worked."""
        proc = self.repo.run_output("record", fmt, out, tool_exit=tool_exit)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.repo.baseline.exists())

    def record_rows(self, rows: list[str]) -> None:
        """Record a baseline from a scanner that prints the `lines` rows `rows`."""
        proc = self.repo.run("record", rows)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(self.repo.baseline.exists())

    def assert_fails(
        self, proc: subprocess.CompletedProcess[str], *expected: str, code: int = 1
    ) -> None:
        """Assert that `proc` exited `code` and printed each of `expected`."""
        self.assertEqual(proc.returncode, code, proc.stdout + proc.stderr)
        for text in expected:
            self.assertIn(text, proc.stdout + proc.stderr)

    def assert_passes(self, proc: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
