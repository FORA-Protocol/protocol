"""Tests for ratchet_harness.py's isolation from the repository that runs the tests.

A hook or `git rebase -x` runs the gate tests with GIT_DIR, GIT_WORK_TREE and
GIT_INDEX_FILE naming the developer's repository, and `git -c` exports
GIT_CONFIG_PARAMETERS. The test runs the harness in a child process with each of
them naming a stand-in for that repository, and checks that the stand-in is
unchanged while the child's throwaway repository got its commit.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from ratchet_harness import GATES, RepoTestCase

# What a gate test does with the harness: a throwaway repository, a commit, a branch.
CHILD = """
import sys
from pathlib import Path
sys.path.insert(0, {gates!r})
from ratchet_harness import GateRepo
repo = GateRepo(Path({root!r}))
repo.write("file.txt", "text\\n")
repo.branch_off_main("a commit in the throwaway repository")
"""


class HarnessIsolationTest(RepoTestCase):
    """`self.repo` stands in for the developer's repository."""

    def snapshot(self) -> tuple[str, ...]:
        """Return what a command that leaked into `self.repo` would change."""
        index = (self.repo.root / ".git" / "index").read_bytes()
        return (
            self.repo.git("rev-parse", "HEAD"),
            self.repo.git("for-each-ref"),
            self.repo.git("config", "--local", "--list"),
            hashlib.sha256(index).hexdigest(),
        )

    def test_the_callers_git_variables_never_reach_a_throwaway_repository(self) -> None:
        self.repo.commit("the developer's commit")
        before = self.snapshot()
        git_dir = self.repo.root / ".git"
        # Outside the stand-in's tree, so no git command finds it by walking up.
        child = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, child)
        proc = self.repo.run_command(
            [sys.executable, "-c", CHILD.format(gates=str(GATES), root=str(child))],
            env={
                "GIT_DIR": str(git_dir),
                "GIT_WORK_TREE": str(self.repo.root),
                "GIT_INDEX_FILE": str(git_dir / "index"),
                "GIT_CONFIG_PARAMETERS": "'user.email=leaked@test.invalid'",
            },
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((child / ".git").is_dir(), "the child made no repository of its own")
        made = self.repo.run_command(["git", "-C", str(child), "log", "-1", "--format=%ae %s"])
        self.assertEqual(
            made.stdout.strip(), "gates@test.invalid a commit in the throwaway repository"
        )
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
