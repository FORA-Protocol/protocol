"""Tests for ci-base-ref.sh, the base each GitHub Actions run of the gates compares with.

Each test builds, in a throwaway repository, the history a run checks out, and runs
the script with the variables GitHub Actions sets. Every run sets all three, empty
when unused, so running these tests inside GitHub Actions cannot leak the job's own.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ratchet_harness import RepoTestCase

if TYPE_CHECKING:
    import subprocess

PULL_REQUEST = ("pull_request", "refs/pull/7/merge")
PUSH_TO_MAIN = ("push", "refs/heads/main")
RELEASE_TAG = ("push", "refs/tags/v1.2.3")


class CiBaseRefTest(RepoTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.repo.copy("ci-base-ref.sh")
        self.first = self.commit("first")
        self.second = self.commit("second")

    def commit(self, message: str) -> str:
        self.repo.commit(message)
        return self.head()

    def head(self) -> str:
        return self.repo.git("rev-parse", "HEAD").strip()

    def base(self, trigger: tuple[str, str], before: str = "") -> subprocess.CompletedProcess[str]:
        event, ref = trigger
        return self.repo.run_command(
            ["bash", "scripts/gates/ci-base-ref.sh"],
            env={"GITHUB_EVENT_NAME": event, "GITHUB_REF": ref, "BEFORE": before},
        )

    def assert_base(self, proc: subprocess.CompletedProcess[str], commit: str) -> None:
        self.assert_passes(proc)
        self.assertEqual(proc.stdout.strip(), commit)

    def merge_a_branch_off_first(self) -> str:
        """Merge a branch that left main at `first`, as GitHub's pull request merge does."""
        self.repo.git("checkout", "-q", "-b", "feature", self.first)
        self.commit("feature")
        self.repo.git("checkout", "-q", "main")
        self.repo.git("merge", "-q", "--no-ff", "-m", "merge", "feature")
        return self.head()

    def test_a_pull_request_compares_with_the_base_side_of_its_merge(self) -> None:
        self.merge_a_branch_off_first()
        self.assert_base(self.base(PULL_REQUEST), self.second)

    def test_a_pull_request_keeps_its_base_when_the_base_branch_moves_on(self) -> None:
        merge = self.merge_a_branch_off_first()
        self.commit("main moves on")
        self.repo.git("checkout", "-q", "--detach", merge)
        self.assert_base(self.base(PULL_REQUEST), self.second)

    def test_a_pull_request_checkout_that_is_not_a_merge_fails(self) -> None:
        self.assert_fails(self.base(PULL_REQUEST), "HEAD is not a merge")

    def test_a_push_to_main_compares_with_main_before_the_push(self) -> None:
        # Two commits pushed at once: the base is BEFORE, not HEAD's parent.
        self.commit("third")
        self.assert_base(self.base(PUSH_TO_MAIN, before=self.first), self.first)

    def test_a_push_to_main_without_before_fails(self) -> None:
        for before in ("", "0" * 40):
            with self.subTest(before=before):
                self.assert_fails(self.base(PUSH_TO_MAIN, before=before), "needs BEFORE")

    def test_a_force_push_to_main_fails(self) -> None:
        self.repo.git("checkout", "-q", "-b", "side", self.first)
        side = self.commit("a commit main never had")
        self.repo.git("checkout", "-q", "main")
        self.assert_fails(self.base(PUSH_TO_MAIN, before=side), "is not an ancestor of HEAD")

    def test_a_release_tag_compares_with_the_tagged_commits_parent(self) -> None:
        self.assert_base(self.base(RELEASE_TAG), self.first)

    def test_a_release_tag_on_a_root_commit_fails(self) -> None:
        self.repo.git("checkout", "-q", "--detach", self.first)
        self.assert_fails(self.base(RELEASE_TAG), "has no parent to compare with")

    def test_a_trigger_with_no_named_base_fails(self) -> None:
        for trigger in (("workflow_dispatch", "refs/heads/main"), ("push", "refs/heads/side")):
            with self.subTest(trigger=trigger):
                self.assert_fails(self.base(trigger, before=self.first), "no base is named")


if __name__ == "__main__":
    unittest.main()
