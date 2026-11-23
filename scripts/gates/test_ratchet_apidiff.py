"""Tests for the `apidiff` format in api_formats.py and the release rule, run through ratchet.py.

The sample is api_diff.py's output for the planted change to the Go SDK package
sdk/go/core in testdata/api/: a removed function, a renamed one, a changed
signature, a removed method, an added function and a deprecated alias that calls
its replacement. testdata/record.sh records it with the pinned apidiff.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from api_harness import ApiTestCase, changelog
from ratchet_harness import entry

SAMPLE = "apidiff.txt"
REMOVED = "./sdk/go/core.PlantedRemoved"
RENAMED = "./sdk/go/core.PlantedRenamedOld"
SIGNATURE = "./sdk/go/core.PlantedSignature"
METHOD = "./sdk/go/core.PlantedType.Dropped"
BREAKS = (REMOVED, RENAMED, SIGNATURE, METHOD)


class ApidiffTest(ApiTestCase):
    def test_a_removal_a_rename_and_a_changed_signature_fail_and_nothing_else(self) -> None:
        self.release("1.2.1", "v1.2.1")
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(*BREAKS)
        for kept in ("PlantedAdded", "PlantedRenamedNew", "PlantedReplacement", "Deprecated"):
            self.assertNotIn(kept, self.proc.stdout)

    def test_each_finding_is_its_symbol_in_its_package_with_no_line(self) -> None:
        self.release("1.2.1", "v1.2.1")
        self.record("apidiff", self.repo.sample(SAMPLE), tool_exit=0)
        signature = f"{SIGNATURE}: changed from func(int) int to func(int, string) int"
        self.assertIn(entry("sdk/go/core", "incompatible", signature), self.repo.entries())
        self.assertIn(
            entry("sdk/go/core", "incompatible", f"{METHOD}: removed"), self.repo.entries()
        )

    def test_a_removed_package_is_named_by_its_import_path(self) -> None:
        self.release("1.2.1", "v1.2.1")
        package = "github.com/FORA-Protocol/protocol/sdk/go/helpers"
        self.record("apidiff", f"- package {package}: removed\n", tool_exit=0)
        self.assertEqual(
            self.repo.entries(), [entry("sdk/go/helpers", "incompatible", f"{package}: removed")]
        )

    def test_output_with_section_headings_is_refused(self) -> None:
        self.release("1.2.1", "v1.2.1")
        self.check("apidiff", "Incompatible changes:\n" + self.repo.sample(SAMPLE))
        self.assert_fails(self.proc, "cannot read the output of", "Incompatible changes:")

    def test_a_failed_run_fails_the_gate(self) -> None:
        self.release("1.2.1", "v1.2.1")
        self.check("apidiff", "", tool_exit=1)
        self.assert_fails(self.proc, "failed with exit code 1")


class ReleaseRuleTest(ApiTestCase):
    """api_rules.py: a break passes only in a major release that lists it under Breaking."""

    def test_a_major_release_that_lists_the_symbol_under_breaking_allows_it(self) -> None:
        self.release("2.0.0", "v1.2.1", changelog(("Unreleased", "Breaking", [REMOVED, METHOD])))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(RENAMED, SIGNATURE)
        self.assertIn(f"api: {REMOVED} is listed under Breaking", self.proc.stderr)

    def test_the_section_may_be_headed_with_the_new_version(self) -> None:
        self.release("2.0.0", "v1.2.1", changelog(("2.0.0", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_passes(self.proc)

    def test_a_listed_symbol_in_a_minor_release_fails(self) -> None:
        self.release("1.3.0", "v1.2.1", changelog(("Unreleased", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(*BREAKS)
        self.assertIn("1.3.0 is not a major release after v1.2.1", self.proc.stderr)

    def test_a_major_release_that_does_not_list_the_symbol_fails(self) -> None:
        self.release("2.0.0", "v1.2.1", changelog(("Unreleased", "Breaking", [REMOVED])))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(RENAMED, SIGNATURE, METHOD)
        self.assertIn(f"api: {RENAMED} is not listed under Breaking", self.proc.stderr)

    def test_only_the_breaking_list_of_the_first_section_counts(self) -> None:
        sections = (
            ("Unreleased", "Added", list(BREAKS)),
            ("1.2.1", "Breaking", list(BREAKS)),
        )
        self.release("2.0.0", "v1.2.1", changelog(*sections))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(*BREAKS)

    def test_a_first_section_for_another_version_does_not_count(self) -> None:
        self.release("2.0.0", "v1.2.1", changelog(("1.9.0", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(*BREAKS)

    def test_the_newest_release_tag_reachable_from_head_is_the_last_release(self) -> None:
        self.repo.commit("an older release")
        self.repo.git("tag", "v1.9.0")
        self.repo.git("tag", "v2.0.0-rc.1")
        self.release("2.0.0", "v1.10.0", changelog(("Unreleased", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_passes(self.proc)

    def test_a_release_tag_that_head_does_not_reach_is_not_the_last_release(self) -> None:
        self.repo.commit("the base")
        self.repo.git("checkout", "-q", "-b", "other")
        self.repo.commit("another line of releases")
        self.repo.git("tag", "v10.0.0")
        self.repo.git("checkout", "-q", "main")
        self.release("2.0.0", "v1.2.1", changelog(("Unreleased", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_passes(self.proc)

    def test_release_tags_are_ordered_by_version_not_by_name(self) -> None:
        # By name, v1.0.0 sorts first and v9.0.0 last; against either, 10.1.0 would
        # read as a major release.
        self.repo.commit("older releases")
        self.repo.git("tag", "v1.0.0")
        self.repo.git("tag", "v9.0.0")
        self.release("10.1.0", "v10.0.0", changelog(("Unreleased", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(*BREAKS)
        self.assertIn("10.1.0 is not a major release after v10.0.0", self.proc.stderr)

    def test_without_a_release_tag_nothing_is_allowed(self) -> None:
        self.release("2.0.0", None, changelog(("Unreleased", "Breaking", list(BREAKS))))
        self.check("apidiff", self.repo.sample(SAMPLE))
        self.assert_reported(*BREAKS)
        self.assertIn("fetch the tags", self.proc.stderr)


class CompareTest(ApiTestCase):
    """api_diff.py: the comparison needs the last release, and fails without one."""

    def test_without_a_release_tag_nothing_is_compared(self) -> None:
        self.release("1.2.1", None)
        proc = self.repo.script("api_diff.py", "go")
        self.assert_fails(
            proc, "no release tag (vX.Y.Z) is reachable from HEAD", "git fetch --tags"
        )
        self.assertEqual(proc.stdout, "")

    def test_an_unknown_sdk_is_a_usage_error(self) -> None:
        proc = self.repo.script("api_diff.py", "rust")
        self.assert_fails(proc, "usage: api_diff.py", code=2)


if __name__ == "__main__":
    unittest.main()
