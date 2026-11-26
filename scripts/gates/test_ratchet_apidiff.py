"""Tests for the `apidiff` format in api_formats.py and the release rule, run through ratchet.py.

The sample is api_diff.py's output for the planted change to the Go SDK package
sdk/go/core in testdata/api/: a removed function, a renamed one, a changed
signature, a removed method, an added function, a deprecated alias that calls
its replacement, and three constants, one with a new value, one retyped and one
that became a variable. testdata/record.sh records it with the pinned apidiff.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import sys
import unittest

from api_harness import ApiTestCase, changelog
from ratchet_harness import entry

SAMPLE = "apidiff.txt"
REMOVED = "./sdk/go/core.PlantedRemoved"
RENAMED = "./sdk/go/core.PlantedRenamedOld"
SIGNATURE = "./sdk/go/core.PlantedSignature"
METHOD = "./sdk/go/core.PlantedType.Dropped"
VALUE = "./sdk/go/core.PlantedValue"
RETYPED = "./sdk/go/core.PlantedRetyped"
TO_VAR = "./sdk/go/core.PlantedConstToVar"
CONSTANTS = (VALUE, RETYPED, TO_VAR)
BREAKS = (REMOVED, RENAMED, SIGNATURE, METHOD, *CONSTANTS)


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
        self.assert_reported(RENAMED, SIGNATURE, *CONSTANTS)
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
        self.assert_reported(RENAMED, SIGNATURE, METHOD, *CONSTANTS)
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
            proc, "no release tag (vX.Y.Z) is reachable from HEAD", "git fetch --tags", code=3
        )
        self.assertEqual(proc.stdout, "")

    def test_without_a_release_tag_each_gate_fails_with_that_reason_alone(self) -> None:
        # griffe's Format counts exit 1 as a breakage reported, so a refusal that
        # exited 1 would also read as a breakage missing from the output.
        self.release("1.2.1", None)
        self.repo.write_entries([])
        for sdk, fmt in (("go", "apidiff"), ("python", "griffe"), ("ts", "api-extractor")):
            with self.subTest(sdk=sdk):
                ratchet = ["check", "--format", fmt, "--baseline", str(self.repo.baseline)]
                command = [sys.executable, "scripts/gates/api_diff.py", sdk]
                proc = self.repo.script("ratchet.py", *ratchet, "--", *command)
                self.assert_fails(proc, "git fetch --tags", "failed with exit code 3")
                self.assertNotIn("no finding is in its output", proc.stderr)

    def test_an_unknown_sdk_is_a_usage_error(self) -> None:
        proc = self.repo.script("api_diff.py", "rust")
        self.assert_fails(proc, "usage: api_diff.py", code=2)


class VersionConstantTest(ApiTestCase):
    """api_rules.py: a version constant may take a new value within its major in a minor release.

    Each case reads a line apidiff printed for the planted constants, with the
    planted symbol, and where a case needs it the values, replaced, so the rule is
    tested against the tool's own wording.
    """

    VERSION = "./sdk/go/helpers.ProtocolVersion"
    MANIFEST = "./sdk/go/helpers.WellKnownManifestVersion"
    OTHER = "./sdk/go/helpers.ConnectProtocolVersion"

    def setUp(self) -> None:
        super().setUp()
        self.release("1.3.0", "v1.2.1")
        self.lines = {
            line.split(":", 1)[0][2:]: line for line in self.repo.sample(SAMPLE).splitlines()
        }

    def planted(self, planted: str, symbol: str, values: tuple[str, str] = ("1.0", "1.1")) -> str:
        """Return apidiff's line for `planted`, naming `symbol`, with `values` if it is a value."""
        line = self.lines[planted].replace(planted, symbol)
        return line.replace('"1.0" to "1.1"', f'"{values[0]}" to "{values[1]}"') + "\n"

    def test_a_new_version_value_within_its_major_passes_and_another_constant_fails(self) -> None:
        sample = self.planted(VALUE, self.VERSION) + self.planted(VALUE, self.MANIFEST)
        self.check("apidiff", sample + self.planted(VALUE, self.OTHER))
        self.assert_reported(self.OTHER)
        self.assertIn(f'{self.OTHER}: value changed from "1.0" to "1.1"', self.proc.stdout)
        for symbol in (self.VERSION, self.MANIFEST):
            self.assertIn(f"api: {symbol} is a version constant, so a new value", self.proc.stderr)

    def test_any_other_change_to_a_version_constant_fails_with_its_reason(self) -> None:
        for name, line, reason in (
            (
                "a new major",
                self.planted(VALUE, self.VERSION, ("1.0", "2.0")),
                '"1.0" to "2.0" is not a new value',
            ),
            (
                "an empty value",
                self.planted(VALUE, self.VERSION, ("1.0", "")),
                '"1.0" to "" is not a new value',
            ),
            (
                "a retype",
                self.planted(RETYPED, self.VERSION),
                "1.3.0 is not a major release after v1.2.1",
            ),
            (
                "const to var",
                self.planted(TO_VAR, self.VERSION),
                "1.3.0 is not a major release after v1.2.1",
            ),
            (
                "a removal",
                self.planted(REMOVED, self.VERSION),
                "1.3.0 is not a major release after v1.2.1",
            ),
        ):
            with self.subTest(name=name):
                self.check("apidiff", line)
                self.assert_reported(self.VERSION)
                self.assertIn(line.removeprefix("- ").strip(), self.proc.stdout)
                self.assertIn(reason, self.proc.stderr)


if __name__ == "__main__":
    unittest.main()
