"""Tests for the `griffe` format in api_formats.py, run through ratchet.py.

The sample is api_diff.py's output for the planted change to the Python SDK module
fora_sdk.zz_api_planted in testdata/api/: a removed function, a renamed one, a
parameter added as required, a removed method, an added function and a deprecated
alias that warns and calls its replacement. testdata/record.sh records it with the
pinned griffe. The release rule itself is tested in test_ratchet_apidiff.py.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from api_harness import ApiTestCase, changelog
from ratchet_harness import entry

SAMPLE = "griffe.txt"
FILE = "sdk/python/fora_sdk/zz_api_planted.py"
MODULE = "fora_sdk.zz_api_planted"
REMOVED = f"{MODULE}.planted_removed"
RENAMED = f"{MODULE}.planted_renamed_old"
SIGNATURE = f"{MODULE}.planted_signature"
METHOD = f"{MODULE}.PlantedClass.dropped"
BREAKS = (REMOVED, RENAMED, SIGNATURE, METHOD)


class GriffeTest(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.release("1.2.1", "v1.2.1")

    def test_a_removal_a_rename_and_a_changed_signature_fail_and_nothing_else(self) -> None:
        self.check("griffe", self.repo.sample(SAMPLE), tool_exit=1)
        self.assert_reported(*BREAKS)
        for kept in ("planted_added", "planted_renamed_new", "planted_replacement", "deprecated"):
            self.assertNotIn(kept, self.proc.stdout)

    def test_each_finding_is_its_dotted_symbol_with_no_line(self) -> None:
        self.record("griffe", self.repo.sample(SAMPLE))
        required = f"{SIGNATURE}(b): Parameter was added as required"
        self.assertIn(entry(FILE, "incompatible", required), self.repo.entries())
        self.assertIn(
            entry(FILE, "incompatible", f"{METHOD}: Public object was removed"),
            self.repo.entries(),
        )

    def test_a_package_module_is_named_without_init(self) -> None:
        out = "sdk/python/fora_sdk/client/__init__.py:0: Client: Public object was removed\n"
        self.record("griffe", out)
        message = "fora_sdk.client.Client: Public object was removed"
        self.assertEqual(
            self.repo.entries(),
            [entry("sdk/python/fora_sdk/client/__init__.py", "incompatible", message)],
        )

    def test_the_symbol_is_what_the_changelog_lists(self) -> None:
        self.release("2.0.0", None, changelog(("Unreleased", "Breaking", [SIGNATURE])))
        self.check("griffe", self.repo.sample(SAMPLE), tool_exit=1)
        self.assert_reported(REMOVED, RENAMED, METHOD)

    def test_a_line_outside_the_search_path_is_refused(self) -> None:
        self.check("griffe", "fora_sdk/core.py:0: verify: Public object was removed\n", tool_exit=1)
        self.assert_fails(self.proc, "cannot read the output of", "not a line of griffe check")

    def test_a_breakage_exit_with_no_breakage_is_a_failed_run(self) -> None:
        self.check("griffe", "", tool_exit=1)
        self.assert_fails(self.proc, "exited 1, which means it reported something")

    def test_a_crash_fails_the_gate(self) -> None:
        self.check("griffe", "", tool_exit=2)
        self.assert_fails(self.proc, "failed with exit code 2")


if __name__ == "__main__":
    unittest.main()
