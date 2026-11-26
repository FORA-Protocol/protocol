"""Tests for the astro-check format in formats.py, run through ratchet.py.

The sample is website/scripts/astro-check.mjs's report, run with the site's
tsconfig.json and the pinned checker, over
testdata/planted/website/src/components/ZzSample.astro, which holds a type error
in its frontmatter, an untyped parameter, and a possibly-null value in a client
script. testdata/record.sh records it.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest

from ratchet_harness import RepoTestCase, entry

SAMPLE = "website/src/components/ZzSample.astro"


class AstroCheckTest(RepoTestCase):
    """The `astro-check` format, reading website/scripts/astro-check.mjs's report."""

    def setUp(self) -> None:
        super().setUp()
        self.report = json.loads(self.repo.sample("astro-check-report.json"))

    def run_report(self, report: object, tool_exit: int = 1) -> None:
        self.proc = self.repo.run_output(
            "check", "astro-check", json.dumps(report), tool_exit=tool_exit
        )

    def test_every_diagnostic_is_a_finding_with_its_code_and_line(self) -> None:
        self.record("astro-check", self.repo.sample("astro-check-report.json"))
        self.assertEqual(
            self.repo.entries(),
            [
                entry(
                    SAMPLE,
                    "ts(18047)",
                    "'node' is possibly 'null'.",
                    source='node.textContent = "y";',
                ),
                entry(
                    SAMPLE,
                    "ts(2322)",
                    "Type 'string' is not assignable to type 'number'.",
                    source='const count: number = "three";',
                ),
                entry(
                    SAMPLE,
                    "ts(7006)",
                    "Parameter 'n' implicitly has an 'any' type.",
                    source="function twice(n) {",
                ),
            ],
        )
        self.run_report(self.report)
        self.assert_passes(self.proc)

    def test_a_new_diagnostic_fails(self) -> None:
        self.record("astro-check", self.repo.sample("astro-check-report.json"))
        extra = {**self.report["diagnostics"][0], "code": "ts(2554)", "message": "Expected 1."}
        self.run_report({**self.report, "diagnostics": [*self.report["diagnostics"], extra]})
        self.assert_fails(self.proc, "findings not in the baseline", "[ts(2554)] Expected 1.")

    def test_a_report_that_checked_no_file_is_refused(self) -> None:
        self.run_report({"checked": [], "diagnostics": []}, tool_exit=0)
        self.assert_fails(self.proc, "lists the files it checked")

    def test_output_that_is_not_a_report_is_refused(self) -> None:
        self.proc = self.repo.run_output("check", "astro-check", "TypeError: boom\n", tool_exit=1)
        self.assert_fails(self.proc, "not astro-check JSON output")

    def test_an_unresolved_import_exit_fails_the_run(self) -> None:
        self.run_report(self.report, tool_exit=3)
        self.assert_fails(self.proc, "failed with exit code 3")

    def test_exit_1_with_no_diagnostic_fails_the_run(self) -> None:
        self.run_report({**self.report, "diagnostics": []}, tool_exit=1)
        self.assert_fails(self.proc, "no finding is in its output")


if __name__ == "__main__":
    unittest.main()
