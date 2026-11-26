"""Tests for the biome and tsc formats in formats.py, run through ratchet.py.

The samples are the pinned biome's and tsc's output with this repository's biome.jsonc and
sdk/ts/tsconfig.json, over testdata/planted/sdk/ts/tests/zz-sample.ts, which
holds one finding of each kind, two of a limit whose message names no function,
and a tsc error whose elaborations name the repository's absolute path.
testdata/record.sh records them.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import re
import unittest

from ratchet_harness import RepoTestCase, entry

SAMPLE = "sdk/ts/tests/zz-sample.ts"
PARAMS = "Function has N parameters, but only 5 are allowed."
SIX = (
    "function sixParameters(a: number, b: number, c: number, d: number, e: number, f: number)"
    ": number {"
)
ARGUMENT = (
    "Argument of type 'typeof import(\"sdk/ts/client/index\")' is not assignable to "
    "parameter of type 'PathOrFileDescriptor'."
)
OVERLOADS = (
    "No overload matches this call. "
    "Overload 1 of 3, '(path: PathOrFileDescriptor, options?: { encoding?: null | undefined; "
    "flag?: string | undefined; } | null | undefined): NonSharedBuffer', gave the following "
    f"error. {ARGUMENT} "
    "Overload 2 of 3, '(path: PathOrFileDescriptor, options?: BufferEncoding | "
    "(ObjectEncodingOptions & { flag?: string | undefined; }) | null | undefined): string | "
    f"NonSharedBuffer', gave the following error. {ARGUMENT}"
)


class BiomeTest(RepoTestCase):
    """The `biome` format, reading `biome check --reporter=json`."""

    def setUp(self) -> None:
        super().setUp()
        self.report = json.loads(self.repo.sample("biome-report.json"))

    def run_report(self, command: str = "check", tool_exit: int = 1) -> None:
        self.proc = self.repo.run_output(
            command, "biome", json.dumps(self.report), tool_exit=tool_exit
        )

    def test_biome_reads_every_diagnostic_whatever_its_severity(self) -> None:
        severities = {d["severity"] for d in self.report["diagnostics"]}
        self.assertEqual(severities, {"error", "warning", "info"})
        self.record("biome", self.repo.sample("biome-report.json"))
        got = self.repo.entries()
        for e in [
            entry(SAMPLE, "format", "Formatter would have printed the following content:"),
            entry(
                SAMPLE,
                "lint/complexity/noExcessiveCognitiveComplexity",
                "Excessive complexity of N detected (max: 15).",
                source="function branchy(xs: number[], limits: number[]): number {",
                sizes=[57],
            ),
            entry(
                SAMPLE,
                "lint/complexity/noExcessiveLinesPerFunction",
                "This function has too many lines (N). Maximum allowed is 60.",
                source="function long(): number[] {",
                sizes=[64],
            ),
            entry(SAMPLE, "lint/complexity/useMaxParams", PARAMS, source=SIX, sizes=[6]),
            entry(
                SAMPLE,
                "lint/style/useConst",
                "This let declares a variable that is only assigned once.",
                source="let once = 1;",
            ),
        ]:
            self.assertIn(e, got)
        self.assertEqual(len(got), len(self.report["diagnostics"]))

    def test_the_smaller_of_two_same_message_findings_cannot_grow(self) -> None:
        self.record("biome", self.repo.sample("biome-report.json"))
        six = next(d for d in self.report["diagnostics"] if "has 6 parameters" in d["message"])
        six["message"] = six["message"].replace("has 6", "has 7")
        self.run_report()
        self.assert_fails(self.proc, "baselined findings that grew", f"(at: {SIX}) (6, 7)")

    def test_a_report_that_leaves_diagnostics_out_is_refused(self) -> None:
        self.report["diagnostics"].pop()
        self.run_report("record")
        self.assert_fails(self.proc, "listed 11 of the 12 diagnostics")
        self.assertFalse(self.repo.baseline.exists())
        self.report = json.loads(self.repo.sample("biome-report.json"))
        self.report["summary"]["diagnosticsNotPrinted"] = 3
        self.run_report("record")
        self.assert_fails(self.proc, "and left 3 out")
        self.assertFalse(self.repo.baseline.exists())

    def test_an_info_diagnostic_counts_at_exit_0(self) -> None:
        self.report["diagnostics"] = [
            d for d in self.report["diagnostics"] if d["severity"] == "info"
        ]
        self.report["summary"].update(errors=0, warnings=0, infos=2)
        self.run_report(tool_exit=0)
        self.assert_fails(self.proc, "lint/complexity/useLiteralKeys")

    def test_a_clean_report_passes(self) -> None:
        self.report["diagnostics"] = []
        self.report["summary"].update(errors=0, warnings=0, infos=0)
        self.run_report(tool_exit=0)
        self.assert_passes(self.proc)

    def test_a_biome_run_that_did_not_finish_fails(self) -> None:
        self.run_report(tool_exit=2)
        self.assert_fails(self.proc, "failed with exit code 2")
        self.report["diagnostics"] = []
        self.report["summary"].update(errors=0, warnings=0, infos=0)
        self.run_report(tool_exit=1)
        self.assert_fails(self.proc, "exited 1, which means it reported something")
        proc = self.repo.run_output("check", "biome", '{"diagnostics": []}')
        self.assert_fails(proc, "a biome report has a summary and diagnostics")


# A diagnostic in a dependency that ships TypeScript source, with an elaboration line.
DEPENDENCY = (
    "website/node_modules/@astrojs/starlight/utils/i18n.ts(1,1): error TS2339: "
    "Property 'language' does not exist on type 'never'.\n"
    "  An elaboration of it.\n"
)


class TscTest(RepoTestCase):
    """The `tsc` format, reading `tsc --noEmit --pretty false`."""

    def test_tsc_joins_elaborations_and_drops_the_repository_path(self) -> None:
        sample = self.repo.sample("tsc-report.txt")
        elaborations = [line for line in sample.splitlines() if line.startswith(" ")]
        self.assertTrue(any(str(self.repo.root.resolve()) in e for e in elaborations))
        self.record("tsc", sample, tool_exit=2)
        got = {e["source"]: e["message"] for e in self.repo.entries()}
        self.assertEqual(
            got["export const asNumber: number = client;"],
            "Type 'typeof import(\"sdk/ts/client/index\")' is not assignable to type 'number'.",
        )
        self.assertEqual(got["const clientBytes = readFileSync(client);"], OVERLOADS)

    def test_an_argument_count_in_a_tsc_message_is_not_a_size(self) -> None:
        self.record("tsc", self.repo.sample("tsc-report.txt"), tool_exit=2)
        arity = [e for e in self.repo.entries() if e["rule"] == "TS2554"]
        self.assertEqual(
            arity,
            [entry(SAMPLE, "TS2554", "Expected 2 arguments, but got 3.", source="two(1, 2, 3);")],
        )

    def test_a_tsc_finding_that_moved_keeps_its_entry(self) -> None:
        sample = self.repo.sample("tsc-report.txt")
        self.record("tsc", sample, tool_exit=2)
        planted = self.repo.root / SAMPLE
        planted.write_text("\n" * 7 + planted.read_text())

        def shift(m: re.Match[str]) -> str:
            return f"{m[1]}({int(m[2]) + 7},{m[3]}):"

        moved = re.sub(r"^(\S+)\((\d+),(\d+)\):", shift, sample, flags=re.MULTILINE)
        self.assertNotEqual(moved, sample)
        self.assert_passes(self.repo.run_output("check", "tsc", moved, tool_exit=2))

    def test_tsc_refuses_a_diagnostic_with_no_file(self) -> None:
        # tsc exits 1 when it cannot read its project; at any exit code, a
        # diagnostic with no file is refused.
        for code, message in [(1, "failed with exit code 1"), (2, "not a tsc diagnostic line")]:
            proc = self.repo.run_output(
                "record", "tsc", self.repo.sample("tsc-config-error.txt"), tool_exit=code
            )
            self.assert_fails(proc, message, "TS5058")
            self.assertFalse(self.repo.baseline.exists())

    def test_a_diagnostic_in_an_installed_dependency_is_not_a_finding(self) -> None:
        sample = self.repo.sample("tsc-report.txt")
        self.record("tsc", sample, tool_exit=2)
        for out in (DEPENDENCY + sample, sample + DEPENDENCY):
            self.assert_passes(self.repo.run_output("check", "tsc", out, tool_exit=2))
        # A run that reported only a dependency's diagnostic found nothing here.
        self.repo.baseline.unlink()
        self.record("tsc", DEPENDENCY, tool_exit=2)
        self.assertEqual(self.repo.entries(), [])

    def test_a_directory_that_only_starts_with_node_modules_is_this_repositorys(self) -> None:
        lookalike = DEPENDENCY.replace("/node_modules/", "/node_modules_x/")
        self.repo.write(lookalike.split("(", 1)[0], "const x = 1;\n")
        proc = self.repo.run_output("check", "tsc", lookalike, tool_exit=2)
        self.assert_fails(proc, "findings not in the baseline", "node_modules_x/")

    def test_a_clean_tsc_run_passes(self) -> None:
        self.assert_passes(self.repo.run_output("check", "tsc", "", tool_exit=0))

    def test_a_tsc_run_that_did_not_finish_fails(self) -> None:
        sample = self.repo.sample("tsc-report.txt")
        for out, code, message in [
            ("", 1, "failed with exit code 1"),
            (sample, 1, "failed with exit code 1"),
            (sample, 3, "failed with exit code 3"),
            ("", 2, "exited 2, which means it reported something"),
        ]:
            proc = self.repo.run_output("check", "tsc", out, tool_exit=code)
            self.assert_fails(proc, message)


if __name__ == "__main__":
    unittest.main()
