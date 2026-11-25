"""Tests for the `api-extractor` format in api_formats.py, run through ratchet.py.

The sample is api_diff.py's line for the TypeScript SDK's entry point ./hashurl,
whose module testdata/api/ plants: a removed function, a renamed one, a parameter
added as required, a removed interface member and class method, an added function
and member, and a deprecated alias that calls its replacement. The committed report
of ./hashurl is the real module's, so API Extractor also reports it as out of date.
testdata/record.sh records it with the pinned API Extractor. The release rule
itself is tested in test_ratchet_apidiff.py.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from api_harness import ApiTestCase, changelog
from ratchet_harness import entry

SAMPLE = "api-extractor.jsonl"
REPORT = "sdk/ts/api/hashurl.api.md"
REMOVED = "./hashurl.plantedRemoved"
RENAMED = "./hashurl.plantedRenamedOld"
SIGNATURE = "./hashurl.plantedSignature"
MEMBER = "./hashurl.PlantedShape.dropped"
METHOD = "./hashurl.PlantedClass.dropped"
BREAKS = (REMOVED, RENAMED, SIGNATURE, MEMBER, METHOD)
STALE = "console-api-report-not-copied"


class ApiExtractorTest(ApiTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.release("1.2.1", "v1.2.1")
        self.row: dict[str, Any] = json.loads(self.repo.sample(SAMPLE))

    def run_row(self, *rows: dict[str, Any]) -> None:
        self.check("api-extractor", "".join(json.dumps(r) + "\n" for r in rows or [self.row]))

    def test_a_removal_a_rename_and_a_changed_signature_fail_and_nothing_else(self) -> None:
        self.row["messages"] = []
        self.run_row()
        self.assert_reported(*BREAKS)
        for kept in ("plantedAdded", "plantedRenamedNew", "plantedReplacement", "Deprecated"):
            self.assertNotIn(kept, self.proc.stdout)

    def test_each_finding_is_its_symbol_and_the_declaration_that_went(self) -> None:
        self.record("api-extractor", self.repo.sample(SAMPLE), tool_exit=0)
        member = f"{MEMBER}: `dropped: number;` is no longer declared"
        old = "export function plantedSignature(a: number): number;"
        signature = f"{SIGNATURE}: `{old}` is no longer declared"
        self.assertIn(entry(REPORT, "incompatible", member), self.repo.entries())
        self.assertIn(entry(REPORT, "incompatible", signature), self.repo.entries())

    def test_a_committed_report_that_differs_from_the_code_fails(self) -> None:
        self.assertEqual([m["id"] for m in self.row["messages"]], [STALE])
        self.row["base"] = None
        self.run_row()
        self.assert_fails(self.proc, f"{REPORT}: [{STALE}] the committed API report")
        self.assertIn("api_diff.py ts --update", self.proc.stdout)

    def test_a_removed_entry_point_fails_on_each_declaration(self) -> None:
        self.row.update(messages=[], head=None)
        self.run_row()
        declared = self.proc.stdout.count("[incompatible]")
        self.assertGreater(declared, len(BREAKS))
        self.assertIn("./hashurl.plantedDeprecated: `export function", self.proc.stdout)

    def test_a_member_is_named_without_its_modifiers(self) -> None:
        base = (
            "```ts\n\n// @public\nexport interface DiscoveryResult {\n"
            "    readonly exchange: string;\n    static readonly kind?: string;\n}\n\n```\n"
        )
        row = {"entry": "./core", "report": "sdk/ts/api/core.api.md", "messages": []}
        self.run_row(
            {**row, "base": base, "head": base.replace("    readonly exchange: string;\n", "")}
        )
        self.assert_reported("./core.DiscoveryResult.exchange")

    def test_a_new_entry_point_passes(self) -> None:
        self.row.update(messages=[], base=None)
        self.run_row()
        self.assert_passes(self.proc)

    def test_a_report_no_entry_point_has_fails(self) -> None:
        orphan = {
            "id": "orphaned-report",
            "text": "no entry point of sdk/ts/package.json has this report",
        }
        self.row.update(messages=[], base=None)
        self.run_row(
            self.row, {"entry": None, "report": "sdk/ts/api/gone.api.md", "messages": [orphan]}
        )
        self.assert_fails(self.proc, "sdk/ts/api/gone.api.md: [orphaned-report]")

    def test_a_listed_symbol_in_a_major_release_is_allowed(self) -> None:
        self.release("2.0.0", None, changelog(("Unreleased", "Breaking", [MEMBER])), sdk="ts")
        self.row["messages"] = []
        self.run_row()
        self.assert_reported(REMOVED, RENAMED, SIGNATURE, METHOD)

    def test_a_report_without_a_declaration_block_is_refused(self) -> None:
        self.row.update(messages=[], base="## API Report\n")
        self.run_row()
        self.assert_fails(self.proc, "cannot read the output of", "has no ```ts block")

    def test_a_line_that_is_not_an_entry_point_is_refused(self) -> None:
        self.check("api-extractor", '{"report": "x"}\n')
        self.assert_fails(self.proc, "cannot read the output of", "not a line of api_diff.py ts")


WIRE_BASE = (
    'export const ProtocolVersion = "1.0";',
    'export const WellKnownManifestVersion = "1.0";',
    'export const ConnectProtocolVersion = "1";',
)


def wire_row(base: tuple[str, ...], head: tuple[str, ...]) -> dict[str, Any]:
    """Return api_diff.py's line for ./wire: `base` at the release, `head` in the tree."""
    return {
        "entry": "./wire",
        "report": "sdk/ts/api/wire.api.md",
        "messages": [],
        "base": "```ts\n" + "".join(f"{line}\n" for line in base) + "```\n",
        "head": "```ts\n" + "".join(f"{line}\n" for line in head) + "```\n",
    }


class VersionConstantTest(ApiTestCase):
    """A version constant may take a new value within its major; any other change still fails."""

    def setUp(self) -> None:
        super().setUp()
        self.release("1.3.0", "v1.2.1")

    def run_wire(self, base: tuple[str, ...], head: tuple[str, ...]) -> None:
        self.check("api-extractor", json.dumps(wire_row(base, head)) + "\n")

    def test_a_new_version_value_within_its_major_passes_and_another_constant_fails(self) -> None:
        head = (
            'export const ProtocolVersion = "1.1";',
            'export const WellKnownManifestVersion = "1.1";',
            'export const ConnectProtocolVersion = "2";',
        )
        self.run_wire(WIRE_BASE, head)
        self.assert_reported("./wire.ConnectProtocolVersion")
        self.assertIn(
            './wire.ConnectProtocolVersion: value changed from "1" to "2"', self.proc.stdout
        )
        for symbol in ("./wire.ProtocolVersion", "./wire.WellKnownManifestVersion"):
            self.assertIn(f"api: {symbol} is a version constant, so a new value", self.proc.stderr)

    def test_any_other_change_to_a_version_constant_fails_with_its_reason(self) -> None:
        kept = WIRE_BASE[1:]
        cases = (
            (
                "a new major",
                ('export const ProtocolVersion = "2.0";',),
                'value changed from "1.0" to "2.0"',
            ),
            (
                "an empty value",
                ('export const ProtocolVersion = "";',),
                'value changed from "1.0" to ""',
            ),
            (
                "a string to a number",
                ("export const ProtocolVersion = 1;",),
                "is no longer declared",
            ),
            ("a const to a let", ('export let ProtocolVersion = "1.1";',), "is no longer declared"),
            ("a retype", ("export const ProtocolVersion: string;",), "is no longer declared"),
            ("a removal", (), "is no longer declared"),
        )
        for name, head, reason in cases:
            with self.subTest(name=name):
                self.run_wire(WIRE_BASE, (*head, *kept))
                self.assert_reported("./wire.ProtocolVersion")
                self.assertIn(reason, self.proc.stdout)

    def test_a_same_name_declaration_that_went_is_still_reported(self) -> None:
        base = ('export const ProtocolVersion = "1.0";', "export type ProtocolVersion = string;")
        self.run_wire(base, ('export const ProtocolVersion = "1.1";',))
        self.assert_reported("./wire.ProtocolVersion")
        self.assertIn(
            "`export type ProtocolVersion = string;` is no longer declared", self.proc.stdout
        )


if __name__ == "__main__":
    unittest.main()
