"""Tests for re-keying a gate's baseline when the gate's tool changes.

A new version of a tool, or a new config, can word its findings differently, give
them new rule names or point at another line, and measure sizes differently, while
the code stays the same. The --base-ref commands re-key the entries of each file
the change does not edit when a tool file the gate script named at the merge base
(--tool-file), or the reader of every tool's output (formats.py), changed since.
Nothing else unlocks it, and a file may not gain findings.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ratchet_harness import BASELINE, GATE_SCRIPT, RepoTestCase, entry, row

if TYPE_CHECKING:
    import subprocess

F = "func f() { g() }"
H = "func h() { k() }"
NAMES_TOOL = f'exec ratchet.py --baseline {BASELINE} --tool-file tool.cfg "$@" -- tool\n'
CHANGED = "the gate's tool changed since main (tool.cfg)"
NEW = "findings not in the baseline"


class ToolChangeCase(RepoTestCase):
    """On main, the gate names tool.cfg, and pkg/a.go has two findings worded the old way."""

    gate_text = NAMES_TOOL

    def setUp(self) -> None:
        super().setUp()
        self.repo.write(GATE_SCRIPT, self.gate_text)
        self.repo.write("tool.cfg", "version = 1\n")
        self.repo.write("pkg/a.go", f"package a\n\n{F}\n{H}\n")
        self.record_rows(
            [self.at("old-rule", "old message", F, 15), self.at("old-rule", "old message", H, 9)]
        )
        self.repo.branch_off_main("introduce the gate")

    def at(self, rule: str, message: str, text: str, size: int) -> str:
        lines = (self.repo.root / "pkg/a.go").read_text().split("\n")
        return row("pkg/a.go", rule, message, size, line=lines.index(text) + 1)

    def reworded(self) -> list[str]:
        """The same two findings as a new tool reports them, the first measured higher."""
        return [self.at("new-rule", "new message", F, 17), self.at("new-rule", "new message", H, 9)]

    def base(self, command: str, rows: list[str]) -> subprocess.CompletedProcess[str]:
        refs = ("--base-ref", "main", "--gate", GATE_SCRIPT)
        return self.repo.run(command, rows, *refs, "--tool-file", "tool.cfg")

    def change_tool(self) -> None:
        self.repo.write("tool.cfg", "version = 2\n")


class ToolChangeTest(ToolChangeCase):
    def test_a_tool_change_rekeys_a_file_the_change_does_not_edit(self) -> None:
        self.change_tool()
        rows = self.reworded()
        proc = self.base("record", rows)
        self.assert_passes(proc)
        self.assertIn(CHANGED, proc.stderr)
        self.assertIn("(was [old-rule] old message)", proc.stderr)
        self.assertEqual(
            self.repo.entries(),
            [
                entry("pkg/a.go", "new-rule", "new message", source=F, sizes=[17]),
                entry("pkg/a.go", "new-rule", "new message", source=H, sizes=[9]),
            ],
        )
        self.assert_passes(self.base("check", rows))

    def test_without_a_tool_change_a_reworded_finding_is_new(self) -> None:
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")

    def test_an_edit_to_the_gate_script_alone_unlocks_nothing(self) -> None:
        self.repo.write(GATE_SCRIPT, "# runs the tool\n" + NAMES_TOOL)
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")

    def test_an_edit_to_the_reader_of_tool_output_unlocks_rekeying(self) -> None:
        formats = self.repo.root / "scripts/gates/formats.py"
        self.repo.write("scripts/gates/formats.py", formats.read_text() + "# reads more\n")
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn("(scripts/gates/formats.py)", proc.stderr)

    def test_a_file_the_change_edits_keeps_its_exact_entries(self) -> None:
        self.change_tool()
        self.repo.write("pkg/a.go", f"package a\n\n// edited\n{F}\n{H}\n")
        proc = self.base("record", self.reworded())
        self.assert_fails(proc, NEW, "[new-rule]", "a file it edits keeps its exact entries")

    def test_a_file_may_not_gain_a_finding_in_a_tool_change(self) -> None:
        self.change_tool()
        rows = [*self.reworded(), row("pkg/a.go", "new-check", "found", line=1)]
        self.assert_fails(self.base("record", rows), NEW, "[new-check]")
        self.assertEqual([e["rule"] for e in self.repo.entries()], ["new-rule", "new-rule"])
        self.repo.write_entries(
            [
                entry("pkg/a.go", "new-check", "found", source="package a"),
                entry("pkg/a.go", "new-rule", "new message", source=F, sizes=[17]),
                entry("pkg/a.go", "new-rule", "new message", source=H, sizes=[9]),
            ]
        )
        self.assert_fails(self.base("check", rows), "baseline entries added since main")

    def test_a_tool_file_is_refused_unless_the_gate_names_it_and_it_is_not_the_baseline(
        self,
    ) -> None:
        refusals = {
            "missing.cfg": "does not exist",
            "pkg/a.go": f"is not named by the gate script {GATE_SCRIPT}",
            BASELINE: "is the baseline",
        }
        for tool, why in refusals.items():
            with self.subTest(tool=tool):
                proc = self.repo.run("check", [], "--gate", GATE_SCRIPT, "--tool-file", tool)
                self.assert_fails(proc, f"--tool-file {tool} {why}", code=2)
        proc = self.repo.run("check", [], "--tool-file", "tool.cfg")
        self.assert_fails(proc, "--tool-file tool.cfg needs --gate", code=2)


class NewlyNamedToolFileTest(ToolChangeCase):
    """On main, the gate script does not name tool.cfg yet."""

    gate_text = f'exec ratchet.py --baseline {BASELINE} "$@" -- tool\n'

    def test_a_tool_file_first_named_in_the_change_unlocks_nothing(self) -> None:
        self.repo.write(GATE_SCRIPT, NAMES_TOOL)
        self.change_tool()
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")


if __name__ == "__main__":
    unittest.main()
