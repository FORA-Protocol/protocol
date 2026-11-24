"""Tests for re-keying a gate's baseline when the gate's tool changes.

A new version of a tool, or a new config, can word its findings differently, give
them new rule names or point at another line, and measure sizes differently, while
the code stays the same. The --base-ref commands re-key the baseline when a tool
file the gate's scripts declared at the merge base (--tool-file), or the reader
of the gate's format in formats.py, changed since, and the change edits nothing
else but baselines: no other file, and nothing of a file named in part beyond the
part. Nothing else unlocks it, and a file may not gain findings. The lockfile
parts are tested in test_ratchet_lock_tools.py.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ratchet_harness import (
    BASELINE,
    CHANGED,
    FORMATS,
    GATE_SCRIPT,
    NAMES_TOOL,
    NEW,
    NOT_REKEYED,
    F,
    H,
    ToolChangeCase,
    entry,
    names_tools,
    row,
)

if TYPE_CHECKING:
    import subprocess

PART = "tools.lock#package.lint"
# The tool is not the lockfile's first package, so a part that took the first element of a
# list instead of the one with the step's name would read `app`.
LOCK = (
    '[[package]]\nname = "app"\nversion = "{app}"\n'
    + '[[package]]\nname = "lint"\nversion = "{lint}"\n'
)
# An edit to another format's reader in formats.py, which leaves its behavior alone.
OTHER_READER = ('if f["severity"] != "error":', 'if f["severity"] not in ("error",):')


class ToolChangeTest(ToolChangeCase):
    def test_a_tool_change_of_its_own_rekeys_the_baseline(self) -> None:
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

    def test_a_tool_change_with_an_edit_to_another_file_rekeys_nothing(self) -> None:
        # The tool now reports a new finding in pkg/a.go, which the change does not
        # edit, that an edit to pkg/b.go caused: a type checker reports a call in
        # one file that a changed signature in another breaks.
        self.repo.write("pkg/b.go", "package a\n\nfunc g(x, y int) {}\n")
        self.change_tool()
        self.assert_no_swap("edits pkg/b.go")

    def test_a_tool_file_the_tool_also_reads_keeps_its_exact_entries(self) -> None:
        # A tool can read its own config: ruff lints pyproject.toml. The change edits
        # tool.cfg, so a reworded finding in it is a new finding.
        in_config = entry("tool.cfg", "old-rule", "old message", source="level = 1")
        self.add_on_main("tool.cfg", "version = 1\nlevel = 1\n", [in_config])
        self.repo.write("tool.cfg", "version = 2\nlevel = 1\n")
        rows = [*self.reworded(), row("tool.cfg", "new-rule", "new message", line=2)]
        self.assert_fails(self.base("record", rows), NEW, "tool.cfg: [new-rule]")

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
            "pkg/a.go": f"is not passed by the gate script {GATE_SCRIPT}",
            BASELINE: "is the baseline",
            "tool.cfg#missing": "names a part that tool.cfg does not have",
            "pkg/a.go#f": "cannot be read",
        }
        for tool, why in refusals.items():
            with self.subTest(tool=tool):
                proc = self.repo.run("check", [], "--gate", GATE_SCRIPT, "--tool-file", tool)
                self.assert_fails(proc, f"--tool-file {tool} {why}", code=2)
        proc = self.repo.run("check", [], "--tool-file", "tool.cfg")
        self.assert_fails(proc, "--tool-file tool.cfg needs --gate", code=2)


class ReaderChangeTest(ToolChangeCase):
    """The reader of the gate's format in formats.py is a tool file of every gate."""

    def test_an_edit_to_the_formats_reader_rekeys_the_baseline(self) -> None:
        self.edit_formats("LINE_FIELDS = 5\n", "LINE_FIELDS = 4 + 1\n")
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn(f"({FORMATS}#lines)", proc.stderr)

    def test_an_edit_to_measure_rekeys_the_baseline(self) -> None:
        # measure reads the messages of every format, so it is part of each format's reader.
        self.edit_formats('LINE_REF.sub("line N", message)', 'LINE_REF.sub("line " + "N", message)')
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn(f"({FORMATS}#lines)", proc.stderr)

    def test_a_comment_in_formats_py_is_not_a_change_to_the_reader(self) -> None:
        self.edit_formats("LINE_FIELDS = 5\n", "LINE_FIELDS = 5  # the fields of a row\n")
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")

    def test_an_edit_to_another_formats_reader_is_not_a_change_to_this_one(self) -> None:
        self.edit_formats(*OTHER_READER)
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")

    def with_reader_edit(self, old: str, new: str) -> subprocess.CompletedProcess[str]:
        """Edit the reader of the gate's format and `old` to `new` elsewhere in formats.py,
        then run `record --base-ref` on the reworded findings."""
        self.edit_formats("LINE_FIELDS = 5\n", "LINE_FIELDS = 4 + 1\n")
        self.edit_formats(old, new)
        return self.base("record", self.reworded())

    def test_an_edit_to_the_reader_and_to_another_reader_rekeys_nothing(self) -> None:
        proc = self.with_reader_edit(*OTHER_READER)
        self.assert_fails(proc, NEW, NOT_REKEYED, f"edits {FORMATS} beyond the tool's part")

    def test_an_edit_to_the_reader_and_to_another_formats_entry_rekeys_nothing(self) -> None:
        ruff = "found=frozenset({1}), sizes=(OVER_LIMIT,)),"
        proc = self.with_reader_edit(ruff, ruff.replace("(OVER_LIMIT,)", "tuple([OVER_LIMIT])"))
        self.assert_fails(proc, NEW, NOT_REKEYED, f"edits {FORMATS} beyond the tool's part")

    def test_an_edit_to_the_reader_and_to_code_no_reader_runs_rekeys_nothing(self) -> None:
        # Finding is the ratchet's own: a type checker reports in ratchet.py and baseline.py
        # what an edit to it breaks there.
        finding = '    message: str\n    source: str = ""\n'
        proc = self.with_reader_edit(
            finding, f"{finding}\n    def unused(self) -> None:\n        pass\n"
        )
        self.assert_fails(proc, NEW, NOT_REKEYED, f"edits {FORMATS} beyond the tool's part")

    def test_an_edit_to_the_reader_and_a_comment_elsewhere_rekeys_the_baseline(self) -> None:
        # A comment changes no finding in another file.
        old = "# `(N > M)`: the measured value"
        self.assert_passes(self.with_reader_edit(old, "# `(N > M)`: the size measured"))

    def test_a_reader_that_needs_a_new_import_changes_only_itself(self) -> None:
        self.edit_formats("import re\n", "import re\nimport string\n")
        self.edit_formats("LINE_FIELDS = 5\n", "LINE_FIELDS = len(string.digits) - 5\n")
        self.assert_passes(self.base("record", self.reworded()))


class NewlyNamedToolFileTest(ToolChangeCase):
    """On main, the gate script does not pass tool.cfg yet; it only mentions it.

    A comment names the file, another spells the argument that would pass it, and
    the tool command is given it as an argument of its own.
    """

    gate_text = (
        "# reads tool.cfg\n"
        f'exec ratchet.py --baseline {BASELINE} "$@" -- tool --config tool.cfg'
        "  # later: --tool-file tool.cfg\n"
    )

    def test_a_tool_file_the_gate_script_only_mentions_is_refused(self) -> None:
        self.change_tool()
        proc = self.base("record", self.reworded())
        self.assert_fails(proc, "--tool-file tool.cfg is not passed by the gate script", code=2)

    def test_a_tool_file_first_named_in_the_change_unlocks_nothing(self) -> None:
        self.repo.write(GATE_SCRIPT, NAMES_TOOL)
        self.change_tool()
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")
        self.assert_fails(self.base("check", self.reworded()), NEW, "[new-rule]")


class ToolFilePartTest(ToolChangeCase):
    """The gate passes the part of a TOML file that pins its tool, not the whole file.

    tools.lock is not a lockfile npm or uv writes, so its part is a key path; the rest of
    the file is not the tool.
    """

    gate_text = names_tools(PART)
    tool_files = (PART,)

    def setUp(self) -> None:
        super().setUp()
        self.add_on_main("tools.lock", LOCK.format(lint="1", app="1"))

    def write_lock(self, *, lint: str, app: str) -> None:
        self.repo.write("tools.lock", LOCK.format(lint=lint, app=app))

    def test_a_new_version_of_the_tool_rekeys_the_baseline(self) -> None:
        self.write_lock(lint="2", app="1")
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn(f"({PART})", proc.stderr)

    def test_another_entry_of_the_lockfile_is_not_a_change_to_the_tool(self) -> None:
        self.write_lock(lint="1", app="2")
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")

    def test_a_tool_change_with_an_edit_to_the_rest_of_its_file_rekeys_nothing(self) -> None:
        self.write_lock(lint="2", app="2")
        proc = self.base("record", self.reworded())
        self.assert_fails(proc, NEW, NOT_REKEYED, "edits tools.lock beyond the tool's part")

    def test_a_finding_an_edit_beyond_the_tool_brought_takes_no_entry(self) -> None:
        # app is the code's own dependency: its new version can break a call in pkg/a.go.
        self.write_lock(lint="2", app="2")
        self.assert_no_swap("edits tools.lock beyond the tool's part")

    def test_a_second_element_with_the_tools_name_is_beyond_the_tool(self) -> None:
        # The part names the first element called lint, and only that one.
        second = '[[package]]\nname = "lint"\nversion = "9"\n'
        self.repo.write("tools.lock", LOCK.format(lint="2", app="1") + second)
        proc = self.base("record", self.reworded())
        self.assert_fails(proc, NOT_REKEYED, "edits tools.lock beyond the tool's part")


class WholeFileAndPartTest(ToolChangeCase):
    """The gate passes tool.cfg whole and a part of it: the whole file is the tool."""

    gate_text = names_tools("tool.cfg", "tool.cfg#version")
    tool_files = ("tool.cfg", "tool.cfg#version")

    def test_an_edit_beyond_the_part_of_a_file_also_named_whole_rekeys_the_baseline(
        self,
    ) -> None:
        self.repo.write("tool.cfg", "version = 1\nlevel = 2\n")
        self.assert_passes(self.base("record", self.reworded()))


class HelperToolFileTest(ToolChangeCase):
    """The helper the gate script runs passes tool.cfg, as a toolchain's helper passes its pin."""

    gate_text = f'exec scripts/gates/helper.sh ratchet {BASELINE} "$@" -- tool\n'

    def setUp(self) -> None:
        super().setUp()
        self.add_on_main("scripts/gates/helper.sh", "TOOL_FILES=(\n  --tool-file tool.cfg\n)\n")

    def test_a_tool_file_the_helper_passes_rekeys_the_baseline(self) -> None:
        self.change_tool()
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn(CHANGED, proc.stderr)


if __name__ == "__main__":
    unittest.main()
