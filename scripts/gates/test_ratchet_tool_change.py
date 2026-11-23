"""Tests for re-keying a gate's baseline when the gate's tool changes.

A new version of a tool, or a new config, can word its findings differently, give
them new rule names or point at another line, and measure sizes differently, while
the code stays the same. The --base-ref commands re-key the baseline when a tool
file the gate's scripts declared at the merge base (--tool-file), or the reader
of the gate's format in formats.py, changed since, and the change edits nothing
else but baselines. Nothing else unlocks it, and a file may not gain findings.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ratchet_harness import A_GO, BASELINE, GATE_SCRIPT, F, H, RepoTestCase, entry, row

if TYPE_CHECKING:
    import subprocess

NAMES_TOOL = f'exec ratchet.py --baseline {BASELINE} --tool-file tool.cfg "$@" -- tool\n'
CHANGED = "the gate's tool changed since main (tool.cfg)"
NOT_REKEYED = "so nothing is re-keyed"
NEW = "findings not in the baseline"
FORMATS = "scripts/gates/formats.py"
PART = "tools.lock#package.lint"
LOCK = (
    '[[package]]\nname = "lint"\nversion = "{lint}"\n'
    + '[[package]]\nname = "app"\nversion = "{app}"\n'
)


class ToolChangeCase(RepoTestCase):
    """On main, the gate names tool.cfg, and pkg/a.go has two findings worded the old way."""

    gate_text = NAMES_TOOL

    def setUp(self) -> None:
        super().setUp()
        self.repo.write(GATE_SCRIPT, self.gate_text)
        self.repo.write("tool.cfg", "version = 1\n")
        self.repo.write("pkg/a.go", A_GO)
        self.record_rows(self.old())
        self.repo.branch_off_main("introduce the gate")

    def at(self, rule: str, message: str, text: str, size: int | None = None) -> str:
        return self.repo.row_at("pkg/a.go", rule, message, text, size)

    def old(self) -> list[str]:
        """The two findings as the tool on main reports them."""
        return [self.at("old-rule", "old message", F, 15), self.at("old-rule", "old message", H, 9)]

    def reworded(self) -> list[str]:
        """The same two findings as a new tool reports them, the first measured higher."""
        new = "new-rule", "new message"
        return [self.at(*new, F, 17), self.at(*new, H, 9)]

    def base(self, command: str, rows: list[str]) -> subprocess.CompletedProcess[str]:
        return self.repo.run_base(command, rows, "--tool-file", "tool.cfg")

    def change_tool(self) -> None:
        self.repo.write("tool.cfg", "version = 2\n")

    def add_on_main(
        self, path: str, text: str, entries: list[dict[str, object]] | None = None
    ) -> None:
        """Commit `path`, holding `text`, on main, with `entries` added to the baseline,
        and merge it into the topic branch."""
        self.repo.git("checkout", "-q", "main")
        self.repo.write(path, text)
        if entries:
            self.repo.write_entries([*self.repo.entries(), *entries])
        self.repo.commit(f"add {path}")
        self.repo.git("checkout", "-q", "topic")
        self.repo.git("merge", "-q", "main")

    def edit_formats(self, old: str, new: str) -> None:
        """Replace `old` by `new` in the copy of formats.py, which must hold it once."""
        text = (self.repo.root / FORMATS).read_text()
        self.assertEqual(text.count(old), 1, old)
        self.repo.write(FORMATS, text.replace(old, new))


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
        rows = [self.at("old-rule", "old message", F, 15), self.at("call-arg", "missing y", H)]
        proc = self.base("record", rows)
        self.assert_fails(proc, NEW, "[call-arg]", NOT_REKEYED, "edits pkg/b.go")
        self.repo.write_entries(
            [
                entry("pkg/a.go", "call-arg", "missing y", source=H),
                entry("pkg/a.go", "old-rule", "old message", source=F, sizes=[15]),
            ]
        )
        added = "baseline entries added since main"
        self.assert_fails(self.base("check", rows), added, "[call-arg]")

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

    def test_a_comment_in_formats_py_is_not_a_change_to_the_reader(self) -> None:
        self.edit_formats("LINE_FIELDS = 5\n", "LINE_FIELDS = 5  # the fields of a row\n")
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")

    def test_an_edit_to_another_formats_reader_is_not_a_change_to_this_one(self) -> None:
        self.edit_formats('if f["severity"] != "error":', 'if f["severity"] not in ("error",):')
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")


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
    """The gate passes the part of a lockfile that pins its tool, not the whole file."""

    gate_text = f'exec ratchet.py --baseline {BASELINE} --tool-file {PART} "$@" -- tool\n'

    def setUp(self) -> None:
        super().setUp()
        self.add_on_main("tools.lock", LOCK.format(lint="1", app="1"))

    def write_lock(self, *, lint: str, app: str) -> None:
        self.repo.write("tools.lock", LOCK.format(lint=lint, app=app))

    def base(self, command: str, rows: list[str]) -> subprocess.CompletedProcess[str]:
        return self.repo.run_base(command, rows, "--tool-file", PART)

    def test_a_new_version_of_the_tool_rekeys_the_baseline(self) -> None:
        self.write_lock(lint="2", app="1")
        proc = self.base("record", self.reworded())
        self.assert_passes(proc)
        self.assertIn(f"({PART})", proc.stderr)

    def test_another_entry_of_the_lockfile_is_not_a_change_to_the_tool(self) -> None:
        self.write_lock(lint="1", app="2")
        self.assert_fails(self.base("record", self.reworded()), NEW, "[new-rule]")


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
