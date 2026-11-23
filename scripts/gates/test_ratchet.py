"""Tests for ratchet.py's check and record, run through its command line.

The tool is a scanner in the `lines` format, whose rows name a line or the whole
file; test_ratchet_sizes.py covers the measured sizes, test_ratchet_base_ref.py
the --base-ref check, and the test_ratchet_<tool>.py files each tool's format.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from ratchet_harness import RepoTestCase, entry, row

A = row("pkg/a.go", "errcheck", "Error return value is not checked")
B = row("pkg/b.go", "unused", "func helper is unused")
C = row("pkg/c.go", "vet", "new finding")
CRASH = "import sys; print({row!r}); raise KeyError('scope')"


class RatchetTest(RepoTestCase):
    def test_record_creates_the_baseline_when_the_gate_is_introduced(self) -> None:
        self.record_rows([A, B, B])
        self.assertEqual(
            self.repo.entries(),
            [
                entry("pkg/a.go", "errcheck", "Error return value is not checked"),
                entry("pkg/b.go", "unused", "func helper is unused", 2),
            ],
        )

    def test_check_passes_when_findings_equal_the_baseline(self) -> None:
        self.record_rows([A, B])
        proc = self.repo.run("check", [B, A])
        self.assert_passes(proc)
        self.assertEqual(proc.stdout, "")

    def test_the_command_may_follow_the_options_and_check_is_the_default(self) -> None:
        out = A + "\n"
        self.assert_passes(self.repo.run_output("", "lines", out, "record", tool_exit=0))
        self.assertEqual([e["path"] for e in self.repo.entries()], ["pkg/a.go"])
        self.assert_passes(self.repo.run_output("", "lines", out, tool_exit=0))
        # With no command, a run that lost a finding fails; `record` would have
        # shrunk the baseline and passed.
        proc = self.repo.run_output("", "lines", "", tool_exit=0)
        self.assert_fails(proc, "baseline entries that no longer occur")
        self.assertEqual([e["path"] for e in self.repo.entries()], ["pkg/a.go"])

    def test_check_passes_with_no_findings_and_no_baseline(self) -> None:
        self.assert_passes(self.repo.run("check", []))

    def test_check_fails_on_a_finding_the_baseline_does_not_hold(self) -> None:
        self.record_rows([A])
        proc = self.repo.run("check", [A, B])
        self.assert_fails(proc, "findings not in the baseline", "pkg/b.go: [unused]")
        self.assertNotIn("pkg/a.go", proc.stdout)

    def test_check_fails_when_a_file_gains_another_copy_of_a_baselined_finding(self) -> None:
        self.record_rows([B])
        self.assert_fails(self.repo.run("check", [B, B]), "findings not in the baseline")

    def test_check_fails_on_a_baseline_entry_that_no_longer_occurs(self) -> None:
        self.record_rows([A, B])
        proc = self.repo.run("check", [A])
        self.assert_fails(proc, "baseline entries that no longer occur", "pkg/b.go: [unused]")

    def test_record_removes_fixed_entries_and_never_adds_one(self) -> None:
        self.record_rows([A, B])
        proc = self.repo.run("record", [B, C])
        self.assert_fails(proc, "pkg/c.go: [vet] new finding")
        self.assertEqual([e["path"] for e in self.repo.entries()], ["pkg/b.go"])

    def test_a_scanner_message_is_taken_as_it_is(self) -> None:
        # The `lines` format carries its size in its own column, so a number in a
        # message, a limit or a line reference among them, is part of the message.
        message = "assert f(x) == (3 > 2)  # see line 12"
        self.record_rows([row("pkg/a.py", "noqa", message)])
        self.assertEqual(self.repo.entries(), [entry("pkg/a.py", "noqa", message)])
        changed = row("pkg/a.py", "noqa", message.replace("3 > 2", "4 > 2"))
        proc = self.repo.run("check", [changed])
        self.assert_fails(
            proc, "findings not in the baseline", "baseline entries that no longer occur"
        )


class FailedRunTest(RepoTestCase):
    """A tool that did not run fails the gate, whatever it printed."""

    def test_an_exit_code_the_format_does_not_list_fails_and_shows_the_output(self) -> None:
        self.record_rows([A])
        proc = self.repo.run_output("check", "lines", A + "\n", tool_exit=3, err="it broke\n")
        self.assert_fails(proc, "failed with exit code 3", "it broke", A)

    def test_a_scanner_that_exits_1_fails_even_with_rows(self) -> None:
        # A scanner exits 0 whatever it finds, so exit 1 is a crash.
        self.record_rows([A])
        self.assert_fails(self.repo.run("check", [A], tool_exit=1), "failed with exit code 1")

    def test_a_scanner_that_raises_fails_check_and_record_and_shows_the_traceback(self) -> None:
        self.record_rows([A, B])
        before = self.repo.baseline.read_text()
        for command in ("check", "record"):
            proc = self.repo.script(
                "ratchet.py",
                command,
                "--format",
                "lines",
                "--baseline",
                str(self.repo.baseline),
                "--",
                "python3",
                "-c",
                CRASH.format(row=A),
            )
            self.assert_fails(proc, "failed with exit code 1", "Traceback", "KeyError: 'scope'")
            self.assertEqual(self.repo.baseline.read_text(), before)

    def test_the_tool_stderr_is_shown_when_the_run_passes(self) -> None:
        proc = self.repo.run_output("check", "lines", "", tool_exit=0, err="a warning\n")
        self.assert_passes(proc)
        self.assertIn("a warning", proc.stderr)

    def test_a_row_that_is_not_in_the_lines_format_fails(self) -> None:
        bad_rows = {
            "no tabs in this line": "1 fields",
            "pkg/a.go\trule\t-\tmessage": "4 fields",
            "pkg/a.go\t-\tr\t9x\tmsg": "not a whole number or -: '9x'",
            "pkg/a.go\tx\tr\t-\tmsg": "not a whole number or -: 'x'",
            "pkg/a.go\t0\tr\t-\tmsg": "lines count from 1",
        }
        for bad, reason in bad_rows.items():
            with self.subTest(row=bad):
                proc = self.repo.run("check", [bad])
                self.assert_fails(
                    proc,
                    "cannot read the output",
                    "not a path<TAB>line<TAB>rule<TAB>size<TAB>message line",
                    reason,
                )
                self.assertFalse(self.repo.baseline.exists())


class LineTest(RepoTestCase):
    """A row that names a line is identified by that line's text, as a tool's finding is."""

    def setUp(self) -> None:
        super().setUp()
        self.repo.write("pkg/a.go", "package a\n\nfunc f() { g() }\n", stage=False)
        self.at_f = row("pkg/a.go", "errcheck", "unchecked", line=3)

    def test_a_row_with_a_line_is_baselined_with_that_lines_text(self) -> None:
        self.record_rows([self.at_f])
        self.assertEqual(
            self.repo.entries(),
            [entry("pkg/a.go", "errcheck", "unchecked", source="func f() { g() }")],
        )

    def test_an_edit_above_the_line_keeps_the_entry(self) -> None:
        self.record_rows([self.at_f])
        self.repo.write("pkg/a.go", "package a\n\n// f calls g.\nfunc f() { g() }\n", stage=False)
        moved = row("pkg/a.go", "errcheck", "unchecked", line=4)
        self.assert_passes(self.repo.run("check", [moved]))

    def test_editing_the_line_makes_a_new_finding(self) -> None:
        self.record_rows([self.at_f])
        self.repo.write("pkg/a.go", "package a\n\nfunc f() { h() }\n", stage=False)
        proc = self.repo.run("check", [self.at_f])
        self.assert_fails(
            proc,
            "findings not in the baseline",
            "(at: func f() { h() })",
            "baseline entries that no longer occur",
            "(at: func f() { g() })",
        )

    def test_a_row_past_the_end_of_its_file_fails(self) -> None:
        past = row("pkg/a.go", "errcheck", "unchecked", line=9)
        self.assert_fails(
            self.repo.run("check", [past]), "points at line 9 of pkg/a.go, which has 4 lines"
        )


class BaselineFileTest(RepoTestCase):
    """A baseline file that ratchet.py did not write is refused, not read loosely."""

    def test_an_entry_listed_twice_is_refused(self) -> None:
        e = entry("pkg/a.go", "errcheck", "Error return value is not checked")
        self.repo.write_entries([e, e])
        self.assert_fails(self.repo.run("check", [A, A]), "an entry is listed twice")

    def test_an_entry_with_a_key_the_baseline_does_not_use_is_refused(self) -> None:
        e = entry("pkg/a.go", "errcheck", "Error return value is not checked")
        self.repo.write_entries([{**e, "size": 90}])
        self.assert_fails(self.repo.run("check", [A]), "keys a baseline does not use: ['size']")

    def test_an_entry_with_a_size_per_finding_missing_is_refused(self) -> None:
        sized = row("pkg/a.go", "funlen", "over the limit", 90)
        self.record_rows([sized, sized])
        entries = self.repo.entries()
        entries[0]["sizes"] = [90]
        self.repo.write_entries(entries)
        self.assert_fails(self.repo.run("check", [sized, sized]), "1 sizes for count 2")


if __name__ == "__main__":
    unittest.main()
