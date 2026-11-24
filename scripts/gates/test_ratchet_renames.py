"""Tests for carrying a whole-file entry across a rename or a copy, with `record --base-ref`.

A finding about a whole file, such as a file's length, has no line to move with,
so only git can say where its file went. `record --base-ref REF` and the
--base-ref check ask git what changed since the merge base: an entry follows its
file when git sees the file renamed, and a file git sees as a copy takes the entry
of its source when the source no longer has that finding.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ratchet_harness import GATE_SCRIPT, RepoTestCase, entry, row

if TYPE_CHECKING:
    import subprocess

RULE, MESSAGE = "file-length", "over the limit"


def lines(count: int, start: int = 0) -> str:
    """Return `count` distinct lines of code, numbered from `start`."""
    return "".join(f"var v{i} = {i}\n" for i in range(start, start + count))


def long_file(path: str, size: int) -> str:
    """Return the row of a whole-file finding of `path`, at `size` lines."""
    return row(path, RULE, MESSAGE, size)


class WholeFileCase(RepoTestCase):
    """On main, pkg/long.go has 40 lines and a baselined whole-file finding of size 40."""

    def setUp(self) -> None:
        super().setUp()
        self.repo.introduce_gate()
        self.repo.write("pkg/long.go", lines(40))
        self.record_rows([long_file("pkg/long.go", 40)])
        self.repo.branch_off_main("introduce the gate")

    def record_base(self, rows: list[str]) -> subprocess.CompletedProcess[str]:
        return self.repo.run_base("record", rows)

    def check_base(self, rows: list[str]) -> subprocess.CompletedProcess[str]:
        return self.repo.run_base("check", rows)

    def split_off(self, copied: int) -> None:
        """Move the first `copied` lines of pkg/long.go to pkg/split.go; git sees a copy."""
        self.repo.write("pkg/split.go", lines(copied))
        self.repo.write("pkg/long.go", lines(40 - copied, start=copied))
        status = self.repo.git("diff", "--name-status", "-M", "-C", "main")
        self.assertIn("C", [s[0] for s in status.split()], status)


class RenameTest(WholeFileCase):
    def test_a_renamed_file_keeps_its_whole_file_entry(self) -> None:
        self.repo.git("mv", "pkg/long.go", "pkg/longer.go")
        rows = [long_file("pkg/longer.go", 40)]
        self.assert_fails(self.repo.run("check", rows), "`record --base-ref REF` carries")
        proc = self.record_base(rows)
        self.assert_passes(proc)
        self.assertIn(f"pkg/longer.go: [{RULE}] {MESSAGE} (from pkg/long.go)", proc.stderr)
        self.assertEqual(self.repo.entries(), [entry("pkg/longer.go", RULE, MESSAGE, sizes=[40])])
        self.assert_passes(self.check_base(rows))

    def test_the_hint_names_a_copy_only_for_a_format_that_carries_one(self) -> None:
        self.repo.git("mv", "pkg/long.go", "pkg/longer.go")
        out = long_file("pkg/longer.go", 40) + "\n"
        for fmt, moved in (("lines", "renamed or copied"), ("suppressions", "renamed")):
            with self.subTest(fmt=fmt):
                proc = self.repo.run_output("check", fmt, out, tool_exit=0)
                self.assert_fails(proc, f"if a file was {moved}, or the gate's tool changed")

    def test_a_renamed_file_that_grew_fails(self) -> None:
        self.repo.git("mv", "pkg/long.go", "pkg/longer.go")
        rows = [long_file("pkg/longer.go", 45)]
        self.assert_fails(self.record_base(rows), "grew", "(40, 45)")
        self.repo.write_entries([entry("pkg/longer.go", RULE, MESSAGE, sizes=[45])])
        self.assert_fails(self.check_base(rows), "baseline sizes raised since main", "(40, 45)")

    def test_without_the_base_ref_record_does_not_follow_a_rename(self) -> None:
        self.repo.git("mv", "pkg/long.go", "pkg/longer.go")
        proc = self.repo.run("record", [long_file("pkg/longer.go", 40)])
        self.assert_fails(proc, "findings not in the baseline", "pkg/longer.go")

    def test_a_copy_takes_the_entry_its_source_no_longer_has(self) -> None:
        self.split_off(30)
        rows = [long_file("pkg/split.go", 30)]
        proc = self.record_base(rows)
        self.assert_passes(proc)
        self.assertIn(f"pkg/split.go: [{RULE}] {MESSAGE} (from pkg/long.go)", proc.stderr)
        self.assert_passes(self.check_base(rows))

    def test_a_copy_whose_source_keeps_the_finding_takes_nothing(self) -> None:
        self.split_off(30)
        rows = [long_file("pkg/long.go", 10), long_file("pkg/split.go", 30)]
        self.assert_fails(self.record_base(rows), "findings not in the baseline", "pkg/split.go")

    def test_an_unrelated_new_file_takes_nothing(self) -> None:
        self.repo.git("rm", "-q", "pkg/long.go")
        self.repo.write("pkg/other.go", "".join(f"const c{i} = {i}\n" for i in range(40)))
        rows = [long_file("pkg/other.go", 40)]
        self.assert_fails(self.record_base(rows), "findings not in the baseline", "pkg/other.go")


class RecordBaseRefTest(WholeFileCase):
    def test_a_deleted_baseline_is_rebuilt_from_what_the_base_allows(self) -> None:
        self.repo.baseline.unlink()
        rows = [long_file("pkg/long.go", 40), row("pkg/x.go", "header", "no header")]
        self.assert_fails(self.record_base(rows), "findings not in the baseline", "pkg/x.go")
        self.assertEqual(self.repo.entries(), [entry("pkg/long.go", RULE, MESSAGE, sizes=[40])])

    def test_a_size_the_branch_lowered_stays_lowered(self) -> None:
        self.record_rows([long_file("pkg/long.go", 35)])
        proc = self.record_base([long_file("pkg/long.go", 38)])
        self.assert_fails(proc, "grew", "(35, 38)")


class NewGateTest(RepoTestCase):
    def test_a_gate_new_since_the_base_records_everything(self) -> None:
        self.repo.write("pkg/long.go", lines(40))
        self.repo.branch_off_main("before the gate")
        self.repo.introduce_gate()
        rows = [long_file("pkg/long.go", 40), row("pkg/x.go", "header", "no header")]
        proc = self.repo.run_base("record", rows)
        self.assert_passes(proc)
        self.assertIn(f"{GATE_SCRIPT} is new since main", proc.stderr)
        self.assertEqual(len(self.repo.entries()), 2)


if __name__ == "__main__":
    unittest.main()
