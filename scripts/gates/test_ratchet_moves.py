"""Tests for carrying a baseline entry when its finding's code moves to another file.

A finding that points at a line is identified by its file, so moving its code
makes it a new finding and its entry one that no longer occurs. `record` carries
the entry to the finding's new file when the finding moved with its line (same
rule, message and line text), and the --base-ref check accepts the carried entry,
so a split or a move keeps its entries while the debt can never grow.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from ratchet_harness import A_GO, F, H, RepoTestCase, entry, row

if TYPE_CHECKING:
    import subprocess

MOVED = "findings that moved to another file"


class MoveCase(RepoTestCase):
    """On main, pkg/a.go holds two baselined findings, at the lines F and H."""

    rule, message = "errcheck", "unchecked"
    f_size: int | None = None
    h_size: int | None = None

    def setUp(self) -> None:
        super().setUp()
        self.repo.introduce_gate()
        self.repo.write("pkg/a.go", A_GO)
        self.record_rows([self.at("pkg/a.go", F, self.f_size), self.at("pkg/a.go", H, self.h_size)])
        self.repo.branch_off_main("introduce the gate")

    def at(self, path: str, text: str, size: int | None = None) -> str:
        """Return the row of a finding at the line `text` of `path`, as the file is now."""
        return self.repo.row_at(path, self.rule, self.message, text, size)

    def move_h_to(self, path: str, text: str = H, prefix: str = "") -> None:
        """Move the line H out of pkg/a.go to `path`, as `text`, after `prefix`."""
        self.repo.write("pkg/a.go", f"package a\n\n{F}\n")
        self.repo.write(path, f"{prefix}{text}\n")

    def check_base(self, rows: list[str]) -> subprocess.CompletedProcess[str]:
        return self.repo.run_base("check", rows)


class MoveTest(MoveCase):
    def test_a_split_carries_the_moved_finding_and_keeps_the_rest(self) -> None:
        self.move_h_to("pkg/b.go")
        rows = [self.at("pkg/a.go", F), self.at("pkg/b.go", H)]
        self.assert_fails(self.repo.run("check", rows), MOVED, "pkg/b.go: [errcheck]")
        proc = self.repo.run("record", rows)
        self.assert_passes(proc)
        self.assertIn(f"pkg/b.go: [errcheck] unchecked (at: {H}) (from pkg/a.go)", proc.stderr)
        self.assertEqual(
            self.repo.entries(),
            [
                entry("pkg/a.go", self.rule, self.message, source=F),
                entry("pkg/b.go", self.rule, self.message, source=H),
            ],
        )
        self.assert_passes(self.repo.run("check", rows))
        proc = self.check_base(rows)
        self.assert_passes(proc)
        self.assertIn("(from pkg/a.go)", proc.stderr)

    def test_a_move_into_a_file_that_exists_is_carried(self) -> None:
        self.repo.write("pkg/b.go", "package a\n")
        self.repo.commit("pkg/b.go")
        self.move_h_to("pkg/b.go", prefix="package a\n\n")
        rows = [self.at("pkg/a.go", F), self.at("pkg/b.go", H)]
        self.record_rows(rows)
        self.assert_passes(self.check_base(rows))

    def test_a_line_edited_as_it_moved_is_a_new_finding(self) -> None:
        edited = "func h() { k(1) }"
        self.move_h_to("pkg/b.go", text=edited)
        rows = [self.at("pkg/a.go", F), self.at("pkg/b.go", edited)]
        proc = self.repo.run("record", rows)
        self.assert_fails(proc, "findings not in the baseline", f"(at: {edited})")
        self.assertNotIn("pkg/b.go", [e["path"] for e in self.repo.entries()])

    def test_a_copied_line_is_a_new_finding(self) -> None:
        self.repo.write("pkg/b.go", f"{H}\n")
        rows = [self.at("pkg/a.go", F), self.at("pkg/a.go", H), self.at("pkg/b.go", H)]
        self.assert_fails(self.repo.run("record", rows), "findings not in the baseline")
        hand_made = [*self.repo.entries(), entry("pkg/b.go", self.rule, self.message, source=H)]
        self.repo.write_entries(hand_made)
        self.assert_fails(self.check_base(rows), "baseline entries added since main", "pkg/b.go")

    def test_one_moved_finding_carries_one_entry(self) -> None:
        self.move_h_to("pkg/b.go")
        self.repo.write("pkg/c.go", f"{H}\n")
        rows = [self.at("pkg/a.go", F), self.at("pkg/b.go", H), self.at("pkg/c.go", H)]
        proc = self.repo.run("record", rows)
        self.assert_fails(proc, "findings not in the baseline", "pkg/c.go: [errcheck]")
        hand_made = [*self.repo.entries(), entry("pkg/c.go", self.rule, self.message, source=H)]
        self.repo.write_entries(hand_made)
        self.assert_fails(self.check_base(rows), "baseline entries added since main", "pkg/c.go")

    def test_a_finding_about_a_whole_file_does_not_move_with_a_line(self) -> None:
        self.repo.write_entries([*self.repo.entries(), entry("pkg/a.go", "header", "no header")])
        moved = row("pkg/b.go", "header", "no header")
        rows = [self.at("pkg/a.go", F), self.at("pkg/a.go", H), moved]
        self.assert_fails(self.repo.run("record", rows), "findings not in the baseline", "pkg/b.go")


class SizedMoveTest(MoveCase):
    """Findings that measure a size: a moved one may not be worse than its entry."""

    rule, message = "funlen", "too long"
    f_size, h_size = 70, 90

    def test_a_moved_finding_keeps_its_size(self) -> None:
        self.move_h_to("pkg/b.go")
        rows = [self.at("pkg/a.go", F, 70), self.at("pkg/b.go", H, 85)]
        self.record_rows(rows)
        self.assertEqual(
            self.repo.entries()[1],
            entry("pkg/b.go", self.rule, self.message, source=H, sizes=[85]),
        )
        self.assert_passes(self.check_base(rows))

    def test_a_moved_finding_that_grew_fails(self) -> None:
        self.move_h_to("pkg/b.go")
        rows = [self.at("pkg/a.go", F, 70), self.at("pkg/b.go", H, 95)]
        self.assert_fails(self.repo.run("record", rows), "grew", "(90, 95)")
        entries = self.repo.entries()
        entries[1]["sizes"] = [95]
        self.repo.write_entries(entries)
        self.assert_fails(self.check_base(rows), "baseline sizes raised since main", "(90, 95)")


if __name__ == "__main__":
    unittest.main()
