"""Tests for ratchet.py's --base-ref check, run through its command line in a git repository.

The check finds the gate script that names the baseline, and compares the
baseline against the one that gate named at the ref.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from ratchet_harness import BASELINE, GATE_SCRIPT, RepoTestCase, entry, row

A = row("pkg/a.go", "errcheck", "Error return value is not checked")
B = row("pkg/b.go", "unused", "func helper is unused")
C = row("pkg/c.go", "vet", "new finding")
ADDED = "baseline entries added since main"
RAISED = "baseline sizes raised since main"


def funlen(size: int) -> str:
    return row("pkg/a.go", "funlen", "Function 'f' is too long (N > 80)", size)


class BaseRefTest(RepoTestCase):
    def introduce_gate(self, findings: list[str]) -> None:
        """Introduce the gate with a baseline of `findings` on main; continue on a branch."""
        self.repo.introduce_gate()
        self.record_rows(findings)
        self.repo.branch_off_main("introduce the gate")

    def add_b_by_hand(self) -> None:
        self.repo.write_entries(
            [*self.repo.entries(), entry("pkg/b.go", "unused", "func helper is unused")]
        )

    def check(self, findings: list[str], ref: str = "main", gate: str = GATE_SCRIPT) -> None:
        self.proc = self.repo.run("check", findings, "--base-ref", ref, "--gate", gate)

    def test_a_baseline_grown_by_hand_fails(self) -> None:
        self.introduce_gate([A])
        self.add_b_by_hand()
        self.check([A, B])
        self.assert_fails(self.proc, ADDED, "pkg/b.go: [unused]")

    def test_a_size_raised_by_hand_fails(self) -> None:
        self.introduce_gate([funlen(90)])
        entries = self.repo.entries()
        entries[0]["sizes"] = [120]
        self.repo.write_entries(entries)
        self.check([funlen(120)])
        self.assert_fails(self.proc, RAISED, "(90, 120)")

    def test_a_size_removed_by_hand_is_a_raised_size(self) -> None:
        self.introduce_gate([funlen(90)])
        self.record_rows([funlen(90)])
        entries = self.repo.entries()
        del entries[0]["sizes"]
        self.repo.write_entries(entries)
        self.check([funlen(90)])
        self.assert_fails(self.proc, RAISED, "(90, none)")

    def test_a_deleted_baseline_recorded_again_fails(self) -> None:
        # Deleting the baseline and running record writes a full new baseline.
        self.introduce_gate([A])
        self.repo.baseline.unlink()
        self.record_rows([A, C])
        self.check([A, C])
        self.assert_fails(self.proc, ADDED, "pkg/c.go: [vet]")

    def test_a_baseline_that_shrank_passes(self) -> None:
        self.introduce_gate([A, B, funlen(90)])
        self.record_rows([A, funlen(85)])
        self.check([A, funlen(85)])
        self.assert_passes(self.proc)

    def test_a_gate_introduced_on_the_branch_passes_and_says_so(self) -> None:
        self.repo.branch_off_main("before the gate")
        self.repo.introduce_gate()
        self.record_rows([A])
        self.check([A])
        self.assert_passes(self.proc)
        self.assertIn(f"{GATE_SCRIPT} is new since main", self.proc.stderr)

    def test_a_ref_that_does_not_resolve_fails(self) -> None:
        self.introduce_gate([A])
        self.check([A], ref="mian")
        self.assert_fails(self.proc, "--base-ref mian does not name a commit")

    def drop_b_on_main(self) -> None:
        """Shrink the baseline on main after the branch left it, as another change would."""
        self.repo.git("checkout", "-q", "main")
        self.record_rows([A])
        self.repo.commit("main drops B")
        self.repo.git("checkout", "-q", "topic")

    def test_a_branch_behind_a_base_that_shrank_since_passes(self) -> None:
        self.introduce_gate([A, B])
        self.drop_b_on_main()
        self.check([A, B])
        self.assert_passes(self.proc)

    def test_growth_since_the_merge_base_fails_after_the_base_moved_on(self) -> None:
        self.introduce_gate([A, B])
        self.drop_b_on_main()
        self.repo.write_entries([*self.repo.entries(), entry("pkg/c.go", "vet", "new finding")])
        self.check([A, B, C])
        self.assert_fails(self.proc, ADDED, "pkg/c.go: [vet]")

    def test_the_compared_commit_is_named(self) -> None:
        self.introduce_gate([A])
        fork = self.repo.git("rev-parse", "HEAD").strip()
        self.check([A])
        self.assert_passes(self.proc)
        self.assertIn(f"at its merge base with HEAD, {fork[:12]}", self.proc.stderr)

    def test_a_ref_with_no_history_in_common_fails(self) -> None:
        self.introduce_gate([A])
        self.repo.git("checkout", "-q", "--orphan", "unrelated")
        self.repo.commit("unrelated history")
        self.repo.git("checkout", "-q", "topic")
        self.check([A], ref="unrelated")
        self.assert_fails(self.proc, "--base-ref unrelated has no history in common with HEAD")

    def test_an_empty_ref_is_refused(self) -> None:
        # An empty ref once read as no ref at all, and the check compared nothing.
        self.introduce_gate([A])
        self.check([A], ref="")
        self.assert_fails(self.proc, "--base-ref needs a ref", code=2)

    def test_a_moved_baseline_is_compared_against_the_one_the_gate_named(self) -> None:
        self.introduce_gate([A])
        moved = BASELINE.replace("gate.json", "moved.json")
        self.repo.write(
            GATE_SCRIPT, (self.repo.root / GATE_SCRIPT).read_text().replace(BASELINE, moved)
        )
        self.repo.baseline.rename(self.repo.root / moved)
        self.repo.baseline = self.repo.root / moved
        self.add_b_by_hand()
        self.check([A, B])
        self.assert_fails(self.proc, ADDED, "pkg/b.go: [unused]")

    def test_a_renamed_gate_is_compared_against_the_baseline_it_had(self) -> None:
        self.introduce_gate([A])
        renamed = GATE_SCRIPT.replace("gate-test", "gate-renamed")
        self.repo.git("mv", GATE_SCRIPT, renamed)
        self.add_b_by_hand()
        self.check([A, B], gate=renamed)
        self.assert_fails(self.proc, ADDED, "pkg/b.go: [unused]")

    def test_a_gate_whose_baseline_is_missing_at_the_ref_fails(self) -> None:
        self.repo.introduce_gate()
        self.repo.branch_off_main("a gate with no baseline")
        self.record_rows([A])
        self.check([A])
        self.assert_fails(self.proc, f"names the baseline {BASELINE}, which does not exist there")

    def test_a_gate_that_does_not_name_the_baseline_fails(self) -> None:
        # Another gate's script, given by mistake, would compare the wrong baseline.
        self.introduce_gate([A])
        self.repo.write("scripts/gates/gate-other.sh", "exec ratchet.py --baseline other.json\n")
        self.check([A], gate="scripts/gates/gate-other.sh")
        self.assert_fails(self.proc, f"does not name the baseline {BASELINE}")

    def test_a_baseline_moved_from_an_existing_gate_fails(self) -> None:
        # The review's case: the grown baseline is copied to a path the gate never
        # named, and checked with --baseline pointing at the copy.
        self.introduce_gate([A])
        self.add_b_by_hand()
        moved = self.repo.root / BASELINE.replace("gate.json", "moved.json")
        moved.write_text(self.repo.baseline.read_text())
        self.repo.baseline = moved
        self.check([A, B])
        self.assert_fails(
            self.proc, "does not name the baseline scripts/gates/baselines/moved.json"
        )

    def test_a_gate_script_that_does_not_exist_fails(self) -> None:
        self.introduce_gate([A])
        self.check([A], gate="scripts/gates/gate-missing.sh")
        self.assert_fails(self.proc, "cannot read the gate script")

    def test_base_ref_needs_the_gate(self) -> None:
        self.introduce_gate([A])
        proc = self.repo.run("check", [A], "--base-ref", "main")
        self.assert_fails(proc, "--base-ref needs --gate", code=2)

    def test_record_takes_no_base_ref(self) -> None:
        proc = self.repo.run("record", [A], "--base-ref", "main")
        self.assert_fails(proc, "--base-ref belongs to check", code=2)
        self.assertFalse(self.repo.baseline.exists())


if __name__ == "__main__":
    unittest.main()
