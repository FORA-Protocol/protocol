"""Tests for the `jscpd` format in formats.py, run through ratchet.py.

The tests read a real JSON report of the pinned jscpd, testdata/jscpd-report.json, of the
two clones planted in testdata/planted/ (one between two Go files, one between
two TypeScript files), recorded by testdata/record.sh with this repository's
.jscpd.json, and edit it to show what does and does not change a clone's
baseline entry.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest
from typing import TYPE_CHECKING

from ratchet_harness import GATE_SCRIPT, RepoTestCase, entry

if TYPE_CHECKING:
    import subprocess


JSCPD_SAMPLE = "jscpd-report.json"
GO_PAIR = ("planted/clones/clone_a.go", "planted/clones/clone_b.go")
TS_PAIR = ("sdk/ts/tests/zz-clone-a.ts", "sdk/ts/tests/zz-clone-b.ts")
GO_DIGEST = "ad1b8aecf36639a4"
TS_DIGEST = "d6078cdbf8aab00c"


def clone(pair: tuple[str, str], digest: str) -> dict[str, object]:
    """Return the baseline entry for a clone between the two files of `pair`."""
    return entry(pair[0], "clone", f"duplicated in {pair[1]}, fragment {digest}")


class JscpdFormatTest(RepoTestCase):
    """The `jscpd` format, read from a real jscpd 4 JSON report of two clones."""

    def setUp(self) -> None:
        super().setUp()
        self.report = json.loads(self.repo.sample(JSCPD_SAMPLE))

    def run_report(self, command: str, tool_exit: int = 1) -> subprocess.CompletedProcess[str]:
        """Run ratchet `command` against a jscpd that prints `self.report`."""
        return self.repo.run_output(command, "jscpd", json.dumps(self.report), tool_exit=tool_exit)

    def record_sample(self) -> None:
        proc = self.repo.run_output("record", "jscpd", self.repo.sample(JSCPD_SAMPLE))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def swap_files(self, dup: dict[str, object]) -> None:
        dup["firstFile"], dup["secondFile"] = dup["secondFile"], dup["firstFile"]

    def test_each_clone_is_one_entry_under_the_file_that_sorts_first(self) -> None:
        # The sample lists both clones in sorted order, so one is swapped first.
        self.swap_files(self.report["duplicates"][0])
        self.assertGreater(
            self.report["duplicates"][0]["firstFile"]["name"],
            self.report["duplicates"][0]["secondFile"]["name"],
        )
        self.assertEqual(self.run_report("record").returncode, 0)
        self.assertEqual(
            self.repo.entries(), [clone(GO_PAIR, GO_DIGEST), clone(TS_PAIR, TS_DIGEST)]
        )

    def test_the_lines_jscpd_reports_are_not_part_of_a_clones_identity(self) -> None:
        # Only the reported lines change here. A copy that really moves can end at
        # another token, and test_a_changed_fragment_is_a_new_clone_and_its_old_entry_is_gone
        # shows that such a clone is new.
        self.record_sample()
        for dup in self.report["duplicates"]:
            for side in ("firstFile", "secondFile"):
                loc = dup[side]
                loc["start"] += 40
                loc["end"] += 40
                loc["startLoc"]["line"] += 40
                loc["endLoc"]["line"] += 40
        self.assert_passes(self.run_report("check"))

    def test_no_record_carries_a_clone_whose_rename_changed_its_fragment(self) -> None:
        # A rename that changes the order jscpd reads the two files in makes it report
        # the other copy, through the token that follows that copy: a new hash, which
        # neither the move rules nor git's rename carry to the renamed file.
        self.repo.introduce_gate()
        self.record_sample()
        self.repo.branch_off_main("introduce the gate")
        renamed = "planted/clones/a_clone.go"
        self.repo.git("mv", GO_PAIR[1], renamed)
        status = self.repo.git("diff", "--cached", "-M", "--name-status", "main")
        self.assertIn(f"R100\t{GO_PAIR[1]}\t{renamed}", status)
        go = next(d for d in self.report["duplicates"] if d["format"] == "go")
        go["firstFile"]["name"], go["secondFile"]["name"] = renamed, GO_PAIR[0]
        go["fragment"] += "\n\n// The next function."
        new = f"{renamed}: [clone] duplicated in {GO_PAIR[0]}, fragment "
        for extra in ((), ("--base-ref", "main", "--gate", GATE_SCRIPT)):
            proc = self.repo.run_output("record", "jscpd", json.dumps(self.report), *extra)
            self.assert_fails(proc, "findings not in the baseline", new)

    def test_a_clone_whose_whitespace_changed_keeps_its_entry(self) -> None:
        # jscpd compares tokens, so it reports one clone for two copies that differ
        # only in whitespace, and the hash leaves whitespace out, so reindenting the
        # copy jscpd reports keeps its entry.
        self.record_sample()
        for dup in self.report["duplicates"]:
            fragment = dup["fragment"]
            changed = fragment.replace("\t", "    ").replace(" = ", "=").replace("{\n", "{ ")
            self.assertNotEqual(changed, fragment)
            self.assertNotEqual(
                changed.splitlines(), [line.strip() for line in fragment.splitlines()]
            )
            dup["fragment"] = changed
        self.assert_passes(self.run_report("check"))

    def test_a_changed_fragment_is_a_new_clone_and_its_old_entry_is_gone(self) -> None:
        self.record_sample()
        go = next(d for d in self.report["duplicates"] if d["format"] == "go")
        changed = go["fragment"].replace("total -= x", "total += x", 1)
        self.assertNotEqual(changed, go["fragment"])
        go["fragment"] = changed
        proc = self.run_report("check")
        self.assert_fails(
            proc, "findings not in the baseline", "baseline entries that no longer occur"
        )
        self.assertEqual(proc.stdout.count(GO_PAIR[0]), 2)
        self.assertNotIn(TS_PAIR[0], proc.stdout)
        self.assertIn("except a clone with a new fragment", proc.stdout)

    def test_a_moved_copy_keeps_its_entry_while_jscpd_reports_the_same_fragment(self) -> None:
        # The copy jscpd takes the fragment from (firstFile) stays where it is.
        self.record_sample()
        go = next(d for d in self.report["duplicates"] if d["format"] == "go")
        go["secondFile"]["name"] = go["secondFile"]["name"].replace("clone_b.go", "clone_c.go")
        self.assert_fails(self.run_report("check"), "findings that moved to another file")
        proc = self.run_report("record")
        self.assert_passes(proc)
        was = f"(was [clone] duplicated in {GO_PAIR[1]}, fragment {GO_DIGEST})"
        self.assertIn(was, proc.stderr)
        moved = (GO_PAIR[0], GO_PAIR[1].replace("clone_b.go", "clone_c.go"))
        self.assertIn(clone(moved, GO_DIGEST), self.repo.entries())
        self.assert_passes(self.run_report("check"))

    def test_a_second_copy_of_a_baselined_fragment_fails(self) -> None:
        self.record_sample()
        self.report["duplicates"].append(self.report["duplicates"][0])
        proc = self.run_report("check")
        self.assert_fails(proc, "findings not in the baseline", ": [clone] duplicated in ")

    def test_a_clone_within_one_file_names_no_second_file(self) -> None:
        dup = next(d for d in self.report["duplicates"] if d["format"] == "go")
        dup["secondFile"]["name"] = dup["firstFile"]["name"]
        self.report["duplicates"] = [dup]
        self.assert_passes(self.run_report("record"))
        self.assertEqual(
            self.repo.entries(),
            [entry(GO_PAIR[0], "clone", f"duplicated within this file, fragment {GO_DIGEST}")],
        )

    def test_a_run_with_no_clones_passes(self) -> None:
        self.report["duplicates"] = []
        self.assert_passes(self.run_report("check", tool_exit=0))

    def test_a_jscpd_run_that_did_not_finish_fails(self) -> None:
        no_duplicates = dict(self.report)
        del no_duplicates["duplicates"]
        none_found = {**self.report, "duplicates": []}
        for out, code, message in [
            (json.dumps(no_duplicates), 1, "not a jscpd JSON report"),
            ("", 0, "not a jscpd JSON report"),
            # jscpd exits 1 when it crashes, and writes no report.
            ("", 1, "not a jscpd JSON report"),
            (json.dumps(none_found), 1, "exited 1, which means it reported something"),
            (json.dumps(self.report), 2, "failed with exit code 2"),
        ]:
            proc = self.repo.run_output("check", "jscpd", out, tool_exit=code)
            self.assert_fails(proc, message)
            self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
