"""Tests for the sizes ratchet.py keeps: check and record, run through its command line.

A scanner in the `lines` format states each finding's size in its own column; the
tools' formats measure theirs from the message, which the test_ratchet_<tool>.py
files cover.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import unittest

from ratchet_harness import RepoTestCase, entry, row

GREW = "baselined findings that grew"
SHRANK = "baselined findings that shrank"


def long_file(size: int, path: str = "pkg/a.go") -> str:
    return row(path, "file-length", "over the limit of 500 lines", size)


class SizeTest(RepoTestCase):
    def test_record_keeps_the_size_apart_from_the_message(self) -> None:
        self.record_rows([long_file(812)])
        self.assertEqual(
            self.repo.entries(),
            [entry("pkg/a.go", "file-length", "over the limit of 500 lines", sizes=[812])],
        )

    def test_a_size_that_grew_fails_check(self) -> None:
        self.record_rows([long_file(90)])
        proc = self.repo.run("check", [long_file(95)])
        self.assert_fails(proc, f"{GREW}, as (baseline, now)", "(90, 95)")
        self.assertNotIn(SHRANK, proc.stdout)

    def test_a_size_that_shrank_fails_check_until_record_lowers_it(self) -> None:
        self.record_rows([long_file(90)])
        proc = self.repo.run("check", [long_file(85)])
        self.assert_fails(proc, f"{SHRANK}, as (now, baseline)", "(85, 90)")
        self.assertNotIn(GREW, proc.stdout)
        self.record_rows([long_file(85)])
        self.assertEqual(self.repo.entries()[0]["sizes"], [85])
        self.assert_passes(self.repo.run("check", [long_file(85)]))
        self.assert_fails(self.repo.run("check", [long_file(90)]), GREW, "(85, 90)")

    def test_record_refuses_to_raise_a_size(self) -> None:
        self.record_rows([long_file(90)])
        proc = self.repo.run("record", [long_file(95)])
        self.assert_fails(proc, GREW, "(90, 95)")
        self.assertEqual(self.repo.entries()[0]["sizes"], [90])

    def test_identical_findings_keep_one_size_each_from_the_largest(self) -> None:
        self.record_rows([long_file(90), long_file(95)])
        self.assertEqual(self.repo.entries()[0]["count"], 2)
        self.assertEqual(self.repo.entries()[0]["sizes"], [95, 90])

    def test_the_smaller_of_two_identical_findings_cannot_grow(self) -> None:
        self.record_rows([long_file(90), long_file(95)])
        proc = self.repo.run("check", [long_file(94), long_file(95)])
        self.assert_fails(proc, GREW, "(90, 94)")

    def test_record_lowers_each_size_of_identical_findings(self) -> None:
        self.record_rows([long_file(90), long_file(95)])
        self.record_rows([long_file(80), long_file(93)])
        self.assertEqual(self.repo.entries()[0]["sizes"], [93, 80])

    def test_a_finding_of_a_set_of_identical_ones_that_is_fixed_keeps_the_others(self) -> None:
        self.record_rows([long_file(90), long_file(95)])
        self.assert_fails(self.repo.run("check", [long_file(95)]), "no longer occur")
        self.record_rows([long_file(95)])
        self.assertEqual(self.repo.entries()[0]["count"], 1)
        self.assertEqual(self.repo.entries()[0]["sizes"], [95])

    def test_a_size_removed_from_the_baseline_by_hand_fails_until_recorded(self) -> None:
        # A missing size allows any size, so check asks for it to be recorded.
        self.record_rows([long_file(90)])
        entries = self.repo.entries()
        del entries[0]["sizes"]
        self.repo.write_entries(entries)
        proc = self.repo.run("check", [long_file(400)])
        self.assert_fails(proc, SHRANK, "(400, none)")
        self.record_rows([long_file(400)])
        self.assertEqual(self.repo.entries()[0]["sizes"], [400])


if __name__ == "__main__":
    unittest.main()
