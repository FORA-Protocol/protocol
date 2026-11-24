"""Tests for the golangci-lint formats in formats.py, run through ratchet.py.

The samples are the pinned golangci-lint's output with this repository's
.golangci.yml, over the package in testdata/planted/planted/, which holds one
finding of each kind whose message carries a measured value or a line number,
two of the kinds whose message names no function, and one file the formatters
rewrite. testdata/record.sh records them.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from ratchet_harness import RepoTestCase, entry

PLANTED = "planted/planted.go"
RUN = "golangci-lint-run.json"
FMT = "golangci-lint-fmt.diff"
BRANCHY = "func Branchy(xs []int) int {"
SIX = "func SixArguments(a, b, c, d, e, f int) int { return a + b + c + d + e + f }"
SEVEN = "func SevenArguments(a, b, c, d, e, f, g int) int { return a + b + c + d + e + f + g }"
ARGS = "argument-limit: maximum number of arguments per function exceeded; max 5 but got N"
LLL = "The line is N characters long, which exceeds the maximum of 120 characters."
GREW = "baselined findings that grew"


class GolangciLintTest(RepoTestCase):
    """The `golangci-lint` format, reading `golangci-lint run` JSON."""

    def setUp(self) -> None:
        super().setUp()
        self.report = json.loads(self.repo.sample(RUN))

    def issues(self, linter: str) -> list[Any]:
        return [i for i in self.report["Issues"] if i["FromLinter"] == linter]

    def edit(self, linter: str, old: str, new: str) -> None:
        """Replace `old` by `new` in the text of the one `linter` issue that holds it."""
        hits = [i for i in self.issues(linter) if old in str(i["Text"])]
        self.assertEqual(len(hits), 1, f"{linter}: {old}")
        hits[0]["Text"] = str(hits[0]["Text"]).replace(old, new)

    def check(self) -> None:
        self.proc = self.repo.run_output("check", "golangci-lint", json.dumps(self.report))

    def record_sample(self) -> None:
        self.record("golangci-lint", self.repo.sample(RUN))

    def test_record_keeps_rule_message_and_line_with_the_size_apart(self) -> None:
        self.record_sample()
        got = {(e["rule"], e.get("source")): e for e in self.repo.entries()}
        expected = [
            entry(
                PLANTED,
                "cyclop",
                "calculated cyclomatic complexity for function Branchy is N, max is 10",
                source=BRANCHY,
                sizes=[126],
            ),
            entry(
                PLANTED,
                "funlen",
                "Function 'Branchy' has too many statements (N > 50)",
                source=BRANCHY,
                sizes=[188],
            ),
            entry(
                PLANTED,
                "funlen",
                "Function 'Long' is too long (N > 80)",
                source="func Long() []int {",
                sizes=[87],
            ),
            entry(
                PLANTED,
                "gocognit",
                "cognitive complexity N of func `Branchy` is high (> 15)",
                source=BRANCHY,
                sizes=[195],
            ),
            entry(
                PLANTED,
                "gocyclo",
                "cyclomatic complexity N of func `Branchy` is high (> 10)",
                source=BRANCHY,
                sizes=[126],
            ),
            {
                **entry(
                    PLANTED,
                    "maintidx",
                    "Function name: Branchy, Cyclomatic Complexity: N, Halstead Volume: N, "
                    "Maintainability Index: N",
                    source=BRANCHY,
                    sizes=[3],
                ),
                "lower_is_worse": True,
            },
            entry(
                PLANTED,
                "nestif",
                "`if x > 0` has complex nested blocks (complexity: N)",
                source="if x > 0 {",
                sizes=[6],
            ),
            entry(
                PLANTED,
                "nilerr",
                "error is not nil (line N) but it returns nil",
                source="return nil",
            ),
            entry(PLANTED, "revive", ARGS, source=SIX, sizes=[6]),
            entry(PLANTED, "revive", ARGS, source=SEVEN, sizes=[7]),
        ]
        for e in expected:
            self.assertEqual(got[(e["rule"], e["source"])], e)
        self.assertEqual(len(self.repo.entries()), 15)

    def test_two_findings_whose_message_names_no_function_are_two_entries(self) -> None:
        self.record_sample()
        long_lines = [e for e in self.repo.entries() if e["rule"] == "lll" and e["path"] == PLANTED]
        self.assertEqual([e["message"] for e in long_lines], [LLL, LLL])
        self.assertEqual(sorted(e["sizes"] for e in long_lines), [[128], [139]])
        args = [e for e in self.repo.entries() if e["message"] == ARGS]
        self.assertEqual(sorted(e["sizes"] for e in args), [[6], [7]])

    def test_the_smaller_of_two_same_message_findings_cannot_grow(self) -> None:
        self.record_sample()
        self.edit("lll", "The line is 128 characters", "The line is 138 characters")
        self.edit("revive", "but got 6", "but got 7")
        self.check()
        self.assert_fails(self.proc, GREW, "(128, 138)", "(6, 7)")

    def test_fixing_one_long_parameter_list_and_writing_another_fails(self) -> None:
        self.record_sample()
        planted = self.repo.root / PLANTED
        text = planted.read_text()
        added = "func OtherSix(a, b, c, d, e, f int) int { return a + b + c + d + e + f }"
        planted.write_text(text + added + "\n")
        six = next(i for i in self.issues("revive") if "but got 6" in str(i["Text"]))
        six["Pos"]["Line"] = len(text.splitlines()) + 1
        self.check()
        self.assert_fails(
            self.proc,
            "findings not in the baseline",
            f"(at: {added})",
            "baseline entries that no longer occur",
            f"(at: {SIX})",
        )

    def test_formatter_findings_are_left_to_the_format_gate(self) -> None:
        linters = {i["FromLinter"] for i in self.report["Issues"]}
        self.assertTrue({"gofumpt", "goimports", "golines"} <= linters)
        self.record_sample()
        rules = {e["rule"] for e in self.repo.entries()}
        self.assertFalse(rules & {"gofumpt", "goimports", "golines"})

    def test_a_finding_keeps_its_entry_when_its_lines_move(self) -> None:
        self.record_sample()
        planted = self.repo.root / PLANTED
        planted.write_text("\n" * 7 + planted.read_text())
        for issue in self.report["Issues"]:
            if issue["Pos"]["Filename"] == PLANTED:
                issue["Pos"]["Line"] += 7
                issue["Pos"]["Offset"] += 7
        self.edit("nilerr", "(line 374)", "(line 381)")
        self.edit("maintidx", "Halstead Volume: 8419.68", "Halstead Volume: 8420.11")
        self.check()
        self.assert_passes(self.proc)

    def test_a_finding_that_grows_fails_and_record_refuses_it(self) -> None:
        self.record_sample()
        self.edit("funlen", "statements (188 > 50)", "statements (189 > 50)")
        self.check()
        self.assert_fails(self.proc, GREW, "too many statements (N > 50) (at: func Branchy")
        self.assertIn("(188, 189)", self.proc.stdout)
        proc = self.repo.run_output("record", "golangci-lint", json.dumps(self.report))
        self.assert_fails(proc, GREW)
        funlen = [e for e in self.repo.entries() if e["rule"] == "funlen"]
        self.assertEqual(sorted(e["sizes"] for e in funlen), [[87], [188]])

    def test_a_finding_that_shrinks_fails_until_record_lowers_it(self) -> None:
        self.record_sample()
        self.edit("funlen", "too long (87 > 80)", "too long (84 > 80)")
        self.check()
        self.assert_fails(self.proc, "baselined findings that shrank", "(84, 87)")
        self.record("golangci-lint", json.dumps(self.report))
        self.check()
        self.assert_passes(self.proc)
        proc = self.repo.run_output("check", "golangci-lint", self.repo.sample(RUN))
        self.assert_fails(proc, GREW, "(84, 87)")

    def test_a_maintainability_index_is_held_from_below(self) -> None:
        self.record_sample()
        self.edit("maintidx", "Maintainability Index: 3", "Maintainability Index: 2")
        self.check()
        self.assert_fails(self.proc, GREW, "(3, 2, lower is worse)")
        self.edit("maintidx", "Maintainability Index: 2", "Maintainability Index: 9")
        self.check()
        self.assert_fails(self.proc, "baselined findings that shrank", "(9, 3, lower is worse)")
        self.record("golangci-lint", json.dumps(self.report))
        maintidx = [e for e in self.repo.entries() if e["rule"] == "maintidx"]
        self.assertEqual(maintidx[0]["sizes"], [9])

    def test_a_changed_limit_is_a_different_finding(self) -> None:
        self.record_sample()
        self.edit("cyclop", "max is 10", "max is 20")
        self.check()
        self.assert_fails(
            self.proc,
            "findings not in the baseline",
            "function Branchy is N, max is 20",
            "baseline entries that no longer occur",
            "function Branchy is N, max is 10",
        )

    def test_a_clean_run_has_no_findings(self) -> None:
        for clean in ('{"Issues":[]}', '{"Issues":null}'):
            proc = self.repo.run_output("check", "golangci-lint", clean, tool_exit=0)
            self.assert_passes(proc)

    def test_a_run_that_did_not_finish_fails(self) -> None:
        cases = [
            ("", 3, "failed with exit code 3"),
            ('{"Issues":[]}', 1, "exited 1, which means it reported something"),
            ("level=error msg=boom", 1, "not golangci-lint JSON output"),
            ("{}", 1, "not a golangci-lint report with an Issues list"),
        ]
        for out, code, message in cases:
            proc = self.repo.run_output("check", "golangci-lint", out, tool_exit=code)
            self.assert_fails(proc, message)
            self.assertNotIn("Traceback", proc.stderr)


class GolangciFmtTest(RepoTestCase):
    """The `golangci-lint-fmt` format, reading `golangci-lint fmt --diff`."""

    def test_reports_each_file_it_would_rewrite(self) -> None:
        # golines wraps the one long line, and gofumpt fixes the spacing.
        self.assertIn("+\treturn Branchy([]int{1, 2, 3})", self.repo.sample(FMT))
        self.record("golangci-lint-fmt", self.repo.sample(FMT))
        self.assertEqual(
            self.repo.entries(),
            [entry("planted/unformatted.go", "golangci-lint fmt", "file is not formatted")],
        )

    def test_a_new_unformatted_file_fails(self) -> None:
        proc = self.repo.run_output("check", "golangci-lint-fmt", self.repo.sample(FMT))
        self.assert_fails(proc, "planted/unformatted.go: [golangci-lint fmt] file is not formatted")

    def test_a_clean_run_passes(self) -> None:
        self.assert_passes(self.repo.run_output("check", "golangci-lint-fmt", "", tool_exit=0))

    def test_output_that_is_not_its_diff_fails(self) -> None:
        plain = "--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-a\n+b\n"
        for out, message in [
            (plain, "not a line of golangci-lint fmt --diff output"),
            (self.repo.sample(FMT) + "panic: runtime error\n", "panic: runtime error"),
            ("", "exited 1, which means it reported something"),
        ]:
            proc = self.repo.run_output("check", "golangci-lint-fmt", out)
            self.assert_fails(proc, message)


if __name__ == "__main__":
    unittest.main()
