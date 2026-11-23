"""Tests for the ruff and mypy formats in formats.py, run through ratchet.py.

The samples are the pinned ruff's and mypy's output with this repository's ruff.toml and
mypy.ini, over the files in testdata/planted/scripts/, which hold one finding of
each kind the gates meet, measured sizes and line references among them, and two
findings of each limit whose message names no function. testdata/record.sh
records them.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import unittest

from ratchet_harness import RepoTestCase, entry

PLANTED = "scripts/zz_planted.py"
BRANCHY = "def branchy(x: int, limits: list[int]) -> int:"
MANY_A = "def many_a(a: int, b: int, c: int, d: int, e: int, f: int, *, g: int) -> int:"
MANY_B = "def many_b(a: int, b: int, c: int, d: int, e: int, f: int, *, g: int, h: int) -> int:"
ARGS = "Too many arguments in function definition (N > 6)"
UNTYPED = "Function is missing a type annotation"


class RuffTest(RepoTestCase):
    """The `ruff` format, reading `ruff check` and `ruff format --check` JSON."""

    def setUp(self) -> None:
        super().setUp()
        self.rows = json.loads(self.repo.sample("ruff-check.json"))

    def edit(self, code: str, old: str, new: str) -> None:
        hits = [r for r in self.rows if r["code"] == code and old in r["message"]]
        self.assertEqual(len(hits), 1, f"{code}: {old}")
        hits[0]["message"] = hits[0]["message"].replace(old, new)

    def check(self) -> None:
        self.proc = self.repo.run_output("check", "ruff", json.dumps(self.rows))

    def test_ruff_check_findings_keep_their_line_and_their_size_apart(self) -> None:
        self.record("ruff", self.repo.sample("ruff-check.json"))
        got = self.repo.entries()
        for e in [
            entry(PLANTED, "C901", "`branchy` is too complex (N > 10)", source=BRANCHY, sizes=[15]),
            entry(
                PLANTED,
                "PLR0911",
                "Too many return statements (N > 6)",
                source="def returns(flags: list[bool]) -> int:",
                sizes=[9],
            ),
            entry(PLANTED, "PLR0912", "Too many branches (N > 12)", source=BRANCHY, sizes=[14]),
            entry(PLANTED, "PLR0913", ARGS, source=MANY_A, sizes=[7]),
            entry(PLANTED, "PLR0913", ARGS, source=MANY_B, sizes=[8]),
            entry(PLANTED, "PLR0915", "Too many statements (N > 50)", source=BRANCHY, sizes=[69]),
            entry(
                PLANTED,
                "F811",
                "Redefinition of unused `first` from line N: `first` redefined here",
                source="def first(xs: list[int]) -> int:",
            ),
            entry(
                "scripts/zz_broken.py",
                "invalid-syntax",
                "Expected an expression",
                source="return a",
            ),
        ]:
            self.assertIn(e, got)
        long_lines = [e for e in got if e["rule"] == "E501"]
        self.assertEqual(sorted(e["sizes"] for e in long_lines), [[101], [102]])
        self.assertEqual(len(got), 14)

    def test_the_smaller_of_two_same_message_findings_cannot_grow(self) -> None:
        self.record("ruff", self.repo.sample("ruff-check.json"))
        self.edit("PLR0913", "(7 > 6)", "(8 > 6)")
        self.check()
        self.assert_fails(self.proc, "baselined findings that grew", f"(at: {MANY_A}) (7, 8)")

    def test_fixing_one_function_and_writing_another_fails(self) -> None:
        self.record("ruff", self.repo.sample("ruff-check.json"))
        planted = self.repo.root / PLANTED
        text = planted.read_text()
        gamma = "def gamma(a: int, b: int, c: int, d: int, e: int, f: int, *, g: int) -> int:"
        planted.write_text(text + gamma + "\n    return a\n")
        many_a = next(r for r in self.rows if r["code"] == "PLR0913" and "(7 > 6)" in r["message"])
        many_a["location"]["row"] = len(text.splitlines()) + 1
        self.check()
        self.assert_fails(
            self.proc, f"(at: {gamma})", "baseline entries that no longer occur", f"(at: {MANY_A})"
        )

    def test_a_finding_that_grows_fails_and_record_refuses_it(self) -> None:
        self.record("ruff", self.repo.sample("ruff-check.json"))
        self.edit("PLR0912", "(14 > 12)", "(15 > 12)")
        self.check()
        self.assert_fails(self.proc, "baselined findings that grew", f"(at: {BRANCHY}) (14, 15)")
        proc = self.repo.run_output("record", "ruff", json.dumps(self.rows))
        self.assert_fails(proc, "baselined findings that grew")
        branches = [e for e in self.repo.entries() if e["rule"] == "PLR0912"]
        self.assertEqual([e["sizes"] for e in branches], [[14]])

    def test_a_finding_that_shrinks_fails_until_record_lowers_it(self) -> None:
        self.record("ruff", self.repo.sample("ruff-check.json"))
        self.edit("PLR0915", "(69 > 50)", "(60 > 50)")
        self.check()
        self.assert_fails(self.proc, "baselined findings that shrank", "(60, 69)")
        self.record("ruff", json.dumps(self.rows))
        self.check()
        self.assert_passes(self.proc)
        proc = self.repo.run_output("check", "ruff", self.repo.sample("ruff-check.json"))
        self.assert_fails(proc, "baselined findings that grew", "(60, 69)")

    def test_a_changed_limit_is_a_different_finding(self) -> None:
        self.record("ruff", self.repo.sample("ruff-check.json"))
        self.edit("PLR0913", "(8 > 6)", "(8 > 7)")
        self.check()
        self.assert_fails(
            self.proc,
            "findings not in the baseline",
            f"Too many arguments in function definition (N > 7) (at: {MANY_B})",
            "baseline entries that no longer occur",
            f"{ARGS} (at: {MANY_B})",
        )

    def test_ruff_format_reports_the_file_wherever_its_first_change_is(self) -> None:
        sample = self.repo.sample("ruff-format.json")
        self.record("ruff", sample)
        self.assertEqual(
            self.repo.entries(),
            [entry("scripts/zz_unformatted.py", "unformatted", "File would be reformatted")],
        )
        moved = json.loads(sample)
        moved[0]["location"]["row"] = 1
        proc = self.repo.run_output("check", "ruff", json.dumps(moved))
        self.assert_passes(proc)

    def test_a_ruff_finding_not_in_the_baseline_fails(self) -> None:
        proc = self.repo.run_output("check", "ruff", self.repo.sample("ruff-format.json"))
        self.assert_fails(proc, "scripts/zz_unformatted.py: [unformatted]")

    def test_ruff_with_no_findings_passes(self) -> None:
        self.assert_passes(self.repo.run_output("check", "ruff", "[]", tool_exit=0))

    def test_a_ruff_run_that_did_not_finish_fails(self) -> None:
        no_code = json.dumps([{**self.rows[0], "code": None}])
        for out, code, message in [
            (self.repo.sample("ruff-check.json"), 2, "failed with exit code 2"),
            ("", 0, "not ruff JSON output"),
            ("[]", 1, "exited 1, which means it reported something"),
            ('{"code": "E501"}', 1, "ruff prints a JSON array"),
            (no_code, 1, "a ruff finding with no rule code"),
        ]:
            proc = self.repo.run_output("check", "ruff", out, tool_exit=code)
            self.assert_fails(proc, message)
            self.assertNotIn("Traceback", proc.stderr)


class MypyTest(RepoTestCase):
    """The `mypy` format, reading `mypy --output json`."""

    def test_mypy_errors_are_findings_and_notes_are_not(self) -> None:
        sample = self.repo.sample("mypy.jsonl")
        self.assertIn('"severity": "note"', sample)
        self.record("mypy", sample)
        self.assertEqual(
            self.repo.entries(),
            [
                entry(
                    PLANTED,
                    "assignment",
                    'Incompatible types in assignment (expression has type "str", '
                    'variable has type "int")',
                    source='value: int = "text"',
                ),
                entry(
                    PLANTED,
                    "name-defined",
                    'Name "undefined_name" is not defined',
                    source="return value + undefined_name",
                ),
                entry(
                    PLANTED,
                    "no-any-return",
                    'Returning Any from function declared to return "int"',
                    source="return value + undefined_name",
                ),
                entry(
                    PLANTED,
                    "no-any-return",
                    'Returning Any from function declared to return "int"',
                    source="return xs[0]",
                ),
                entry(
                    PLANTED,
                    "no-redef",
                    'Name "first" already defined on line N',
                    source="def first(xs: list[int]) -> int:",
                ),
                entry(PLANTED, "no-untyped-def", UNTYPED, source="def untyped_a(x):"),
                entry(PLANTED, "no-untyped-def", UNTYPED, source="def untyped_b(y):"),
                entry(
                    PLANTED,
                    "type-arg",
                    'Missing type arguments for generic type "list"',
                    source="def first(xs: list) -> int:",
                ),
            ],
        )

    def test_a_finding_that_moved_is_still_the_baselined_finding(self) -> None:
        sample = self.repo.sample("mypy.jsonl")
        self.record("mypy", sample)
        planted = self.repo.root / PLANTED
        planted.write_text("\n" * 7 + planted.read_text())
        rows = [json.loads(line) for line in sample.splitlines()]
        for r in rows:
            r["line"] += 7
            r["message"] = r["message"].replace("on line 10", "on line 17")
        moved = "".join(json.dumps(r) + "\n" for r in rows)
        self.assertIn("on line 17", moved)
        self.assertNotIn("on line 10", moved)
        self.assert_passes(self.repo.run_output("check", "mypy", moved))

    def test_an_untyped_function_moved_to_a_new_function_is_a_new_finding(self) -> None:
        # untyped_b is annotated and a new function, untyped_c, is written without
        # annotations: the count of no-untyped-def findings in the file stays 2, but
        # the finding on untyped_b's line is gone and untyped_c's is new.
        sample = self.repo.sample("mypy.jsonl")
        self.record("mypy", sample)
        planted = self.repo.root / PLANTED
        text = planted.read_text().replace("def untyped_b(y):", "def untyped_b(y: int) -> int:")
        planted.write_text(text + "\n\ndef untyped_c(z):\n    return z\n")
        rows = [json.loads(line) for line in sample.splitlines()]
        moved = next(r for r in rows if r["code"] == "no-untyped-def" and r["line"] == 22)
        moved["line"] = moved["end_line"] = len(text.splitlines()) + 3
        out = "".join(json.dumps(r) + "\n" for r in rows)
        proc = self.repo.run_output("check", "mypy", out)
        self.assert_fails(
            proc,
            "findings not in the baseline",
            f"{UNTYPED} (at: def untyped_c(z):)",
            "baseline entries that no longer occur",
            f"{UNTYPED} (at: def untyped_b(y):)",
        )

    def test_mypy_with_no_errors_passes(self) -> None:
        self.assert_passes(self.repo.run_output("check", "mypy", "\n", tool_exit=0))

    def test_a_mypy_run_that_did_not_finish_fails(self) -> None:
        sample = self.repo.sample("mypy.jsonl")
        note = next(line for line in sample.splitlines() if '"note"' in line)
        error = json.loads(sample.splitlines()[0])
        for out, code, message in [
            (sample, 2, "failed with exit code 2"),
            (note + "\n", 1, "exited 1, which means it reported something"),
            ("mypy: can't read file 'x.py'\n", 1, "not mypy JSON output"),
            (json.dumps({**error, "code": None}) + "\n", 1, "a mypy error with no error code"),
        ]:
            proc = self.repo.run_output("check", "mypy", out, tool_exit=code)
            self.assert_fails(proc, message)
            self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main()
