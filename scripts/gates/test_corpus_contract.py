"""Tests for corpus_contract.py, run through its command line and through ratchet.py.

Each test copies the gate modules into a throwaway git repository holding a small
tree that meets the contract: a registry with one corpus, its vocabulary, both
expected-failure files, and a Go, a Python and a TypeScript file that name the
corpus and read its columns. A test plants one violation and reads the rows the
scanner prints, or the result of the gate's ratchet run.

Run: python3 -m unittest discover -s scripts/gates -p 'test_*.py'
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from ratchet_harness import RatchetRepo, row

MODULES = ("corpora.py", "corpus_contract.py", "corpus_replay.py", "corpus_vocabulary.py")
REGISTRY = "sdk/parity/corpora.json"
REASONS = "sdk/parity/reasons.json"
CORPUS = "sdk/go/thing/testdata/thing-vectors.json"
PY_FAILURES = "sdk/python/tests/expected-failures.json"
TS_FAILURES = "sdk/ts/tests/expected-failures.json"

# A replay in each language that names the corpus file and reads each of its columns.
READS = '"thing-vectors.json" .name .input .outcome .supersedes'
REPLAYS = {
    "sdk/go/thing/gen_thing_test.go": f"package thing // {READS}\n",
    "sdk/python/tests/test_thing.py": f"# {READS}\n",
    "sdk/ts/tests/thing.test.ts": f"// {READS}\n",
}


def rows_of(corpus_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {"note": "a corpus", "vectors": corpus_rows}


class CorpusContractTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        self.repo = RatchetRepo(Path(tmp))
        self.repo.copy(*MODULES)
        self.corpora: dict[str, dict[str, str]] = {
            "thing": {"file": CORPUS, "list": "vectors", "row_key": "name"}
        }
        self.fixtures: list[str] = []
        self.write_registry()
        self.write_json(REASONS, {"note": "n", "reasons": {"too_long": "the input is too long"}})
        self.write_json(
            CORPUS,
            rows_of(
                [
                    {"name": "short", "input": "a", "outcome": "accepted"},
                    {"name": "long", "input": "aaaa", "outcome": "refused:too_long"},
                ]
            ),
        )
        self.write_failures(PY_FAILURES, [])
        self.write_failures(TS_FAILURES, [])
        for path, text in REPLAYS.items():
            self.repo.write(path, text)

    def write_json(self, path: str, doc: object) -> None:
        self.repo.write(path, json.dumps(doc, indent=2) + "\n")

    def write_registry(self) -> None:
        self.write_json(
            REGISTRY,
            {
                "note": "n",
                "fixtures": self.fixtures,
                "reasons": REASONS,
                "expected_failures": {"python": PY_FAILURES, "ts": TS_FAILURES},
                "corpora": self.corpora,
            },
        )

    def write_failures(self, path: str, entries: list[object]) -> None:
        self.write_json(path, {"note": "n", "entries": entries})

    def rows(self) -> list[str]:
        proc = self.repo.script("corpus_contract.py")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout.splitlines()

    def test_a_tree_that_meets_the_contract_has_no_finding(self) -> None:
        self.assertEqual(self.rows(), [])

    def test_a_corpus_file_no_entry_names_is_reported(self) -> None:
        other = "sdk/go/deep/er/testdata/other-vectors.json"
        self.write_json(other, rows_of([{"name": "a", "outcome": "accepted"}]))
        self.repo.write("sdk/go/thing/elsewhere.json", "{}\n")
        self.assertEqual(
            self.rows(),
            [row(other, "corpus-unregistered", f"no entry of {REGISTRY} names this file")],
        )

    def test_an_entry_with_no_file_or_no_rows_is_reported(self) -> None:
        self.corpora["gone"] = {
            "file": "sdk/go/gone-vectors.json",
            "list": "vectors",
            "row_key": "name",
        }
        self.corpora["nolist"] = {"file": CORPUS, "list": "absent", "row_key": "name"}
        self.corpora["notes"] = {"file": CORPUS, "list": "note", "row_key": "name"}
        self.corpora["empty"] = {"file": CORPUS, "list": "empty", "row_key": "name"}
        self.write_registry()
        doc = json.loads((self.repo.root / CORPUS).read_text())
        self.write_json(CORPUS, {**doc, "empty": []})
        self.assertEqual(
            sorted(self.rows()),
            sorted(
                [
                    row(REGISTRY, "corpus-entry", "gone: no file sdk/go/gone-vectors.json"),
                    row(REGISTRY, "corpus-entry", "nolist: list 'absent' holds no rows"),
                    row(REGISTRY, "corpus-entry", "notes: list 'note' holds no rows"),
                    row(REGISTRY, "corpus-entry", "empty: list 'empty' holds no rows"),
                ]
            ),
        )

    def test_rows_the_row_key_does_not_name_uniquely_are_reported(self) -> None:
        self.write_json(
            CORPUS,
            rows_of(
                [
                    {"name": "a", "input": "", "outcome": "accepted"},
                    {"name": "a", "input": "", "outcome": "accepted"},
                    {"name": "x#y", "input": "", "outcome": "accepted"},
                    {"name": "", "input": "", "outcome": "accepted"},
                    {"input": "", "outcome": "accepted"},
                ]
            ),
        )
        self.corpora["bad#id"] = {"file": CORPUS, "list": "vectors", "row_key": "input"}
        self.write_registry()
        rows = self.rows()
        unnamed = "rows name does not name (a non-empty string without '#')"
        self.assertIn(row(REGISTRY, "corpus-entry", f"thing: {unnamed}", 3), rows)
        self.assertIn(
            row(REGISTRY, "corpus-entry", "thing: name 'a' names more than one row"), rows
        )
        self.assertIn(
            row(REGISTRY, "corpus-entry", "'bad#id': a corpus id is non-empty, without '#'"), rows
        )

    def test_rows_without_an_outcome_of_the_one_format_are_counted(self) -> None:
        bad = [None, "refused", "rejected:too_long", "refused:Too_long", "refused:", True, "ok"]
        self.write_json(
            CORPUS,
            rows_of(
                [{"name": "good", "input": "", "outcome": "accepted"}]
                + [{"name": f"r{i}", "input": "", "outcome": o} for i, o in enumerate(bad)]
                + [{"name": "none", "input": ""}]
            ),
        )
        message = "thing: rows without an outcome, accepted or refused:<token>"
        self.assertEqual(
            sorted(self.rows()),
            sorted(
                [
                    row(REASONS, "corpus-reason", "too_long: no corpus row is refused for it"),
                    row(CORPUS, "corpus-outcome", message, len(bad) + 1),
                ]
            ),
        )

    def test_a_token_outside_the_vocabulary_and_an_unused_token_are_reported(self) -> None:
        reasons = {
            "too_long": "the input is too long",
            "unused": "x",
            "Bad-Token": "y",
            "empty": " ",
        }
        self.write_json(REASONS, {"note": "n", "reasons": reasons})
        doc = rows_of(
            [
                {"name": "long", "input": "", "outcome": "refused:too_long"},
                {"name": "odd", "input": "", "outcome": "refused:not_listed"},
            ]
        )
        self.write_json(CORPUS, doc)
        self.assertEqual(
            sorted(self.rows()),
            sorted(
                [
                    row(REASONS, "corpus-reason", "'Bad-Token': not a token, [a-z][a-z0-9_]*"),
                    row(REASONS, "corpus-reason", "Bad-Token: no corpus row is refused for it"),
                    row(REASONS, "corpus-reason", "empty: has no meaning"),
                    row(REASONS, "corpus-reason", "empty: no corpus row is refused for it"),
                    row(REASONS, "corpus-reason", "unused: no corpus row is refused for it"),
                    row(CORPUS, "corpus-reason", "thing#odd: not_listed is not in the vocabulary"),
                ]
            ),
        )

    def test_a_supersedes_pointer_must_name_a_registered_corpus(self) -> None:
        corpus_rows: list[dict[str, Any]] = [
            {"name": "short", "input": "", "outcome": "accepted", "supersedes": ["thing#gone"]},
            {"name": "long", "input": "", "outcome": "refused:too_long", "supersedes": "thing#a"},
        ]
        self.write_json(CORPUS, rows_of(corpus_rows))
        self.assertEqual(self.rows(), [])
        corpus_rows[0]["supersedes"] = ["thing#a", "no-hash", "thing#a#b"]
        corpus_rows[1]["supersedes"] = "nosuch#a"
        self.write_json(CORPUS, rows_of(corpus_rows))
        tail = "which is not <corpus>#<row> naming a registered corpus"
        self.assertEqual(
            self.rows(),
            [
                row(CORPUS, "corpus-pointer", f"thing#short: supersedes 'no-hash', {tail}"),
                row(CORPUS, "corpus-pointer", f"thing#short: supersedes 'thing#a#b', {tail}"),
                row(CORPUS, "corpus-pointer", f"thing#long: supersedes 'nosuch#a', {tail}"),
            ],
        )

    def test_an_expected_failure_records_a_different_outcome_of_a_registered_row(self) -> None:
        self.write_failures(
            PY_FAILURES, [{"row": "thing#long", "outcome": "accepted", "why": "not ported yet"}]
        )
        self.write_failures(
            TS_FAILURES,
            [
                {"row": "thing#short", "outcome": "accepted", "why": "same as the row"},
                {"row": "thing#long", "outcome": "refused", "why": "malformed"},
                {"row": "thing#long", "outcome": "refused:other", "why": "unknown token"},
                {"row": "thing#nosuch", "outcome": "accepted", "why": "no such row"},
                {"row": "nohash", "outcome": "accepted", "why": "no pointer"},
                {"row": "thing#short", "outcome": "refused:too_long", "why": " "},
                {"row": "thing#short", "outcome": "accepted"},
            ],
        )
        self.assertEqual(
            sorted(self.rows()),
            sorted(
                [
                    row(
                        TS_FAILURES,
                        "corpus-expected-failure",
                        "thing#short: records the row's own outcome",
                    ),
                    row(
                        TS_FAILURES,
                        "corpus-expected-failure",
                        "thing#long: 'refused' is not an outcome",
                    ),
                    row(
                        TS_FAILURES, "corpus-expected-failure", "thing#long: listed more than once"
                    ),
                    row(TS_FAILURES, "corpus-reason", "thing#long: other is not in the vocabulary"),
                    row(
                        TS_FAILURES,
                        "corpus-pointer",
                        "'thing#nosuch': names no registered corpus row",
                    ),
                    row(TS_FAILURES, "corpus-pointer", "'nohash': names no registered corpus row"),
                    row(TS_FAILURES, "corpus-expected-failure", "thing#short: gives no reason why"),
                    row(
                        TS_FAILURES, "corpus-expected-failure", "thing#short: listed more than once"
                    ),
                    row(
                        TS_FAILURES, "corpus-expected-failure", "thing#short: listed more than once"
                    ),
                    row(
                        TS_FAILURES,
                        "corpus-expected-failure",
                        "{'row': 'thing#short', 'outcome': 'accepted'}: "
                        "not an object of row, outcome, why",
                    ),
                ]
            ),
        )

    def test_an_expected_failure_for_a_row_with_no_outcome_is_reported(self) -> None:
        self.write_json(CORPUS, rows_of([{"name": "bare", "input": "", "outcome": "?"}]))
        self.write_json(REASONS, {"note": "n", "reasons": {}})
        self.write_failures(PY_FAILURES, [{"row": "thing#bare", "outcome": "accepted", "why": "w"}])
        self.assertIn(
            row(PY_FAILURES, "corpus-expected-failure", "thing#bare: the row records no outcome"),
            self.rows(),
        )

    def test_a_corpus_a_language_never_names_or_never_reads_is_reported(self) -> None:
        self.repo.write("sdk/python/tests/test_thing.py", "# .name .input .outcome .supersedes\n")
        self.repo.write("sdk/ts/tests/thing.test.ts", '// "thing-vectors.json" .name .input\n')
        self.repo.write("sdk/ts/testdata/thing.ts", "// .outcome .supersedes\n")
        self.assertEqual(
            self.rows(),
            [
                row(CORPUS, "corpus-replay", "no python replay names this file"),
                row(
                    CORPUS, "corpus-column", "list 'vectors': the ts replay never reads ['outcome']"
                ),
            ],
        )

    def add_list(self, name: str, rows: list[dict[str, Any]]) -> None:
        """Add the top-level list `name` to the corpus file."""
        doc = json.loads((self.repo.root / CORPUS).read_text())
        self.write_json(CORPUS, {**doc, name: rows})

    def test_a_list_of_rows_that_is_neither_an_entry_nor_a_fixture_is_reported(self) -> None:
        self.add_list("extra", [{"name": "x", "input": ""}])
        unclaimed = "list 'extra' is neither a registry entry nor a declared fixture"
        self.assertEqual(self.rows(), [row(CORPUS, "corpus-unregistered", unclaimed)])
        self.fixtures.append(f"{CORPUS}#extra")
        self.write_registry()
        fixture = "list 'extra' is a declared fixture"
        self.assertEqual(self.rows(), [row(CORPUS, "corpus-fixture", fixture)])

    def assert_unregistering_survives_record(self, *, as_fixture: bool, finding: str) -> None:
        """Record a baseline with the case list `refused` registered, drop its entry
        (declaring it a fixture when `as_fixture`), record again, and require the gate
        to fail on `finding`, which `record` could not add."""
        self.add_list("refused", [{"name": "r", "input": ""}])
        self.corpora["thing.refused"] = {"file": CORPUS, "list": "refused", "row_key": "name"}
        self.write_registry()
        self.assertEqual(self.repo.gate("record", "corpus_contract.py").returncode, 0)
        self.assertEqual(self.repo.gate("check", "corpus_contract.py").returncode, 0)
        del self.corpora["thing.refused"]
        if as_fixture:
            self.fixtures.append(f"{CORPUS}#refused")
        self.write_registry()
        self.repo.gate("record", "corpus_contract.py")
        after = self.repo.gate("check", "corpus_contract.py")
        self.assertEqual(after.returncode, 1, after.stdout + after.stderr)
        self.assertIn(finding, after.stdout + after.stderr)

    def test_relabelling_an_entry_as_a_fixture_cannot_be_recorded_away(self) -> None:
        finding = "list 'refused' is a declared fixture"
        self.assert_unregistering_survives_record(as_fixture=True, finding=finding)

    def test_a_fixture_that_names_no_list_of_rows_is_reported(self) -> None:
        self.fixtures.extend([f"{CORPUS}#absent", f"{CORPUS}#note", "sdk/go/other.json#rows"])
        self.write_registry()
        self.assertEqual(
            self.rows(),
            [
                row(
                    REGISTRY,
                    "corpus-entry",
                    f"fixture {f!r} names no list of rows in a registered file",
                )
                for f in sorted(self.fixtures)
            ],
        )

    def test_deleting_an_entry_cannot_be_recorded_away(self) -> None:
        finding = "list 'refused' is neither a registry entry"
        self.assert_unregistering_survives_record(as_fixture=False, finding=finding)

    def test_a_list_on_the_outcome_format_may_not_state_it_again(self) -> None:
        self.write_json(
            CORPUS,
            rows_of(
                [
                    {"name": "short", "input": "", "outcome": "accepted", "valid": True},
                    {"name": "long", "input": "", "outcome": "refused:too_long", "reason": "x"},
                ]
            ),
        )
        for path in REPLAYS:
            self.repo.write(path, f"// {READS} .valid .reason\n")
        again = "thing: column {} states the outcome a second time"
        self.assertEqual(
            self.rows(),
            [
                row(CORPUS, "corpus-outcome", again.format("reason")),
                row(CORPUS, "corpus-outcome", again.format("valid")),
            ],
        )

    def test_a_retired_flag_on_a_list_on_the_outcome_format_is_reported(self) -> None:
        doc = rows_of(
            [{"name": "short", "input": "", "outcome": "accepted", "strict_malformed": False}]
        )
        self.write_json(CORPUS, doc)
        self.write_json(REASONS, {"note": "n", "reasons": {}})
        for path in REPLAYS:
            self.repo.write(path, f"// {READS} .strict_malformed\n")
        again = "thing: column strict_malformed states the outcome a second time"
        self.assertEqual(self.rows(), [row(CORPUS, "corpus-outcome", again)])

    def test_refusal_detail_is_a_result_but_empty_on_an_accepted_row(self) -> None:
        self.write_json(
            CORPUS,
            rows_of(
                [
                    {"name": "clean", "input": "", "outcome": "accepted", "rules": []},
                    {"name": "listed", "input": "", "outcome": "accepted", "rules": ["r.one"]},
                    {
                        "name": "long",
                        "input": "",
                        "outcome": "refused:too_long",
                        "rules": ["r.two"],
                    },
                ]
            ),
        )
        for path in REPLAYS:
            self.repo.write(path, f"// {READS} .rules\n")
        listed = "thing#listed: an accepted row lists rules"
        self.assertEqual(self.rows(), [row(CORPUS, "corpus-outcome", listed)])

    def test_the_structural_flag_states_the_outcome_a_second_time(self) -> None:
        doc = rows_of(
            [
                {"name": "short", "input": "", "outcome": "accepted", "structural": False},
                {"name": "long", "input": "", "outcome": "refused:too_long", "structural": True},
            ]
        )
        self.write_json(CORPUS, doc)
        for path in REPLAYS:
            self.repo.write(path, f"// {READS} .structural\n")
        again = "thing: column structural states the outcome a second time"
        self.assertEqual(self.rows(), [row(CORPUS, "corpus-outcome", again)])

    def test_refusal_detail_is_a_list(self) -> None:
        doc = rows_of(
            [
                {"name": "short", "input": "", "outcome": "accepted", "rules": False},
                {"name": "long", "input": "", "outcome": "refused:too_long", "rules": "r.one"},
            ]
        )
        self.write_json(CORPUS, doc)
        for path in REPLAYS:
            self.repo.write(path, f"// {READS} .rules\n")
        self.assertEqual(
            self.rows(),
            [
                row(CORPUS, "corpus-outcome", "thing#short: rules is not a list"),
                row(CORPUS, "corpus-outcome", "thing#long: rules is not a list"),
            ],
        )

    def test_a_retired_column_beside_rows_without_an_outcome_is_left_to_the_baseline(self) -> None:
        self.write_json(CORPUS, rows_of([{"name": "old", "input": "", "valid": True}]))
        self.write_json(REASONS, {"note": "n", "reasons": {}})
        for path in REPLAYS:
            self.repo.write(path, f"// {READS} .valid\n")
        message = "thing: rows without an outcome, accepted or refused:<token>"
        self.assertEqual(self.rows(), [row(CORPUS, "corpus-outcome", message, 1)])

    def test_a_replay_names_its_corpus_as_a_whole_file_name_in_a_string(self) -> None:
        columns = ".name .input .outcome .supersedes"
        self.repo.write(
            "sdk/python/tests/test_thing.py",
            f'GO / "request-thing-vectors.json"\n'
            f"# sdk/go/thing/testdata/thing-vectors.json, {columns}\n",
        )
        self.repo.write(
            "sdk/ts/tests/thing.test.ts",
            f'import c from "../thing/testdata/thing-vectors.json"; // {columns}\n',
        )
        self.assertEqual(
            self.rows(), [row(CORPUS, "corpus-replay", "no python replay names this file")]
        )

    def test_the_gate_fails_on_a_new_row_without_an_outcome_and_on_a_stale_entry(self) -> None:
        self.write_json(CORPUS, rows_of([{"name": "old", "input": ""}]))
        self.write_json(REASONS, {"note": "n", "reasons": {}})
        proc = self.repo.gate("record", "corpus_contract.py")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.repo.gate("check", "corpus_contract.py").returncode, 0)
        self.write_json(
            CORPUS, rows_of([{"name": "old", "input": ""}, {"name": "new", "input": ""}])
        )
        grew = self.repo.gate("check", "corpus_contract.py")
        self.assertEqual(grew.returncode, 1, grew.stdout + grew.stderr)
        self.assertIn("corpus-outcome", grew.stdout + grew.stderr)
        self.write_json(CORPUS, rows_of([{"name": "old", "input": "", "outcome": "accepted"}]))
        stale = self.repo.gate("check", "corpus_contract.py")
        self.assertEqual(stale.returncode, 1, stale.stdout + stale.stderr)
        self.assertEqual(self.repo.gate("record", "corpus_contract.py").returncode, 0)
        self.assertEqual(self.repo.entries(), [])


if __name__ == "__main__":
    unittest.main()
