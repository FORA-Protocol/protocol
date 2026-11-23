# ADR-002: The conformance-corpus contract

Status: Accepted. The corpus-contract gate, `scripts/gates/gate-corpus-contract.sh`,
reads every corpus through the registry and enforces:

- rule 1 as far as a scan of the source text can: each SDK names the corpus file in
  a string literal, and names every column the file declares. A quoted mention in a
  comment still counts; no replay names its corpus by registry id yet, which would
  close that, and a shared replay module per language is to add it;
- rule 2, except that no other file lists corpus locations by hand, which review
  enforces; every fixture is held by the gate's baseline, so a new one fails;
- of rule 3, the outcome format, that a case list whose rows all record an outcome
  carries none of the columns the corpora used for it before, and that an accepted
  row lists no refusal detail;
- of rule 4, that every token is in the vocabulary and every vocabulary token is
  used;
- of rule 5, the pointers in supersession records and expected-failure entries;
- of rule 6, the expected-failure entries themselves.

Each migrated replay enforces the rest of rules 3, 4 and 6: it compares the token
the SDK's public error reports with the row's outcome, or with the port's
expected-failure entry. Rule 7 is enforced by each emitter's comparison and by the
guard test in `sdk/go/internal/vectorio`. Rule 8, the pointer as a test name in
rule 5, and one operation per row in rule 3 are enforced by review.

The gate's baseline holds the case lists that do not state their outcomes in the
one format yet, each at its number of such rows. Like every gate baseline it only
shrinks: a corpus added or extended from now on meets rule 3, and a case list
leaves the baseline when its corpus, its replays and its SDK errors are migrated.

## Context

Go is the oracle for every behavior the three SDKs share. A Go emitter writes a
corpus (a `*-vectors.json` file under a `testdata/` directory), and the Python
and TypeScript suites replay it. The corpora grew one at a time, and each chose
its own conventions:

- Outcomes are encoded differently: one corpus has a boolean `refused`, another
  a string, and `expected_reason` is present in some, optional in others, and
  ignored by some replays.
- The three SDKs name refusal reasons differently, so each replay carries a
  translation table and several match loosely, by substring. A replay that
  matches loosely passes when the port refuses for the wrong reason.
- Row pointers come in two formats.
- The directories that hold corpora are listed by hand in several gates, so a
  corpus in a new directory is never checked.
- An expected-failure entry flips on any assertion failure, so it cannot tell
  "the port does not implement this row" from "the port fails this row for
  another reason".

## Decision

1. Every corpus is replayed by all three SDKs, and each replay reads every
   column the corpus declares. There is no exemption.
2. One registry file, `sdk/parity/corpora.json`, lists every corpus and its
   location. Every gate that enumerates corpora reads the registry; nothing lists
   corpus locations by hand.
   - An entry is one case list: `{"file", "list", "row_key"}`, keyed by the corpus
     id. `file` is the path from the repository root, `list` the top-level key that
     holds the rows (empty when the file is a bare array), and `row_key` the column
     whose value names each row. A file with several case lists has one entry per
     list, so a row name is unique within its list only.
   - A top-level list that holds data for the cases, not cases, is a fixture: the
     registry's `fixtures` array names it as `<file>#<list>`. Every top-level list
     of rows in a registered file is either an entry or a fixture, and every
     fixture names such a list. So a list added to a registered file is checked
     the day it lands, and deleting an entry is a new finding, not a baseline
     entry that `record` removes. The gate's baseline holds one finding per
     fixture, so declaring a new fixture is a finding `record` cannot add.
   - The registry also names the vocabulary file (`reasons`) and each port's
     expected-failure file (`expected_failures`).
   - Every tracked file that matches `sdk/go/**/testdata/*-vectors.json` must be
     named by an entry. That is the only use of the file-name convention; it is
     how a corpus in a new directory is caught.
3. Every row states its outcome in one format, in its `outcome` column: the
   string `accepted`, or `refused:<token>` with a reason token. One string
   compares the same way in every language and in an expected-failure entry.
   Columns that record a result of the operation, such as a computed digest or
   the key a selection chose, stay beside it; the outcome is never encoded in
   another column as well: the accept/refuse decision lives only in `outcome`.
   A column that restated it as a flag or a single token (`valid`, `refused`,
   `expected_reason`, `strict_malformed`, `structural` and the rest, listed once in
   `RETIRED_OUTCOME_COLUMNS` in `scripts/gates/corpora.py`) is retired, and a case
   list on the outcome format carries none of them. A list of what a refusal found
   (rule ids, schema keywords, field paths: `REFUSAL_DETAIL_COLUMNS` beside it) is
   a result and stays, but it is a list, and an empty one on an `accepted` row, so
   the decision cannot hide in a detail column either. A predicate's own result, such as whether a pattern is
   safe, is a result too. A row checks one operation, so it has one outcome; a
   case that checks two operations is two rows.
4. Reason tokens come from one vocabulary, `sdk/parity/reasons.json`, which maps
   each token (`[a-z][a-z0-9_]*`) to its meaning. A token is added in the change
   that first records it in a corpus, and removed when no row records it. All
   three SDKs report the token through their public errors, so a replay compares
   tokens directly, with no translation table and no substring match. A function
   that refuses with an error reports the token through one public refusal type,
   under one name: `helpers.RefusalError` with a `Reason` field in Go,
   `fora_sdk.RefusalError` with a `reason` attribute in Python, and `RefusalError`
   with a `reason` property in TypeScript, exported as
   `@fora-protocol/sdk-l1/refusal`. In Go a typed refusal that already names its
   token, such as `PoPError`, reports it too, and `helpers.ReasonOf(err)` reads the
   token of either from an error chain; a refusal keeps wrapping its sentinel, so
   `errors.Is` still matches it. A function whose public result is a verdict
   reports the token in the verdict's `reason` field instead, as Python's and
   TypeScript's signed-URL and delivery-proof verifiers do. The change that
   migrates a group of corpora adds the refusals its SDK functions need; an
   existing boolean or error return keeps working, and the refusal is reported
   beside it.
5. A row is named by one pointer format, `<corpus>#<row>`, everywhere a row is
   referenced: supersession records (a row's `supersedes` list), expected-failure
   entries and test names. `<corpus>` is the registry id and `<row>` the value of
   its row key; neither holds a `#`. A supersession pointer names a registered
   corpus; the superseded row itself is usually gone.
6. A port that does not meet a row yet lists it in its one expected-failure
   file, `sdk/python/tests/expected-failures.json` or
   `sdk/ts/tests/expected-failures.json`, as `{"row", "outcome", "why"}`: the row
   pointer, the outcome the port produces today, and why. The replay asserts that
   outcome, so the entry fails when the row starts passing and when the port
   fails differently. The gate refuses an entry whose pointer names no row, whose
   row records no outcome, whose outcome is the row's own, or that lists a row
   twice. Go is the oracle and has no such file.
7. Corpora are rendered only by their Go emitter, and an emitter only compares:
   `go test` fails when the committed file differs from what the emitter renders,
   and `vectorio.Check` (`sdk/go/internal/vectorio`) then writes the rendering
   beside the corpus as `<corpus>.got`, which git ignores. Regeneration is its own
   command, `scripts/vectors.sh`: it runs the emitters, moves every `.got` file
   over its corpus, and runs the tests again. Nothing a test reads chooses between
   comparing and writing, which is what the no-test-switch rule (ADR-003 decision
   2) requires; the `FORA_UPDATE_VECTORS` variable that once did is gone. A guard
   test in `vectorio` fails when any Go file names that variable, or when an
   emitter reads the environment or a flag, or writes a file itself. An emitter
   is a `gen_*_test.go` file, or a file that calls `vectorio.Check` or a function
   of its own package that does.
8. A replay drives the SDK's public API, the same entry point a user calls.

## Consequences

- A refusal for the wrong reason fails the replay in every language.
- Adding a corpus means adding it to the registry; every gate then checks it.
- Migrating the existing corpora to one outcome format and one vocabulary changes
  the corpus files, their replays and the SDK errors behind them once, one group
  of corpora at a time. The Go emitters regenerate the files, and each group's
  change shrinks the gate's baseline.
