# ADR-002: The conformance-corpus contract

Status: Accepted. Rule 1 is enforced by the corpus-completeness test. Rule 7 is
enforced by each emitter's own drift check. Rules 2 to 6 and rule 8 are enforced
by review until a gate exists for them.

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
2. One registry file lists every corpus and its location. Every gate that
   enumerates corpora reads the registry; nothing lists corpus locations by hand.
3. Every row states its outcome in one format: either `accepted`, or `refused`
   with a reason token.
4. Reason tokens come from one vocabulary, written once in the repository. All
   three SDKs report them through their public errors, so a replay compares
   tokens directly, with no translation table and no substring match.
5. A row is named by one pointer format, `<corpus>#<row>`, everywhere a row is
   referenced: supersession records, expected-failure entries and test names.
6. A port that does not meet a row yet lists it in its one expected-failure
   file, with the outcome the port produces today. The replay asserts that
   outcome, so the entry fails when the row starts passing and when the port
   fails differently.
7. Corpora are written only by their Go emitter. An emitter is also the drift
   check: `go test` fails when the committed file differs from what the emitter
   writes. Regeneration moves to a generator command (`go generate`, or a small
   `go run` program), and the `_test.go` file only compares. Today an emitter
   rewrites its file when `FORA_UPDATE_VECTORS=1` is set and skips its
   comparison; that variable is an inherited violation of the no-test-switch
   rule (ADR-003 decision 2) and goes when the generator command exists.
8. A replay drives the SDK's public API, the same entry point a user calls.

## Consequences

- A refusal for the wrong reason fails the replay in every language.
- Adding a corpus means adding it to the registry; every gate then checks it.
- Migrating the existing corpora to one outcome format and one vocabulary changes
  the corpus files and every replay once. The Go emitters regenerate the files.
