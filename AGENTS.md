# Instructions for contributors and coding agents

This file states how code is written in this repository. It applies to every
change, whoever or whatever writes it. `CLAUDE.md` imports this file, so agents
that read either one get the same rules. The decisions behind these rules are in
[`docs/architecture/`](docs/architecture/); the reasoning behind the wire format
is in [`docs/design-history.md`](docs/design-history.md).

Read the rules for the job your change does. Most changes touch more than one.

## The repository

[`README.md`](README.md#whats-in-this-repo) maps the trees. In short:

- `proto/` is the wire format. Within `fora.v1` it is additive only, and
  `buf breaking` holds that.
- `gen/` holds the generated code: buf writes it from `proto/`, and
  `scripts/gen-sdk-types.sh` writes the Pydantic and Zod types and the JSON
  Schemas. Never edit a generated file by hand; regenerate it. The few
  hand-written support files there say so in their first lines (for example
  `gen/jsonschema/jsonschema.go` and `gen/python/wire/base.py`).
- `sdk/go`, `sdk/python` and `sdk/ts` are the hand-written SDKs. Go is the
  oracle: Python and TypeScript implement the behavior Go defines, and the
  conformance corpora prove it.
- `sdk/parity/symbol-map.json` maps every public Go symbol to its Python and
  TypeScript names, or records why one has none.
  [`docs/sdk-parity-matrix.md`](docs/sdk-parity-matrix.md) is generated from it.
- `conformance/` checks the proto, its documentation and its examples.
- `scripts/release/` builds, checks and publishes a release
  ([`RELEASING.md`](RELEASING.md)).
- `website/` is the documentation site.

## Gates

Run `scripts/ci-local.sh` before you push. It runs everything CI runs. Pass
`--base-ref REF` when the base of your pull request is not `origin/main`.

The quality gates live in `scripts/gates/`. Each gate is one file named
`scripts/gates/gate-<name>.sh`, so `ls scripts/gates/gate-*.sh` lists them, and
`scripts/gates/run.sh` runs them all. Each gate runs its tool through
`scripts/gates/ratchet.py`:

- A finding that is not in the gate's baseline fails the build. New code is held
  to zero findings.
- The baseline holds the findings this repository inherited. It only shrinks: an
  entry that no longer occurs also fails the build, and CI refuses a baseline
  that gained an entry, or allows a worse size, than where your change left the
  base branch (their merge base). In CI that base is a pull request's base
  branch, the commit `main` pointed at before a push, or, for a release tag,
  where the tagged commit left `main`.
- A finding is identified by its file, rule, message and the text of the line it
  points at, not by its line number, so each function's finding is its own
  entry. Editing that line makes it a new finding. A line that moves to another
  file unedited, in a split or a move, keeps its entry: `record` carries it
  there, and the baseline diff shows the move. An inline suppression is the
  exception: its entry never moves to another file, and follows its file only
  when git sees the file renamed.
- A finding that measures something (a function's length or complexity, an
  argument count, a file's length) is baselined at its size. It may shrink; the
  build fails if it grows. A maintainability index is held the other way: it
  may rise, and the build fails if it falls.
- After you fix, shrink or move a baselined finding, run the gate's `record`
  command (`scripts/gates/gate-<name>.sh record`) to lower or carry its entry,
  and commit the baseline with the change. Until you do, the gate fails, so the
  baseline always matches the tree. After you rename or split a file, stage the
  change and run `scripts/gates/gate-<name>.sh record --base-ref <base>`: it also
  carries an entry about a whole file, such as its length, to where git sees the
  file renamed or copied.
- Change a gate's tool, its version pin or its config in a change of its own
  that edits no other file. A gate script passes each file that decides what its
  tool reports with `--tool-file`, and the helper it runs passes its toolchain's
  pins the same way (a `FILE#PART` names the part of a manifest or lockfile that
  pins a tool). When one of them changed since the base and your change edits
  nothing else but baselines, `record --base-ref <base>` re-keys the entries of
  each file at the sizes the tool now measures; a change that also edits any
  other file re-keys nothing. A finding the new version reports beyond those
  fails like any new one. A formatter that rewrites a line makes the findings on
  that line new: run it in a change of its own and fix them there.

Every tracked source file is hand-written and gated, except the generated code.
The generated code is declared in one place, `GENERATED` in
`scripts/gates/scope.py`, and each entry there names the generator that writes
it; a generated file also says so in its first lines (`Code generated ... DO NOT
EDIT.`). The scope gate (`scripts/gates/gate-scope.sh`) fails when a hand-written
file is not read by every gate of its language, or when a gate reads generated
code. So a new generator adds its output to `GENERATED` in the same change, and
a tool's config never leaves a hand-written file out. The one other exclusion,
declared in `EXCLUDED` in `scope.py` with its reason, is the documentation site
(`website/`): it has its own toolchain, its own package, build and tests, and
these gates do not cover it. No other path may be excluded.

The size and complexity limits apply to every file, tests included, because a
test is code that has to be read and kept:

| Language | File | Function | Arguments | Complexity |
|---|---|---|---|---|
| Go | 500 lines | 80 lines, 50 statements | 5 | cyclomatic 10, cognitive 15, nested `if` 5 |
| Python | 500 lines | 50 statements, 12 branches, 6 returns | 6 | cyclomatic 10 |
| TypeScript, JavaScript | 400 lines | 60 lines | 5 | cognitive 15 |

A line is at most 120 characters in Go and 100 in Python; the TypeScript
formatter wraps at 120. Cyclomatic complexity 10 is McCabe's limit, the one
NIST SP 500-235 recommends; cognitive complexity 15 is the default of the tools
that measure it. Ruff measures no cognitive complexity and biome no cyclomatic
complexity, so each language has the measures its tools provide. When a
limit trips, split the function or the file along its responsibilities; do not
move code around only to get under the number.

The gates catch textual copies and limits. They cannot catch a copy that was
rewritten instead of pasted: the same test in two languages, a short helper
written again, data restated in another format. After CI passes, every change
gets a review that looks for exactly those, so search for the existing helper
before you write one.

Never suppress a finding inline. The inline-suppression gate fails on a new one,
in every form the tools read; the ones this repository inherited are in its
baseline. The forms are (`scripts/gates/inline_suppressions.py` holds the exact
patterns):

- Go: `//nolint`, and `#nosec` in a comment.
- Python: `# noqa` in any letter case, the file-wide `# ruff: noqa` and
  `# flake8: noqa`, `# isort: skip`, `skip_file` and `off`, `# fmt: off` and
  `# fmt: skip`, `# type: ignore`, a `# mypy:` inline-config line, and the
  `@no_type_check` decorator.
- TypeScript and JavaScript: `biome-ignore`, `@ts-ignore`, `@ts-expect-error`,
  `@ts-nocheck` and `eslint-disable`, in a line or a block comment, and the
  double assertion through `unknown` (`as unknown as`, and in TypeScript the
  `<unknown>` form).

If a rule is wrong
for a case, add an exclusion to the tool's config with a comment that gives the
reason, and say why in the pull request. "The tool is noisy" is not a reason.
Exclusion lists only shrink.

A gate whose tool is missing fails and prints the install command; it is never
skipped. The one place the gates do not run is the proto-ci workflow, which sets
`FORA_CI_SKIP_GATES=1` for `scripts/ci-local.sh` only because the gates workflow
runs the same gates on the same commit.

## Every change

- **No test-only switch.** No environment variable, package variable, build-tag
  branch, option or field may exist so that a test can relax a check, exported
  or not. A parameter that production code never sets is such a switch even when
  it is an argument. A test that needs different behavior supplies its own
  client, resolver, clock or key through the public API. This repository
  inherited three such variables. `SKIP_SSRF` and `ALLOW_INSECURE` are removed
  (see [SDK code](#sdk-code)); `FORA_UPDATE_VECTORS` is still to be removed (see
  [Conformance corpora](#conformance-corpora)). No change may add another.
- **No duplication.** Before you write a helper, fixture or constant, search for
  the one that exists. Shared test code has one home per language (see
  [Test suites](#test-suites)). Data that several places need, such as a list of
  corpora or a set of labels, is written once and read everywhere else. The
  duplication gate catches textual copies; reviewers catch the rest.
- **A comment is a claim.** A comment, docstring, changelog line or step name
  that states a checkable property must be true of the code. Check it before you
  commit it, and re-check every such sentence your change makes false.
- **This repository is public.** Tracked files never name an issue-tracker key,
  a private repository, a developer's local path or a customer. Describe the
  behavior or the reason instead.
- **Commits** use the subject form `Area: sentence` (for example
  `Go SDK: refuse a Signature-Agent member with parameters`), one change per
  commit.

## SDK code

- Keep the layers apart. The L1 trust core never dials and takes its clock
  as an input; the L2 tier (resolvers, clients, server adapters) does the I/O
  through a vetted client. The design history records both under "SDK
  layering: a dial-free trust core, a vetted-client I/O tier" and "SSRF-guarded
  fetch: two flags, a corpus-locked transport". The second section's two flags
  are superseded by the rule below, as its own note says.
- Route every outbound fetch through the SSRF-guarded transport by default. A
  caller may pass its own client. Never add a way to turn the guard off. The SDK
  library code reads no environment variable at all, and
  `sdk/go/internal/envguard` fails if any of the three SDKs starts to. A test
  that must reach a loopback or plaintext peer serves it over TLS and injects a
  client or transport that trusts it (the language's harness holds the helper).
- Report a refusal as a typed error that carries a reason token, in all three
  languages, so a test and a corpus replay can compare the reason.
- A public symbol added to Go is mapped in `sdk/parity/symbol-map.json` in the
  same change, with its Python and TypeScript names or the reason it has none.
- Within a major version an SDK's public API only grows. The API gates
  (`scripts/gates/gate-api-*.sh`) compare it with the last release, the newest
  `vX.Y.Z` tag reachable from HEAD, and fail on a removed, renamed or changed
  exported symbol. To rename one, keep the old name as a deprecated alias that
  calls the new one. Only a major release removes it, listed under
  `### Breaking` in that SDK's `CHANGELOG.md`
  ([ADR-004](docs/architecture/adr-004-sdk-api-gates.md)). A clone needs the
  release tags to run these gates: `git fetch --tags` from this repository's
  remote. The TypeScript SDK's API reports under `sdk/ts/api` are committed;
  after a change to its API, `python3 scripts/gates/api_diff.py ts --update`
  rewrites them.

## Conformance corpora

A behavior that more than one SDK implements is pinned by a corpus: a JSON file
of rows that the Go emitter writes and Python and TypeScript replay. The rules
are in
[ADR-002: Conformance corpora](docs/architecture/adr-002-conformance-corpora.md).
In short:

- The Go emitter (`gen_*_vectors_test.go`) writes its corpus and is its drift
  check: `go test` fails when the committed file differs from what the emitter
  writes. Never edit a corpus by hand. Today an emitter rewrites its file when
  `FORA_UPDATE_VECTORS=1` is set (`FORA_UPDATE_VECTORS=1 go test ./sdk/go/...`),
  and it then returns before its comparison. That variable is an inherited
  violation of the no-test-switch rule: regeneration is to move to a generator
  command, after which the `_test.go` file only compares. Until then, regenerate
  with it and commit the output.
- Record every row's outcome in one format: accepted, or refused with a reason
  token from the shared vocabulary. Make the replay compare the token, so a row
  that is refused for a different reason fails.
- Drive the replay through the SDK's public API, the same entry point a user
  calls.
- When a port does not meet a row yet, list the row in that port's one
  expected-failure file, with the outcome the port produces today. Make the
  entry fail both when the row starts passing and when the port fails
  differently.
- ADR-002 records which of these rules a gate enforces and which reviewers
  enforce.

## Test suites

The rules are in
[ADR-003: SDK test suites](docs/architecture/adr-003-sdk-test-suites.md). In
short:

- Test through the public API. A test that calls a private function, or copies
  one, proves the copy.
- Every behavior that can fail has a negative test, and the negative test
  asserts the refusal reason, not only that something was refused.
- Prove that a test passes for the right reason: break the code under test in
  each way the test claims to catch, and watch it fail each time. Reverting the
  fix once is not enough.
- Put shared test code in the language's harness module
  (`sdk/python/tests/resolvers_harness.py`,
  `sdk/ts/tests/resolvers-harness.ts` and `sdk/ts/tests/wba-fixtures.ts`):
  the signer, the capturing transport, the recording resolver, the replay
  store, the loopback origin and the reason matcher. Add to it; never write a
  second copy in a test file. Import the SDK's own codecs instead of copying
  them.
- Assert the precondition before the step that depends on it, and assert that
  the step happened before you read its result.

## Release scripts

- A script that publishes takes an explicit `--dry-run` argument, and the real
  publish and the dry run share one invocation. Never run a publishing script to
  see what it does.
- Derive each ecosystem's version spelling (Go, npm, PyPI) in one place, and
  read it from there everywhere; never strip or rewrite a tag by hand in one
  step.
- Every step a release takes, the irreversible ones especially, has a check that
  runs before the irreversible step.

## Documentation

- The site and the proto comments state the protocol as it is. A change to
  behavior updates the page and the proto comment that describe it, and the
  changelog entry (`proto/CHANGELOG.md` and the site changelog).
- Cite an external specification by its published name and section, at the
  version this repository implements.
