# ADR-001: Written instructions and shrink-only quality gates

Status: Accepted

## Context

Much of this repository's code is written by coding agents. An agent follows the
rules it can read and the checks that fail its build; it does not know a
convention that exists only in reviewers' heads. A review of seven branches found
73 defects. Most of them fell into four groups:

- copies of a helper, fixture or data list that already existed;
- tests that passed for the wrong reason;
- comments and changelog lines the code contradicted;
- lint findings no check reported.

The repository had no written instructions for contributors. Its CI ran
`go vet`, `buf lint` and the test suites, but no format, lint, type or
duplication check over the SDK code, the tests or the scripts. A first
measurement of the tree found 69 ruff findings, 38 Python files to reformat, 27
golangci-lint findings, about 690 mypy errors, 207 biome errors and 502
duplicated blocks.

## Decision

1. `AGENTS.md` at the repository root states the rules for each job: SDK code,
   conformance corpora, test suites, release scripts and documentation.
   `CLAUDE.md` imports it, so every agent reads the same text.
2. The hand-written code of every language is to be gated for format, lint,
   types, duplication, file length and inline suppressions: the SDK code, its
   tests, the corpus emitters and the scripts. Each language's gates are added
   in a change of their own. Go has no type gate of its own, because its
   compiler and `go vet` check its types. Generated code is excluded.
3. Every gate runs its tool through `scripts/gates/ratchet.py`, against a
   committed baseline of the findings the repository inherited:
   - a finding that is not in the baseline fails the build;
   - a baseline entry that no longer occurs fails the build;
   - CI fails when a baseline gained an entry, or a size it allows got worse,
     since the change left the base branch: the comparison is with the baseline
     at their merge base, so a branch behind its base is not failed for an entry
     the base dropped after the branch left it.

   A finding is identified by its path, rule and message and by the text of the
   line it points at, not by its line number, so unrelated edits do not churn
   the baseline and two findings of one rule in one file are two entries.
   Editing the line a finding points at makes it a new finding; a line that
   moves to another file unedited keeps its entry, which `record` carries to the
   new file, as long as the findings with that rule, message and line text do
   not grow in number and none of their sizes gets worse. When a file that
   decides what a gate's tool reports changes (the tool's version pin, its
   config, its scanner, each named by the gate script, or the module that reads
   every tool's output), the findings of each file the change does not edit
   take that file's entries, whatever their rule, message or line, at the sizes
   the tool now measures, as long as the file has no more findings than before:
   the code did not change, so what changed is how the tool reads it. A
   finding that measures a size (a line's, a function's or a file's length, an
   argument count, a complexity) keeps that size apart from its message: the
   baseline records the worst size it allows, the build fails when the size
   gets worse, and `record` tightens it when it improves. For most measures a
   larger size is worse; for a maintainability index a smaller one is.
4. Inherited findings that a sweep fixes mechanically (formatting, import order,
   autofixable lint, plain annotation gaps) are fixed when the gate is
   introduced. The rest go into the baseline and are removed package by package.
5. No inline suppressions. An exclusion goes in the tool's config with a comment
   giving its reason. Exclusion lists only shrink.
6. A gate whose tool is missing fails; it is never skipped.
7. `scripts/gates/run.sh` finds every `scripts/gates/gate-*.sh` and runs it.
   `scripts/ci-local.sh` runs it locally and `.github/workflows/gates.yml` runs it
   in CI, for every pull request, every push to main and every release. Each CI
   run compares the baselines with a base that a rerun cannot move: a pull
   request's base side, the commit main pointed at before a push, and a release
   tag's parent, the check its commit passed on reaching main. Any other trigger
   fails until it is given a base (`scripts/gates/ci-base-ref.sh`).
8. Every language has size and complexity limits: file length, function length,
   argument count and complexity, which AGENTS.md lists with each language's
   gates. The complexity limits follow published guidance: cyclomatic
   complexity 10, McCabe's limit, which NIST SP 500-235 recommends, and
   cognitive complexity 15, the default of the tools that measure it. The size limits are this repository's own choice; no
   comparable published evidence exists for them. They apply to test files as
   to any other file. They make a god function or a god file fail the build
   mechanically. They do not find a missing abstraction, which is what review
   is for.
9. The gates find what is textual: a pasted copy, a long function, a new
   suppression. A copy that was rewritten instead of pasted, the same behavior
   tested again in another language, and data restated in another format are
   not textual, and no deterministic check finds them. A review after CI passes
   looks for them, and AGENTS.md tells contributors to search for the existing
   helper first.
10. Generated code is declared in one place, the `GENERATED` list in
    `scripts/gates/scope.py`, each entry naming its generator, and every
    generated file says so in its first lines. Every other tracked source file
    is hand-written and gated by every gate of its language. The one other
    exclusion is the documentation site (`website/`), declared in the
    `EXCLUDED` list in `scope.py` with its reason: it has its own toolchain,
    and these gates do not cover it. No other path may be excluded.

## Consequences

- New code is held to zero findings from the day its gate lands, while the
  inherited debt is visible in one file per gate and can only go down.
- A rule a tool cannot check lives in `AGENTS.md` and in review. When a rule
  keeps being broken in review, the remedy is a check, not more text.
- A baseline entry names a path and a message. When the line a finding points
  at moves to another file unedited, by a rename, a split or a move, `record`
  carries the entry, and the baseline diff shows the move. The findings with
  one rule, message and line text never grow in number, so a finding can take
  the place of an identical one that left another file in the same change, as
  identical findings in one file are counted together. A finding about a whole
  file has no line to move with: it follows its file when git sees the file
  renamed, and a file git sees as a copy takes its source's entry when the
  source no longer has that finding; `record --base-ref` carries those. A file
  renamed and rewritten until git no longer sees the rename keeps nothing.
- A change to a gate's tool re-keys only the files the change does not edit.
  Within such a file one finding can take the place of another without the
  file's count growing, so a tool or config change comes in a change of its
  own, which also keeps the change visible in review. A formatter that rewrites
  lines makes the findings on them new, as any edit to a line does, and they
  are fixed in the change that reformats.
