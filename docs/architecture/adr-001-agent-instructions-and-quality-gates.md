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
2. The hand-written code of every language is gated for format, lint, types,
   duplication, file length and inline suppressions: the SDK code, its tests,
   the corpus emitters, the scripts and the documentation site. Go has no type
   gate of its own, because its compiler and `go vet` check its types.
   Generated code is excluded.
3. Every gate runs its tool through `scripts/gates/ratchet.py`, against a
   committed baseline of the findings the repository inherited:
   - a finding that is not in the baseline fails the build;
   - a baseline entry that no longer occurs fails the build;
   - CI fails when a baseline gained an entry, or a size it allows got worse,
     since the change left the base branch: the comparison is with the baseline
     at their merge base, so a branch behind its base is not failed for an entry
     the base dropped after the branch left it. The one exception is a finding
     in a tree that the merge base excluded from the gates and this change
     brings inside them, and CI fails when the list of excluded trees grew.

   A finding is identified by its path, rule and message and by the text of the
   line it points at, not by its line number, so unrelated edits do not churn
   the baseline and two findings of one rule in one file are two entries.
   Editing the line a finding points at makes it a new finding; a line that
   moves to another file unedited keeps its entry, which `record` carries to the
   new file, as long as the findings with that rule, message and line text do
   not grow in number and none of their sizes gets worse. A clone, which the
   duplication gate reports with no line, is identified by its two files and a
   hash of the fragment jscpd reports: the text of one of its two copies, picked
   by the order jscpd reads the files in, through the token after it. Its entry
   is carried to wherever jscpd reports the same hash. A rename or a move that
   changes that order, or an edit right after the copy, can change the hash;
   the inherited clone is then new, and neither the move rules nor git's
   renames carry it. That is accepted, not designed around: the duplication
   baseline holds inherited clones only until they are removed, and a clone
   that turns new is removed in that change. When a file that
   decides what a gate's tool reports changes (the tool's version pin, its
   config, its scanner, each passed by the gate script or the helper it runs,
   or the reader of the gate's format), in a change that edits nothing else but
   baselines, the findings of each file take that file's entries, whatever
   their rule, message or line, at the sizes the tool now measures, as long as
   the file has no more findings than before: the code did not change, so what
   changed is how the tool reads it. A tool that a manifest and a lockfile pin
   is named by its part of them: its key in the manifest, and its package in
   the lockfile, with the packages only the gate's tools bring and the entries
   that record its pin. The rest of those files is the code's own version and
   dependencies, so an edit to it is an edit to something else. A
   finding that measures a size (a line's, a function's or a file's length, an
   argument count, a complexity) keeps that size apart from its message: the
   baseline records the worst size it allows, the build fails when the size
   gets worse, and `record` tightens it when it improves. For most measures a
   larger size is worse; for a maintainability index a smaller one is.
4. Inherited findings that a sweep fixes mechanically (formatting, import order,
   autofixable lint, plain annotation gaps) are fixed when the gate is
   introduced. The rest go into the baseline and are removed package by package.
5. No inline suppressions. An exclusion goes in the tool's config with a comment
   giving its reason. Exclusion lists only shrink. An inherited suppression's
   baseline entry never moves to another file, by a move or a copy, where it
   would silence code it was not written for; it follows its file only when git
   sees the file renamed. The inline-suppression gate
   (`scripts/gates/gate-inline-suppressions.sh`) lists every inline form in the
   hand-written code and runs it through the same ratchet, so a new one fails
   the build and the inherited ones can only go down.
6. A gate whose tool is missing fails; it is never skipped.
7. `scripts/gates/run.sh` finds every `scripts/gates/gate-*.sh` and runs it.
   `scripts/ci-local.sh` runs it locally and `.github/workflows/gates.yml` runs it
   in CI, for every pull request, every push to main and every release. Each CI
   run compares the baselines with a base that a rerun cannot move: a pull
   request's base side, the commit main pointed at before a push, and, for a
   release tag, where the tagged commit left main: for a commit on main that is
   the commit itself, which passed main's check, and for a commit off main it
   covers every commit since it left. Any other trigger
   fails until it is given a base (`scripts/gates/ci-base-ref.sh`).
8. Every language has size and complexity limits: file length, function length,
   argument count and complexity (AGENTS.md lists them). The complexity limits
   follow published guidance: cyclomatic complexity 10, McCabe's limit, which
   NIST SP 500-235 recommends, and cognitive complexity 15, the default of the
   tools that measure it. The size limits are this repository's own choice; no
   comparable published evidence exists for them. They apply to test files as
   to any other file. They make a god function or a god file fail the build
   mechanically. They do not find a missing abstraction, which is what review
   is for. File length is checked by one gate for every language,
   `scripts/gates/gate-file-length.sh`, so no tool's config sets a file-length
   rule.
9. The gates find what is textual: a pasted copy, a long function, a new
   suppression. A copy that was rewritten instead of pasted, the same behavior
   tested again in another language, and data restated in another format are
   not textual, and no deterministic check finds them. A review after CI passes
   looks for them, and AGENTS.md tells contributors to search for the existing
   helper first.
10. Generated code is declared in one place, the `GENERATED` list in
    `scripts/gates/scope.py`, each entry naming its generator, and every
    generated file says so in its first lines. Every other tracked source file
    is hand-written and gated by every gate of its language, the documentation
    site (`website/`) included. No path is excluded: the `EXCLUDED` list in
    `scope.py`, which once held the site, is empty and only shrinks. The scope
    gate (`scripts/gates/gate-scope.sh`) asks each gate's tool which files it
    reads and fails on a hand-written file a gate leaves out, or a generated
    file a gate reads. A tool's config cannot leave a hand-written file out unnoticed.
11. A rule is enforced by the strongest means that can express it. First,
    types and construction make the wrong state unrepresentable: one place
    states a fact and everything else derives from it. Where types cannot
    express the rule, a static check refuses the form: a name ban per concern,
    or a structural ban for a call or a composition a name ban cannot see. An
    exemption goes by path in the rule's own config, with its reason, and the
    outstanding violations only shrink. A check that finds the wrong form after
    it is written catches only the cases its author thought of, so a scanner
    written by hand is added only when the change asks for one and covers the
    forms the tree contains. A guard is seen to fail on the defect that prompted it
    and on each of those forms; a form nobody writes is a known limit recorded
    in the guard's header. AGENTS.md
    states this order and names what enforces each level today, including the
    levels no tool covers yet.

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
  renamed and rewritten until git no longer sees the rename keeps nothing. A
  clone follows neither rule: a rename, a split or a move keeps its entry only
  while jscpd reports the same hash for it (decision 3).
- A change to a gate's tool re-keys the baseline only when the change edits
  nothing else but baselines, because a tool that reads several files at once
  (a type checker, a duplication finder) can report a finding in one file that
  an edit to another caused. The same holds for what the code depends on: a
  manifest or lockfile that pins a tool pins the code's dependencies too, and a
  dependency's new version can change what a type checker reports in code nobody
  edited, so an edit to the rest of such a file re-keys nothing. A tool upgrade
  that moves a dependency the tool shares with the code therefore waits until
  that dependency has moved in a change of its own, which fixes any finding it
  causes. Within a file one finding can take the place of
  another without the file's count growing; with no code changed, that is the
  tool reading the same code anew. A tool or config change therefore comes in a
  change of its own, which also keeps the change visible in review. A formatter that rewrites
  lines makes the findings on them new, as any edit to a line does, and they
  are fixed in the change that reformats.
