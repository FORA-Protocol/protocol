#!/usr/bin/env python3
"""Run a gate's tool and compare its findings against a shrink-only baseline.

Every gate in this repository runs through this script. The tool's findings are
compared against the gate's committed baseline of inherited findings:

- A finding that is not in the baseline fails the gate. New code is held to zero.
- A baseline entry that no longer occurs also fails the gate, and names the entry
  to delete. The baseline only ever shrinks, and it never hides a fixed finding.
- A finding that measures a size (a function's length or complexity, an argument
  count, a line's or a file's length) is baselined at its size. The gate fails
  when the size grows, and when it shrank until `record` lowers it.
- With --base-ref, the baseline is compared against the one the gate script
  (--gate) named where HEAD left that git ref (their merge base), and any entry
  or size beyond what the ref allowed there, once moved findings have carried
  their entries (below), fails the gate. A baseline cannot grow by hand edit
  either. Only a gate script that does not
  exist at the merge base has no earlier baseline; a baseline that the gate named
  there and that is missing there fails, and so does a ref that is empty, does
  not resolve, or shares no history with HEAD.
- A finding in a tree that scope.py's EXCLUDED declared at the merge base and no
  longer declares is inherited; EXCLUDED itself only shrinks (exclusions.py).

A finding is identified by its path, its rule, its message and the text of the
line it points at, never by its line number: an edit elsewhere in a file does not
move its entry, and two findings of one rule in one file are two entries. Editing
the line a finding points at makes it a new finding. Identical findings in one
file are counted, and their sizes are compared largest to largest. A finding
whose line moves to another file unedited keeps its entry: `record` carries the
entry to the finding's new file and the --base-ref check accepts it, as long as
the findings with that format's move key (carry.py; by default the rule, message
and line text) do not grow in number and none of their sizes gets worse.

A run whose tool failed fails the gate before any comparison: an exit code the
tool's format does not list, output the format cannot read, or an exit code that
says the tool found something with no finding in the output (formats.py).

Usage:
  ratchet.py [check] --format FMT --baseline FILE [--base-ref REF --gate GATE] [TOOLS] -- CMD...
  ratchet.py record  --format FMT --baseline FILE [--base-ref REF --gate GATE] [TOOLS] -- CMD...
  TOOLS: --tool-file FILE, once for each file that decides what the tool reports.

The command may also follow the options, and `check` is the default, so a gate
script passes its own arguments through unchanged: `gate-x.sh record` records and
`gate-x.sh --base-ref REF` checks.

`record` writes the baseline. When the baseline file exists, `record` keeps only
the entries that still occur, carries an entry to where its finding moved with
its line, lowers each size that shrank, and otherwise never adds an entry or
raises a size; it creates a baseline only when the file does not exist yet, which
is how a gate is introduced. With --base-ref, `record` carries what the baseline at the merge
base allows instead, renamed and copied files included: a finding about a whole
file (with no line) follows its file when git sees it renamed, and a copy takes
its source's entry when the source no longer has that finding. An entry the
existing baseline already holds stays no larger than it is there, except where a
tool change re-keys it (below), and a missing baseline is rebuilt from what the
merge base allows. Stage new files first, so
git sees them.

The gate script and the helper it runs pass, with --tool-file, each file that
decides what the tool reports: its version pin, its config, its scanner
(toolfiles.py, which also reads the part of a file a tool file names). The
reader of the gate's format in formats.py is one too. The --base-ref commands
re-key the baseline when one of the tool files the scripts declared at the merge
base changed since, and the change edits no other file but baselines: the
findings of each file then take that file's entries whatever their rule, message
or line, at the sizes the tool now measures, as long as the file has no more
findings than before. A change that also edits any other file re-keys nothing,
because the tools that read more than one file at a time (a type checker, a
duplication finder) can report a finding in one file that an edit to another
caused; so a change of tool cannot carry a finding that code brought. A tool
file first declared in the same change unlocks nothing.

This script runs the tool and git and reads and writes the files; baseline.py
holds the baseline model and its comparisons, carry.py the rules that carry an
entry to where its finding went, formats.py the finding model and each tool's
reader, and toolfiles.py what a gate script declares. The script needs only the
Python standard library.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

from baseline import (
    BaselineError,
    State,
    cap,
    compare,
    describe,
    dump_baseline,
    exceeds,
    load_baseline,
    record,
    restrict,
    section,
)
from carry import Carried, Changes, Policy, carry, policy_of
from exclusions import left_since, with_inherited
from formats import FORMATS, Finding, Format, measure, relpath
from scope import REPO_ROOT, lines
from toolfiles import Declared, declare, path_of, reader_spec, tool_edits, unreadable

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


# How many of the other files a tool change edits its message names.
LISTED = 5


def fail(message: str) -> NoReturn:
    raise SystemExit(f"ratchet: {message}")


def report_carried(what: str, carried: list[Carried]) -> None:
    """List on stderr each entry carried to where its finding moved, so a log shows it."""
    if carried:
        sys.stderr.write(f"ratchet: {what}:\n" + "".join(f"{c}\n" for c in carried))


def read_baseline(text: str, where: str) -> State:
    """Parse a baseline file's text, or fail naming `where`."""
    try:
        return load_baseline(text, where)
    except BaselineError as exc:
        fail(str(exc))


class Sources:
    """The lines of the files findings point at, read once per file."""

    def __init__(self) -> None:
        self.files: dict[str, list[str]] = {}

    def line(self, path: str, number: int) -> str:
        if path not in self.files:
            p = Path(path) if Path(path).is_absolute() else REPO_ROOT / path
            try:
                self.files[path] = lines(p.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                fail(f"cannot read {path}, which a finding points at: {exc}")
        found = self.files[path]
        if number > len(found):
            fail(f"a finding points at line {number} of {path}, which has {len(found)} lines")
        return found[number - 1].strip()


def run_tool(fmt: Format, cmd: list[str]) -> State:
    """Run `cmd` from the repository root, check that it ran, and measure its findings."""
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    sys.stderr.write(proc.stderr)
    name, code = cmd[0], proc.returncode
    if code not in fmt.ran | fmt.found:
        sys.stderr.write(proc.stdout)
        fail(f"{name} failed with exit code {code}")
    try:
        reported = fmt.parse(proc.stdout)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        fail(f"cannot read the output of {name}: {exc}")
    if code in fmt.found and not reported:
        fail(
            f"{name} exited {code}, which means it reported something, "
            "but no finding is in its output"
        )
    state, sources = State(), Sources()
    for r in reported:
        if not fmt.keep(r):
            continue
        message, size, lower = measure(fmt, r.message)
        source = sources.line(r.path, r.line) if r.line is not None else ""
        state.add(
            Finding(r.path, r.rule, message, source), size if r.size is None else r.size, lower
        )
    return state


def git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )


def git_show(commit: str, rel: str) -> str | None:
    """Return the file `rel` as of `commit`, or None if it does not exist there."""
    proc = git("show", f"{commit}:{rel}")
    return proc.stdout if proc.returncode == 0 else None


def read_now(rel: str) -> str | None:
    """Return the file `rel` as it is in the tree now, or None if it does not exist."""
    try:
        return (REPO_ROOT / rel).read_text(encoding="utf-8")
    except OSError:
        return None


def declaration(text: str, where: str, read: Callable[[str], str | None]) -> Declared:
    """Return what the gate script `where` (with `text`) and its helper declare, or fail."""
    try:
        return declare(text, where, read)
    except ValueError as exc:
        fail(str(exc))


def gate_script(given: Path, rel: str) -> str:
    """Return the gate script `given`, relative to the root, after checking that it names `rel`."""
    p = given if given.is_absolute() else Path.cwd() / given
    gate = relpath(str(p.resolve()))
    text = read_now(gate)
    if text is None:
        fail(f"--gate {given}: cannot read the gate script")
    if rel not in declaration(text, gate, read_now).baselines:
        fail(f"--gate {gate} does not name the baseline {rel}")
    return gate


def gate_at(commit: str, gate: str, renames: Mapping[str, str]) -> str | None:
    """Return the text of `gate` at `commit`, following a rename, or None if it is new."""
    text = git_show(commit, gate)
    if text is not None:
        return text
    old = next((old for old, new in renames.items() if new == gate), None)
    return None if old is None else git_show(commit, old)


def paths_at(commit: str) -> frozenset[str]:
    """Return the paths of the files in `commit`."""
    proc = git("ls-tree", "-r", "-z", "--name-only", commit)
    if proc.returncode != 0:
        fail(f"git ls-tree of {commit[:12]} failed: {proc.stderr.strip()}")
    return frozenset(p for p in proc.stdout.split("\0") if p)


def changes_since(commit: str) -> Changes:
    """Return what git sees renamed, copied and changed between `commit` and the tree now.

    The tree includes uncommitted edits to tracked files; a new file counts once
    it is staged.
    """
    proc = git("diff", "--name-status", "-z", "-M", "-C", "--no-color", "--no-ext-diff", commit)
    if proc.returncode != 0:
        fail(f"git diff against {commit[:12]} failed: {proc.stderr.strip()}")
    fields = proc.stdout.split("\0")
    renames: dict[str, str] = {}
    copies: list[tuple[str, str]] = []
    changed: set[str] = set()
    i = 0
    while i + 1 < len(fields):
        status, path = fields[i], fields[i + 1]
        if status[:1] not in ("R", "C"):
            changed.add(path)
            i += 2
            continue
        new = fields[i + 2]
        if status[0] == "R":
            renames[path] = new
            changed.add(path)
        else:
            copies.append((path, new))
        changed.add(new)
        i += 3
    return Changes(renames, tuple(copies), frozenset(changed))


def merge_base(ref: str) -> str:
    """Return the commit where HEAD's history left `ref`'s: their merge base.

    Comparing there, rather than with the tip of `ref`, holds a change to what it
    added: a branch behind `ref` is not failed for an entry that `ref` dropped
    after the branch left it. The commit is named on stderr.
    """
    commit = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").stdout.strip()
    if not commit:
        fail(f"--base-ref {ref} does not name a commit here (fetch it, or check its spelling)")
    base = git("merge-base", commit, "HEAD").stdout.strip()
    if not base:
        fail(f"--base-ref {ref} has no history in common with HEAD here (fetch the full history)")
    sys.stderr.write(f"ratchet: comparing with {ref} at its merge base with HEAD, {base[:12]}\n")
    return base


@dataclass(frozen=True)
class Earlier:
    """The baseline a gate had where HEAD left a ref, and what changed since then."""

    ref: str
    baseline: State
    changes: Changes
    left: tuple[str, ...] = ()

    def carried_to(self, now: State, policy: Policy) -> State:
        """Return what the baseline allows at `now`'s identities, with `left`'s trees inherited."""
        allowed, carried = carry(self.baseline, now, policy, self.changes)
        report_carried(f"entries carried since {self.ref}", carried)
        return with_inherited(allowed, now, self.left, self.ref)


def tool_change(ref: str, commit: str, changes: Changes, specs: frozenset[str]) -> Changes:
    """Return `changes`, re-keying them when a tool file of `specs` changed since `commit`.

    `specs` are the tool files the gate's scripts declared at `commit`, and the
    reader of its format. A re-key needs a change that edits nothing but those
    files and baselines; any other edit leaves `changes` as they are.
    """
    edited, others = tool_edits(specs, changes.changed, lambda rel: git_show(commit, rel), read_now)
    if not edited:
        return changes
    named = ", ".join(edited)
    if others:
        more = f" and {len(others) - LISTED} more" if len(others) > LISTED else ""
        sys.stderr.write(
            f"ratchet: the gate's tool changed since {ref} ({named}), but this change also "
            f"edits {', '.join(others[:LISTED])}{more}, so nothing is re-keyed: an edit to "
            "one file can change what the tool reports in another. Change the tool in a "
            "change of its own\n"
        )
        return changes
    sys.stderr.write(
        f"ratchet: the gate's tool changed since {ref} ({named}), and this change edits "
        "nothing else: the findings of each file are re-keyed at their sizes now\n"
    )
    return replace(changes, tool_changed=True, at_base=paths_at(commit))


def earlier(ref: str, gate: str, fmt: str) -> Earlier | None:
    """Return the baseline `gate` named at the merge base of `ref` and HEAD.

    Only a gate whose script does not exist there has none, because it is being
    introduced; that returns None. Anything else that cannot be read there fails,
    so that the check never passes without comparing.
    """
    commit = merge_base(ref)
    left = left_since(lambda rel: git_show(commit, rel), ref, fail)
    changes = changes_since(commit)
    old_gate = gate_at(commit, gate, changes.renames)
    if old_gate is None:
        sys.stderr.write(
            f"ratchet: {gate} is new since {ref}, so its baseline has no earlier version\n"
        )
        return None
    at = f"at {commit[:12]} (the merge base with {ref})"
    named = declaration(old_gate, gate, lambda rel: git_show(commit, rel))
    if len(named.baselines) != 1:
        found = sorted(named.baselines)
        fail(f"{gate} {at} names {len(found)} baselines, not one: {found}")
    (old,) = named.baselines
    old_text = git_show(commit, old)
    if old_text is None:
        fail(f"{gate} {at} names the baseline {old}, which does not exist there")
    changes = tool_change(ref, commit, changes, named.tool_files | {reader_spec(fmt)})
    return Earlier(ref, read_baseline(old_text, f"{old} {at}"), changes, left)


def grown_since(baseline: State, found: Earlier, policy: Policy) -> list[str]:
    """Return the entries and sizes `baseline` has above the one `found` holds.

    An entry whose finding moved with its line, or with its renamed or copied
    file, is carried to where it is now first (carry.py).
    """
    ref = found.ref
    added, raised = exceeds(baseline, found.carried_to(baseline, policy))
    return [
        *section(
            f"baseline entries added since {ref} (a baseline only shrinks):",
            (describe(f, n) for f, n in sorted(added.items())),
        ),
        *section(f"baseline sizes raised since {ref}, as ({ref}, now):", raised),
    ]


def parse(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    """Return the options before `--`, and the tool command after it."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("command", nargs="?", default="check", choices=["check", "record"])
    parser.add_argument("--format", required=True, choices=sorted(FORMATS))
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--base-ref", help="git ref whose baseline this one may not exceed")
    parser.add_argument("--gate", type=Path, help="the gate script; required with --base-ref")
    parser.add_argument(
        "--tool-file",
        action="append",
        default=[],
        help="a file, or PATH#PART, that decides what the tool reports: its version pin, "
        "its config or its scanner (repeatable; the gate script or its helper passes each)",
    )
    split = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:split])
    cmd = argv[split + 1 :]
    if not cmd:
        parser.error("the tool command follows --")
    if args.base_ref is not None and not args.base_ref:
        parser.error("--base-ref needs a ref; an empty one would compare nothing")
    if args.base_ref is not None and args.gate is None:
        parser.error("--base-ref needs --gate, the gate script whose baseline it compares")
    for tool in args.tool_file:
        refusal = refuse_tool_file(tool, args)
        if refusal:
            parser.error(f"--tool-file {tool} {refusal}")
    return args, cmd


def refuse_tool_file(tool: str, args: argparse.Namespace) -> str | None:
    """Return why `tool` cannot be a --tool-file of this gate, or None if it can."""
    if args.gate is None:
        return "needs --gate, the gate script that passes it"
    if relpath(str(REPO_ROOT / path_of(tool))) == relpath(str(baseline_path(args))):
        return "is the baseline, which every `record` changes"
    refusal = unreadable(tool, read_now)
    if refusal:
        return refusal
    gate = args.gate if args.gate.is_absolute() else Path.cwd() / args.gate
    try:
        text = gate.read_text(encoding="utf-8")
    except OSError as exc:
        return f"cannot be checked against the gate script: {exc}"
    if tool in declaration(text, str(args.gate), read_now).tool_files:
        return None
    return f"is not passed by the gate script {args.gate} or the helper it runs"


def write_baseline(
    current: State, baseline: State | None, path: Path, found: Earlier | None, policy: Policy
) -> int:
    """Run `record`: write the baseline `current` leaves behind, and report what it refused.

    With --base-ref (`found`), what the merge base's baseline allows is carried to
    the identities the findings have now, renames and copies included; an entry
    the existing baseline already holds stays no larger than it is there.
    """
    prior = None
    if found is not None:
        prior = found.carried_to(current, policy)
        if baseline is not None:
            # A tool change re-measures the files it re-keys; every other entry stays
            # no larger than the working baseline holds it.
            kept = restrict(baseline, lambda f: not found.changes.rekeys(f.path))
            prior = cap(prior, kept)
    elif baseline is not None:
        prior, carried = carry(baseline, current, policy)
        report_carried("entries carried to where their finding moved", carried)
    written, refused = record(current, prior)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_baseline(written))
    print(f"ratchet: wrote {len(written.counts)} entries to {relpath(str(path))}")
    for line in refused:
        print(line)
    return 1 if refused else 0


def check(current: State, baseline: State, found: Earlier | None, policy: Policy) -> int:
    """Run `check`: report what `current` and `baseline` disagree on, and the --base-ref check."""
    problems = compare(current, baseline)
    if exceeds(current, baseline)[0] and exceeds(baseline, current)[0]:
        _, carried = carry(baseline, current, policy)
        problems += section(
            "findings that moved to another file (run `record` to carry their entries):",
            map(str, carried),
        )
        problems.append(
            "if a file was renamed or copied, or the gate's tool changed, "
            "`record --base-ref REF` carries their entries too"
        )
    if found is not None:
        problems += grown_since(baseline, found, policy)
    for line in problems:
        print(line)
    return 1 if problems else 0


def baseline_path(args: argparse.Namespace) -> Path:
    """Return --baseline, which a relative path names from the repository root."""
    given: Path = args.baseline
    return given if given.is_absolute() else REPO_ROOT / given


def main(argv: list[str]) -> int:
    """Run the `check` or `record` command; return the process exit code."""
    args, cmd = parse(argv)
    current = run_tool(FORMATS[args.format], cmd)
    policy = policy_of(args.format)
    path = baseline_path(args)
    rel = relpath(str(path))
    baseline = read_baseline(path.read_text(), rel) if path.exists() else None
    found = None
    if args.base_ref is not None:
        found = earlier(args.base_ref, gate_script(args.gate, rel), args.format)
    if args.command == "record":
        return write_baseline(current, baseline, path, found, policy)
    return check(current, baseline or State(), found, policy)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
