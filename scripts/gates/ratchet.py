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
  or size the ref allowed there and the baseline exceeds fails the gate. A
  baseline cannot grow by hand edit either. Only a gate script that does not
  exist at the merge base has no earlier baseline; a baseline that the gate named
  there and that is missing there fails, and so does a ref that is empty, does
  not resolve, or shares no history with HEAD.

A finding is identified by its path, its rule, its message and the text of the
line it points at, never by its line number: an edit elsewhere in a file does not
move its entry, and two findings of one rule in one file are two entries. Editing
the line a finding points at makes it a new finding. Identical findings in one
file are counted, and their sizes are compared largest to largest. A finding
whose line moves to another file unedited keeps its entry: `record` carries the
entry to the finding's new file and the --base-ref check accepts it, as long as
the findings with that rule, message and line text do not grow in number and
none of their sizes gets worse (carry.py).

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
its line, lowers each size that shrank, and never adds an entry or raises a size;
it creates a baseline only when the file does not exist yet, which is how a gate
is introduced. With --base-ref, `record` carries what the baseline at the merge
base allows instead, renamed and copied files included: a finding about a whole
file (with no line) follows its file when git sees it renamed, and a copy takes
its source's entry when the source no longer has that finding. An entry the
existing baseline already holds stays no larger than it is there, and a missing
baseline is rebuilt from what the merge base allows. Stage new files first, so
git sees them.

A gate script names, with --tool-file, each file that decides what its tool
reports: its version pin, its config, its scanner. When one of the files it named
at the merge base, or formats.py, changed since, the --base-ref commands re-key
the findings of each file the change does not edit: they take that file's
entries whatever their rule, message or line, at the sizes the tool now measures,
as long as the file has no more findings than before. A file the change edits
keeps its exact entries, and a tool file first named in the same change unlocks
nothing.

This script runs the tool and git and reads and writes the files; baseline.py
holds the baseline model and its comparisons, and formats.py the finding model
and each tool's reader. The script needs only the Python standard library.
"""

from __future__ import annotations

import argparse
import re
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
from carry import Carried, Changes, carry
from formats import FORMATS, Finding, Format, measure, relpath
from scope import REPO_ROOT

if TYPE_CHECKING:
    from collections.abc import Mapping

# Where the gates keep their baselines, and how a gate script names one.
BASELINE_PATH = re.compile(r"scripts/gates/baselines/[\w.-]+\.json")
# The module that reads every tool's output into findings: a change to it is a change
# to what every gate reports.
FORMATS_FILE = "scripts/gates/formats.py"


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
                self.files[path] = p.read_text(encoding="utf-8", errors="replace").split("\n")
            except OSError as exc:
                fail(f"cannot read {path}, which a finding points at: {exc}")
        lines = self.files[path]
        if number > len(lines):
            fail(f"a finding points at line {number} of {path}, which has {len(lines)} lines")
        return lines[number - 1].strip()


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


def gate_script(given: Path, rel: str) -> str:
    """Return the gate script `given`, relative to the root, after checking that it names `rel`."""
    p = given if given.is_absolute() else Path.cwd() / given
    gate = relpath(str(p.resolve()))
    try:
        named = rel in (REPO_ROOT / gate).read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"--gate {given}: cannot read the gate script: {exc}")
    if not named:
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


def tool_change(ref: str, commit: str, changes: Changes, named: list[str]) -> Changes:
    """Return `changes`, saying whether one of the files `named` changed since `commit`.

    `named` are the tool files the gate script named at `commit`, and the reader of
    every tool's output. A tool file that the gate first names in this change does
    not count, so a change cannot name a file it edits to have its findings re-keyed.
    """
    edited = sorted(p for p in [*named, FORMATS_FILE] if p in changes.changed)
    if not edited:
        return changes
    sys.stderr.write(
        f"ratchet: the gate's tool changed since {ref} ({', '.join(edited)}): the findings "
        "of each file this change does not edit are re-keyed at their sizes now, and "
        "a file it edits keeps its exact entries\n"
    )
    return replace(changes, tool_changed=True, at_base=paths_at(commit))


def earlier(ref: str, gate: str, tool_files: list[str]) -> Earlier | None:
    """Return the baseline `gate` named at the merge base of `ref` and HEAD.

    Only a gate whose script does not exist there has none, because it is being
    introduced; that returns None. Anything else that cannot be read there fails,
    so that the check never passes without comparing.
    """
    commit = merge_base(ref)
    changes = changes_since(commit)
    old_gate = gate_at(commit, gate, changes.renames)
    if old_gate is None:
        sys.stderr.write(
            f"ratchet: {gate} is new since {ref}, so its baseline has no earlier version\n"
        )
        return None
    named = sorted(set(BASELINE_PATH.findall(old_gate)))
    if len(named) != 1:
        fail(f"{gate} at {ref} names {len(named)} baselines, not one: {named}")
    old_text = git_show(commit, named[0])
    if old_text is None:
        fail(f"{gate} at {ref} names the baseline {named[0]}, which does not exist there")
    changes = tool_change(ref, commit, changes, [t for t in tool_files if t in old_gate])
    return Earlier(ref, read_baseline(old_text, f"{named[0]} at {ref}"), changes)


def grown_since(baseline: State, found: Earlier, fmt: Format) -> list[str]:
    """Return the entries and sizes `baseline` has above the one `found` holds.

    An entry whose finding moved with its line, or with its renamed or copied
    file, is carried to where it is now first (carry.py).
    """
    ref = found.ref
    allowed, carried = carry(found.baseline, baseline, fmt.move_key, found.changes)
    report_carried(f"entries carried since {ref}", carried)
    added, raised = exceeds(baseline, allowed)
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
        help="a file that decides what the tool reports: its version pin, its config "
        "or its scanner (repeatable; the gate script names each one)",
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
        return "needs --gate, the gate script that names it"
    if not (REPO_ROOT / tool).is_file():
        return "does not exist; name it from the repository root"
    if relpath(str(REPO_ROOT / tool)) == relpath(str(baseline_path(args))):
        return "is the baseline, which every `record` changes"
    gate = args.gate if args.gate.is_absolute() else Path.cwd() / args.gate
    try:
        named = tool in gate.read_text(encoding="utf-8")
    except OSError as exc:
        return f"cannot be checked against the gate script: {exc}"
    return None if named else f"is not named by the gate script {args.gate}"


def write_baseline(
    fmt: Format, current: State, baseline: State | None, path: Path, found: Earlier | None
) -> int:
    """Run `record`: write the baseline `current` leaves behind, and report what it refused.

    With --base-ref (`found`), what the merge base's baseline allows is carried to
    the identities the findings have now, renames and copies included; an entry
    the existing baseline already holds stays no larger than it is there.
    """
    prior = None
    if found is not None:
        prior, carried = carry(found.baseline, current, fmt.move_key, found.changes)
        if baseline is not None:
            # A tool change re-measures the files it re-keys; every other entry stays
            # no larger than the working baseline holds it.
            kept = restrict(baseline, lambda f: not found.changes.rekeys(f.path))
            prior = cap(prior, kept)
        report_carried(f"entries carried since {found.ref}", carried)
    elif baseline is not None:
        prior, carried = carry(baseline, current, fmt.move_key)
        report_carried("entries carried with the line their finding moved with", carried)
    written, refused = record(current, prior)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_baseline(written))
    print(f"ratchet: wrote {len(written.counts)} entries to {relpath(str(path))}")
    for line in refused:
        print(line)
    return 1 if refused else 0


def check(fmt: Format, current: State, baseline: State, found: Earlier | None) -> int:
    """Run `check`: report what `current` and `baseline` disagree on, and the --base-ref check."""
    problems = compare(current, baseline)
    if exceeds(current, baseline)[0] and exceeds(baseline, current)[0]:
        _, carried = carry(baseline, current, fmt.move_key)
        problems += section(
            "findings whose line moved to another file (run `record` to carry their entries):",
            map(str, carried),
        )
        problems.append(
            "if a file was renamed or copied, or the gate's tool changed, "
            "`record --base-ref REF` carries their entries too"
        )
    if found is not None:
        problems += grown_since(baseline, found, fmt)
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
    fmt = FORMATS[args.format]
    current = run_tool(fmt, cmd)
    path = baseline_path(args)
    rel = relpath(str(path))
    baseline = read_baseline(path.read_text(), rel) if path.exists() else None
    found = None
    if args.base_ref is not None:
        found = earlier(args.base_ref, gate_script(args.gate, rel), args.tool_file)
    if args.command == "record":
        return write_baseline(fmt, current, baseline, path, found)
    return check(fmt, current, baseline or State(), found)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
