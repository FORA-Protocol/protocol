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
  ratchet.py [check] --format FMT --baseline FILE [--base-ref REF --gate GATE] -- CMD [ARG...]
  ratchet.py record  --format FMT --baseline FILE -- CMD [ARG...]

The command may also follow the options, and `check` is the default, so a gate
script passes its own arguments through unchanged: `gate-x.sh record` records and
`gate-x.sh --base-ref REF` checks.

`record` writes the baseline. When the baseline file exists, `record` keeps only
the entries that still occur, carries an entry to where its finding moved with
its line, lowers each size that shrank, and never adds an entry or raises a size;
it creates a baseline only when the file does not exist yet, which is how a gate
is introduced.

This script runs the tool and git and reads and writes the files; baseline.py
holds the baseline model and its comparisons, and formats.py the finding model
and each tool's reader. The script needs only the Python standard library.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

from baseline import (
    BaselineError,
    State,
    compare,
    describe,
    dump_baseline,
    exceeds,
    load_baseline,
    record,
    section,
)
from carry import Carried, carry
from formats import FORMATS, Finding, Format, measure, relpath
from scope import REPO_ROOT

# Where the gates keep their baselines, and how a gate script names one.
BASELINE_PATH = re.compile(r"scripts/gates/baselines/[\w.-]+\.json")
GATES = "scripts/gates"


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


def gate_at(commit: str, gate: str) -> str | None:
    """Return the text of `gate` at `commit`, following a rename, or None if it is new."""
    text = git_show(commit, gate)
    if text is not None:
        return text
    renames = git("diff", "--name-status", "-M", commit, "--", GATES).stdout
    for line in renames.splitlines():
        status, *paths = line.split("\t")
        if status.startswith("R") and paths[-1] == gate:
            return git_show(commit, paths[0])
    return None


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


def grown_since(baseline: State, ref: str, gate: str, fmt: Format) -> list[str]:
    """Return the entries and sizes `baseline` has above the one `gate` used at `ref`.

    The baseline `ref` allowed is read at the merge base of `ref` and HEAD, and
    an entry whose finding moved with its line is carried to where it is now
    (carry.py). Only a gate whose script does not exist there has nothing to
    compare against, because it is being introduced. Anything else that cannot be
    read there fails, so that the check never passes without comparing.
    """
    commit = merge_base(ref)
    old_gate = gate_at(commit, gate)
    if old_gate is None:
        sys.stderr.write(
            f"ratchet: {gate} is new since {ref}, so its baseline has no earlier version\n"
        )
        return []
    named = sorted(set(BASELINE_PATH.findall(old_gate)))
    if len(named) != 1:
        fail(f"{gate} at {ref} names {len(named)} baselines, not one: {named}")
    old_text = git_show(commit, named[0])
    if old_text is None:
        fail(f"{gate} at {ref} names the baseline {named[0]}, which does not exist there")
    old = read_baseline(old_text, f"{named[0]} at {ref}")
    allowed, carried = carry(old, baseline, fmt.move_key)
    report_carried(f"entries carried since {ref} with the line their finding moved with", carried)
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
    split = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:split])
    cmd = argv[split + 1 :]
    if not cmd:
        parser.error("the tool command follows --")
    if args.base_ref is not None and not args.base_ref:
        parser.error("--base-ref needs a ref; an empty one would compare nothing")
    if args.command == "record" and args.base_ref is not None:
        parser.error("--base-ref belongs to check; record never compares against a ref")
    if args.base_ref is not None and args.gate is None:
        parser.error("--base-ref needs --gate, the gate script whose baseline it compares")
    return args, cmd


def write_baseline(fmt: Format, current: State, baseline: State | None, path: Path) -> int:
    """Run `record`: write the baseline `current` leaves behind, and report what it refused."""
    prior = None
    if baseline is not None:
        prior, carried = carry(baseline, current, fmt.move_key)
        report_carried("entries carried with the line their finding moved with", carried)
    written, refused = record(current, prior)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dump_baseline(written))
    print(f"ratchet: wrote {len(written.counts)} entries to {relpath(str(path))}")
    for line in refused:
        print(line)
    return 1 if refused else 0


def check(fmt: Format, current: State, baseline: State, args: argparse.Namespace) -> int:
    """Run `check`: report what `current` and `baseline` disagree on, and the --base-ref check."""
    problems = compare(current, baseline)
    if problems:
        _, carried = carry(baseline, current, fmt.move_key)
        problems += section(
            "findings whose line moved to another file (run `record` to carry their entries):",
            map(str, carried),
        )
    if args.base_ref is not None:
        rel = relpath(str(baseline_path(args)))
        problems += grown_since(baseline, args.base_ref, gate_script(args.gate, rel), fmt)
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
    baseline = read_baseline(path.read_text(), relpath(str(path))) if path.exists() else None
    if args.command == "record":
        return write_baseline(fmt, current, baseline, path)
    return check(fmt, current, baseline or State(), args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
