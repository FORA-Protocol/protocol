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
  (--gate) named at that git ref, and any entry or size the ref does not allow
  fails the gate. A baseline cannot grow by hand edit either. Only a gate script
  that does not exist at the ref has no earlier baseline; a baseline that the
  gate named at the ref and that is missing there fails.

A finding is identified by its path, its rule, its message and the text of the
line it points at, never by its line number: an edit elsewhere in a file does not
move its entry, and two findings of one rule in one file are two entries. Editing
the line a finding points at makes it a new finding. Identical findings in one
file are counted, and their sizes are compared largest to largest.

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
the entries that still occur, lowers each size that shrank, and never adds an
entry or raises a size; it creates a baseline only when the file does not exist
yet, which is how a gate is introduced.

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
from formats import FORMATS, Finding, Format, measure, relpath
from scope import REPO_ROOT

# Where the gates keep their baselines, and how a gate script names one.
BASELINE_PATH = re.compile(r"scripts/gates/baselines/[\w.-]+\.json")
GATES = "scripts/gates"


def fail(message: str) -> NoReturn:
    raise SystemExit(f"ratchet: {message}")


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


def grown_since(baseline: State, ref: str, gate: str) -> list[str]:
    """Return the entries and sizes `baseline` has above the one `gate` used at `ref`.

    Only a gate whose script does not exist at `ref` has nothing to compare
    against, because it is being introduced. Anything else that cannot be read
    at `ref` fails, so that the check never passes without comparing.
    """
    commit = git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").stdout.strip()
    if not commit:
        fail(f"--base-ref {ref} does not name a commit here (fetch it, or check its spelling)")
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
    added, raised = exceeds(baseline, read_baseline(old_text, f"{named[0]} at {ref}"))
    return [
        *section(
            f"baseline entries added since {ref} (a baseline only shrinks):",
            (describe(f, n) for f, n in sorted(added.items())),
        ),
        *section(f"baseline sizes raised since {ref}, as ({ref}, now):", raised),
    ]


def main(argv: list[str]) -> int:
    """Run the `check` or `record` command; return the process exit code."""
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
    if args.command == "record" and args.base_ref:
        parser.error("--base-ref belongs to check; record never compares against a ref")
    if args.base_ref and args.gate is None:
        parser.error("--base-ref needs --gate, the gate script whose baseline it compares")

    current = run_tool(FORMATS[args.format], cmd)
    path: Path = args.baseline if args.baseline.is_absolute() else REPO_ROOT / args.baseline
    rel = relpath(str(path))
    exists = path.exists()
    baseline = read_baseline(path.read_text(), rel) if exists else State()

    if args.command == "record":
        written, refused = record(current, baseline if exists else None)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(dump_baseline(written))
        print(f"ratchet: wrote {len(written.counts)} entries to {rel}")
        for line in refused:
            print(line)
        return 1 if refused else 0

    problems = compare(current, baseline)
    if args.base_ref:
        problems += grown_since(baseline, args.base_ref, gate_script(args.gate, rel))
    for line in problems:
        print(line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
