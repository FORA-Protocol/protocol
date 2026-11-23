"""The finding model and the reader for each tool the gates run.

A Format reads one tool's output. Its parser turns the tool's stdout into the
findings the tool reported: a path relative to the repository root, a rule, a
message, and the line the finding points at when the tool names one. The Format
also states which exit codes mean the tool ran, which of those mean it found
something, and which values in its messages measure a size. ratchet.py runs the
tool, checks the run against those, and compares the findings against the gate's
baseline; it reads FORMATS by the name a gate passes as --format.

Each tool's Format has a test in its own test_ratchet_<tool>.py that reads a real
sample of that tool's output, recorded by testdata/record.sh; test_ratchet.py
covers the `lines` format, the one a scanner written in this repository prints.
A parser refuses output it cannot read with a ValueError, so a tool that
wrote something else fails its gate instead of reading as a run with no findings.
The module needs only the Python standard library.
"""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from scope import REPO_ROOT

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True)
class Reported:
    """One finding as its tool reported it.

    `line` is the 1-based line the finding points at, or None for a finding about
    a whole file. `size` is a size the tool states apart from its message (only
    the `lines` format has one); every other size is measured from the message.
    """

    path: str
    rule: str
    message: str
    line: int | None = None
    size: int | None = None


@dataclass(frozen=True, order=True)
class Finding:
    """A finding's identity in the baseline: never its line number.

    `source` is the text of the line the finding points at, stripped, or "" for a
    finding with no line. A finding that moves keeps its identity; two findings of
    one rule in one file, with the same message, are told apart by their lines.
    """

    path: str
    rule: str
    message: str
    source: str = ""


@dataclass(frozen=True)
class Size:
    """A measured value in a tool's message, which the baseline keeps apart from it.

    `pattern` names the value `size`. Most sizes are worse when larger: a
    function's length, an argument count, a complexity. A maintainability index
    is worse when smaller, and `lower_is_worse` says so.
    """

    pattern: re.Pattern[str]
    lower_is_worse: bool = False


@dataclass(frozen=True)
class Format:
    """How to read one tool's output, and how to tell a run that worked from one that did not.

    `ran` lists the exit codes of a run that worked; any other code is a failed
    run. `found` lists the codes among them that the tool uses to say it reported
    something, so a run that exits with one and holds no finding failed (a crash
    that exits 1, for one). `keep` drops the findings another gate reports.
    `sizes` are the measured values the tool's messages carry, and `unstable` the
    values that change with unrelated edits and measure nothing the gate can
    hold; both are replaced by `N` in the message. `line_refs` replaces the
    number in a reference to another line ("defined on line 12"), which moves
    with every edit above it.
    """

    parse: Callable[[str], list[Reported]]
    ran: frozenset[int]
    found: frozenset[int] = frozenset()
    keep: Callable[[Reported], bool] = lambda _: True
    sizes: tuple[Size, ...] = ()
    unstable: tuple[re.Pattern[str], ...] = ()
    line_refs: bool = True


def relpath(path: str) -> str:
    """Return `path` relative to the repository root, with forward slashes."""
    p = Path(path)
    if p.is_absolute():
        # A path outside the repository stays absolute, so the finding still names it.
        with contextlib.suppress(ValueError):
            p = p.resolve().relative_to(REPO_ROOT)
    return p.as_posix().removeprefix("./")


def line_number(value: object) -> int | None:
    """Return `value` as a 1-based line number, or None when the tool gave no line."""
    return value if isinstance(value, int) and value >= 1 else None


def load_json(out: str, tool: str) -> object:
    """Parse `out` as JSON, or refuse it as output that `tool` did not write."""
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise ValueError(f"not {tool} JSON output ({exc}): {out[:200]!r}") from exc


# The `lines` format, printed by a scanner written in this repository: one
# `path<TAB>rule<TAB>size<TAB>message` row per finding, where size is a whole
# number or `-` for none. The scanner states a size itself, so its message is
# taken as it is and never measured.
LINE_FIELDS = 4


def parse_lines(out: str) -> list[Reported]:
    """Read `path<TAB>rule<TAB>size<TAB>message` rows; blank lines are ignored."""
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t", LINE_FIELDS - 1)
        if len(parts) != LINE_FIELDS or not (parts[2] == "-" or parts[2].isdigit()):
            raise ValueError(f"not a path<TAB>rule<TAB>size<TAB>message line: {line!r}")
        path, rule, size, message = parts
        findings.append(
            Reported(relpath(path), rule, message, size=None if size == "-" else int(size))
        )
    return findings


# golangci-lint's formatters. `golangci-lint run` reports their findings next to
# the linters'; the lint gate drops them, because the format gate reports them.
GOLANGCI_FORMATTERS = frozenset({"gci", "gofmt", "gofumpt", "goimports", "golines", "swaggo"})


def parse_golangci_json(out: str) -> list[Reported]:
    """Read `golangci-lint run --output.json.path=stdout`."""
    report = load_json(out, "golangci-lint")
    issues = report.get("Issues", False) if isinstance(report, dict) else False
    if issues is not None and not isinstance(issues, list):
        raise ValueError(f"not a golangci-lint report with an Issues list: {out[:200]!r}")
    return [
        Reported(
            relpath(i["Pos"]["Filename"]),
            i["FromLinter"],
            i["Text"],
            line_number(i["Pos"]["Line"]),
        )
        for i in issues or []
    ]


GOLANGCI_FMT_FILE = re.compile(r"^diff (\S+)\.orig (\S+)$")
DIFF_LINE = re.compile(r"^(?:--- |\+\+\+ |@@ |[ +\-\\]|$)")


def parse_golangci_fmt_diff(out: str) -> list[Reported]:
    """Read `golangci-lint fmt --diff`: one finding for each file it would rewrite.

    Each file's diff opens with a `diff FILE.orig FILE` line. Any line that is
    neither that nor a line of a unified diff is refused.
    """
    findings = []
    for line in out.splitlines():
        m = GOLANGCI_FMT_FILE.match(line)
        if m:
            findings.append(
                Reported(relpath(m.group(2)), "golangci-lint fmt", "file is not formatted")
            )
        elif not findings or not DIFF_LINE.match(line):
            raise ValueError(f"not a line of golangci-lint fmt --diff output: {line!r}")
    return findings


def _size(pattern: str, *, lower_is_worse: bool = False) -> Size:
    return Size(re.compile(pattern), lower_is_worse)


# `(N > M)`: the measured value and the limit it exceeded, as funlen writes them.
OVER_LIMIT = _size(r"\((?P<size>\d+) > \d+\)")

GOLANGCI_SIZES = (
    OVER_LIMIT,  # funlen
    _size(r"\bThe line is (?P<size>\d+) characters\b"),  # lll
    _size(r"\bcomplexity (?P<size>\d+) of func\b"),  # gocognit, gocyclo
    _size(r"\bcomplexity for function \S+ is (?P<size>\d+),"),  # cyclop
    _size(r"\(complexity: (?P<size>\d+)\)"),  # nestif
    _size(r"\bmax \d+ but got (?P<size>\d+)\b"),  # revive argument-limit
    _size(r"\bfile length is (?P<size>\d+) lines\b"),  # revive file-length-limit
    _size(r"\bMaintainability Index: (?P<size>\d+)\b", lower_is_worse=True),  # maintidx
)
# maintidx also prints the two values its index is computed from; the index is
# the one the baseline holds.
GOLANGCI_UNSTABLE = (re.compile(r"\b(?:Cyclomatic Complexity|Halstead Volume): (?P<drop>[\d.]+)"),)

FORMATS: dict[str, Format] = {
    # A scanner exits 0 whatever it finds; any other exit is a crash.
    "lines": Format(parse_lines, ran=frozenset({0}), line_refs=False),
    # golangci-lint exits 1 when it reports an issue; any other non-zero code is a
    # failed run. The lint gate leaves the formatters' issues to the format gate.
    "golangci-lint": Format(
        parse_golangci_json,
        ran=frozenset({0}),
        found=frozenset({1}),
        keep=lambda r: r.rule not in GOLANGCI_FORMATTERS,
        sizes=GOLANGCI_SIZES,
        unstable=GOLANGCI_UNSTABLE,
    ),
    # `golangci-lint fmt --diff` exits 1 when it prints a diff.
    "golangci-lint-fmt": Format(parse_golangci_fmt_diff, ran=frozenset({0}), found=frozenset({1})),
}
