"""The finding model and the reader for each tool the gates run.

A Format reads one tool's output. Its parser turns the tool's stdout into the
findings the tool reported: a path relative to the repository root, a rule, a
message, and the line the finding points at when the tool names one. The Format
also states which exit codes mean the tool ran, which of those mean it found
something, and which values in its messages measure a size. ratchet.py runs the
tool, checks the run against those, and compares the findings against the gate's
baseline; it reads FORMATS by the name a gate passes as --format.

test_ratchet.py covers the `lines` format, the one a scanner written in this
repository prints. A parser refuses output it cannot read with a ValueError, so a tool that
wrote something else fails its gate instead of reading as a run with no findings.
The module needs only the Python standard library.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from scope import REPO_ROOT

if TYPE_CHECKING:
    import re
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


FORMATS: dict[str, Format] = {
    # A scanner exits 0 whatever it finds; any other exit is a crash.
    "lines": Format(parse_lines, ran=frozenset({0}), line_refs=False),
}
