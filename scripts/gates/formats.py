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
covers the `lines` format of this repository's own scanners. A parser refuses output it
cannot read with a ValueError, so a tool that wrote something else fails its gate
instead of reading as a run with no findings. The module needs only the Python
standard library.
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


# The `lines` format, written by this repository's own scanners: one
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


def parse_ruff(out: str) -> list[Reported]:
    """Read `ruff check` or `ruff format --check` run with `--output-format json`.

    Ruff prints one JSON array, `[]` when it finds nothing. A lint finding points
    at its line. A format finding (rule `unformatted`) is about the whole file:
    its location is the first place the formatter would change, which moves.
    """
    rows = load_json(out, "ruff")
    if not isinstance(rows, list):
        raise ValueError(f"ruff prints a JSON array: {out[:200]!r}")
    findings = []
    for f in rows:
        if not f.get("code"):
            raise ValueError(f"a ruff finding with no rule code: {f!r}")
        line = None if f["code"] == "unformatted" else line_number(f["location"]["row"])
        findings.append(Reported(relpath(f["filename"]), f["code"], f["message"], line))
    return findings


def parse_mypy(out: str) -> list[Reported]:
    """Read mypy run with `--output json`: one JSON object per line.

    Only errors are findings: a note explains an error or reports a revealed type.
    """
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        f = load_json(line, "mypy")
        if not isinstance(f, dict):
            raise ValueError(f"mypy prints one JSON object per line: {line!r}")
        if f["severity"] != "error":
            continue
        if not f.get("code"):
            raise ValueError(f"a mypy error with no error code: {line!r}")
        findings.append(
            Reported(relpath(f["file"]), f["code"], f["message"], line_number(f["line"]))
        )
    return findings


def parse_biome(out: str) -> list[Reported]:
    """Read biome's `--reporter=json` output.

    Every diagnostic is a finding, whatever its severity: an info-level suggestion
    counts like an error, so the gate holds new code to zero diagnostics. A
    diagnostic's category ("format", "lint/style/useConst", ...) is its rule. A
    format diagnostic is about the whole file, and has no line. Output that lists
    fewer diagnostics than its summary counts, or says it left some out, is
    refused, because the missing ones would read as fixed.
    """
    report = load_json(out, "biome")
    if not isinstance(report, dict) or "summary" not in report or "diagnostics" not in report:
        raise ValueError(f"a biome report has a summary and diagnostics: {out[:200]!r}")
    summary = report["summary"]
    diagnostics = report["diagnostics"]
    counted = int(summary["errors"]) + int(summary["warnings"]) + int(summary["infos"])
    if summary.get("diagnosticsNotPrinted") or len(diagnostics) != counted:
        raise ValueError(
            f"biome listed {len(diagnostics)} of the {counted} diagnostics it counted "
            f"and left {summary.get('diagnosticsNotPrinted')} out; pass --max-diagnostics=none"
        )
    findings = []
    for d in diagnostics:
        line = None if d["category"] == "format" else d["location"].get("start", {}).get("line")
        path = relpath(d["location"]["path"])
        findings.append(Reported(path, d["category"], d["message"], line_number(line)))
    return findings


TSC_LINE = re.compile(
    r"^(?P<path>.+)\((?P<line>\d+),\d+\): (?:error|warning) (?P<rule>TS\d+): (?P<message>.*)$"
)


def parse_tsc(out: str) -> list[Reported]:
    """Read tsc's `--pretty false` output.

    A diagnostic is `path(line,col): error TSnnnn: message`, followed by indented
    lines that elaborate it; those are joined into the message. The repository's
    absolute path, which tsc prints inside some type names, is removed from every
    line, so the message is the same on every machine. A diagnostic with no file
    (a bad tsconfig, for one) is refused, because it means the check did not run.
    """
    findings: list[Reported] = []
    root = REPO_ROOT.as_posix() + "/"
    for line in out.splitlines():
        if not line.strip():
            continue
        if line.startswith(" ") and findings:
            last = findings.pop()
            joined = f"{last.message} {line.strip().replace(root, '')}"
            findings.append(Reported(last.path, last.rule, joined, last.line))
            continue
        m = TSC_LINE.match(line)
        if m is None:
            raise ValueError(f"not a tsc diagnostic line: {line!r}")
        message = m["message"].replace(root, "")
        findings.append(Reported(relpath(m["path"]), m["rule"], message, int(m["line"])))
    return findings


def _size(pattern: str, *, lower_is_worse: bool = False) -> Size:
    return Size(re.compile(pattern), lower_is_worse)


# `(N > M)`: the measured value and the limit it exceeded, as ruff and funlen write them.
OVER_LIMIT = _size(r"\((?P<size>\d+) > \d+\)")

GOLANGCI_SIZES = (
    OVER_LIMIT,  # funlen
    _size(r"\bThe line is (?P<size>\d+) characters\b"),  # lll
    _size(r"\bcomplexity (?P<size>\d+) of func\b"),  # gocognit, gocyclo
    _size(r"\bcomplexity for function \S+ is (?P<size>\d+),"),  # cyclop
    _size(r"\(complexity: (?P<size>\d+)\)"),  # nestif
    _size(r"\bmax \d+ but got (?P<size>\d+)\b"),  # revive argument-limit
    _size(r"\bMaintainability Index: (?P<size>\d+)\b", lower_is_worse=True),  # maintidx
)
# maintidx also prints the two values its index is computed from; the index is
# the one the baseline holds.
GOLANGCI_UNSTABLE = (re.compile(r"\b(?:Cyclomatic Complexity|Halstead Volume): (?P<drop>[\d.]+)"),)

BIOME_SIZES = (
    _size(r"\btoo many lines \((?P<size>\d+)\)"),  # noExcessiveLinesPerFunction
    _size(r"\bFunction has (?P<size>\d+) parameters\b"),  # useMaxParams
    _size(r"\bExcessive complexity of (?P<size>\d+) detected\b"),  # cognitive complexity
)

FORMATS: dict[str, Format] = {
    # This repository's scanners exit 0 whatever they find; any other exit is a crash.
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
    # Ruff exits 0 with no findings, 1 with findings, and 2 when it fails itself.
    "ruff": Format(parse_ruff, ran=frozenset({0}), found=frozenset({1}), sizes=(OVER_LIMIT,)),
    # Mypy exits 0 with no errors, 1 with errors, and 2 when it fails itself.
    "mypy": Format(parse_mypy, ran=frozenset({0}), found=frozenset({1})),
    # biome exits 1 when it reports an error (with --error-on-warnings, a warning).
    # An info-level diagnostic leaves the exit code at 0.
    "biome": Format(parse_biome, ran=frozenset({0}), found=frozenset({1}), sizes=BIOME_SIZES),
    # `tsc --noEmit` exits 2 when it reports a diagnostic in a file, and 1 when
    # it cannot read its project. Node exits 1 on an uncaught exception, so exit 1
    # is a failed run.
    "tsc": Format(parse_tsc, ran=frozenset({0}), found=frozenset({2})),
}
