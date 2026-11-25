"""The readers of the SDK API gates' tools, one Format per tool, as formats.py has for the rest.

An API gate's command is scripts/gates/api_diff.py, which runs the tool against
the last release and prints the tool's own output. Every finding is one
incompatible change to a public symbol, and carries that symbol spelled as the
tool spells it, so a changelog lists it in the same words. A finding has no line:
it is about a symbol, and an edit elsewhere in the file must not change it. Each
Format's `keep` drops the changes api_rules.py allows: a changed value of a protocol
version constant, and a break a major release lists. ratchet.py reads
API_FORMATS by the name a gate passes as --format.

The module needs only the Python standard library.
"""

from __future__ import annotations

import json
import re
from collections import Counter

from api_diff import PYTHON_SEARCH_PATH, go_module
from api_rules import VERSION_CONSTANTS, allowed, version_value_changed
from formats import Format, Reported

# `apidiff -m -incompatible` prints one `- OBJECT: CHANGE` line per change, and a
# removed or added package as `- package IMPORT/PATH: CHANGE`.
APIDIFF_PACKAGE = re.compile(r"^- package (?P<path>\S+): (?P<change>.+)$")
APIDIFF_OBJECT = re.compile(r"^- (?P<object>\./\S+): (?P<change>.+)$")


def package_directory(import_path: str) -> str:
    """Return the directory of the package `import_path` within the tree's module.

    apidiff prints a removed package by its import path. api_diff.py compares the
    release by the tree's module path, rewriting it after a major-version move, so
    that is the tree's path; a package of another module is refused.
    """
    prefix = go_module() + "/"
    if not import_path.startswith(prefix):
        raise ValueError(f"package {import_path} is not in the module {go_module()}")
    return import_path.removeprefix(prefix)


def parse_apidiff(out: str) -> list[Reported]:
    """Read `apidiff -m -incompatible OLD NEW`, run from the repository root.

    An object is printed relative to the module root (`./sdk/go/core.Verify`,
    `./sdk/go/core.(*Client).Do`); that spelling is its symbol, and the finding's
    path is its package directory. A package is printed by its import path, which
    is its symbol, and its directory within the module is the finding's path. Any
    other line, such as the section headings apidiff prints without -incompatible,
    is refused.
    """
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        if m := APIDIFF_PACKAGE.match(line):
            symbol, path = m["path"], package_directory(m["path"])
        elif m := APIDIFF_OBJECT.match(line):
            symbol = m["object"]
            directory, _, name = symbol.rpartition("/")
            path = f"{directory}/{name.split('.', 1)[0]}".removeprefix("./")
        else:
            raise ValueError(f"not a line of apidiff -incompatible output: {line!r}")
        message = f"{symbol}: {m['change']}"
        findings.append(Reported(path, "incompatible", message, symbol=symbol))
    return findings


# `griffe check -f oneline` prints `FILE:LINE: OBJECT: EXPLANATION` per breakage, where
# OBJECT is the object's path within its module, with the parameter in parentheses
# for a parameter's breakage.
GRIFFE_LINE = re.compile(r"^(?P<path>[^:\s][^:]*):\d+: (?P<object>[^:\s]+): (?P<why>.+)$")


def parse_griffe(out: str) -> list[Reported]:
    """Read `griffe check -s sdk/python -f oneline`, run from the repository root.

    The symbol is the object's dotted path from its package, `fora_sdk.module.name`,
    built from the file griffe names (relative to the search path sdk/python) and the
    object; a parameter's breakage keeps the parameter in its message. Griffe's line
    number is dropped: for a removed object it is 0, and an old line otherwise.
    """
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        m = GRIFFE_LINE.match(line)
        if m is None or not m["path"].startswith(f"{PYTHON_SEARCH_PATH}/"):
            raise ValueError(f"not a line of griffe check -f oneline output: {line!r}")
        module = m["path"].removeprefix(f"{PYTHON_SEARCH_PATH}/").removesuffix(".py")
        module = module.removesuffix("/__init__").replace("/", ".")
        symbol = f"{module}.{m['object'].split('(', 1)[0]}"
        message = f"{module}.{m['object']}: {m['why']}"
        findings.append(Reported(m["path"], "incompatible", message, symbol=symbol))
    return findings


# An API Extractor report holds the API as TypeScript declarations in one ```ts block:
# a top-level declaration per statement, and a member per line inside a class,
# interface, enum, namespace or object type, indented under it.
REPORT_BLOCK = re.compile(r"^```ts\n(?P<body>.*?)^```", re.MULTILINE | re.DOTALL)
TOP_LEVEL = re.compile(
    r"^(?:export\s+)?(?:declare\s+)?(?:default\s+)?(?:abstract\s+)?(?:async\s+)?"
    r"(?:function\*?|class|interface|type|const|let|var|enum|namespace|module)\s+(?P<name>[\w$]+)"
)
MODIFIER = re.compile(
    r"^(?:readonly|static|public|protected|private|abstract|override|accessor|get|set|"
    r"async|declare)\s+"
)
MEMBER = re.compile(r"^(?P<name>constructor|new\b|\[[^\]]*\]|\"[^\"]*\"|'[^']*'|[\w$]+|\()")
REPORT_CHANGED = (
    "the committed API report is missing or differs from the code: run "
    "`python3 scripts/gates/api_diff.py ts --update` and commit sdk/ts/api"
)


def declared_name(line: str) -> str:
    """Return the name a report line declares: a top-level name, or a member's name."""
    if m := TOP_LEVEL.match(line):
        return m["name"]
    while m := MODIFIER.match(line):
        line = line[m.end() :]
    m = MEMBER.match(line)
    if m is None:
        return line
    return "()" if m["name"] == "(" else m["name"]


def declarations(report: str, entry: str) -> Counter[tuple[str, str]]:
    """Return each declaration line of `report` with the symbol it declares.

    The symbol is the entry point's subpath and the names of the declarations that
    enclose the line, joined by dots: `./core.Verifier.sort`. A line that closes a
    declaration is part of its enclosing declaration only when it carries more
    than the brace (`} & Other;`). Comments and imports are not declarations.
    """
    m = REPORT_BLOCK.search(report)
    if m is None:
        raise ValueError(f"the report of {entry} has no ```ts block")
    found: Counter[tuple[str, str]] = Counter()
    enclosing: list[str] = []
    for raw in m["body"].splitlines():
        line = raw.strip()
        if not line or line.startswith(("//", "import ")):
            continue
        if line.startswith("}"):
            if line not in ("}", "};"):
                found[(".".join([entry, *enclosing]), line)] += 1
            if enclosing:
                enclosing.pop()
            continue
        name = declared_name(line)
        found[(".".join([entry, *enclosing, name]), line)] += 1
        if line.endswith("{"):
            enclosing.append(name)
    return found


# A report declares a constant with a string value as `export const NAME = "VALUE";`.
STRING_CONSTANT = re.compile(r'^export (?:declare )?const [\w$]+ = (?P<value>"[^"\n]*");$')


def changed_values(
    gone: Counter[tuple[str, str]], head: Counter[tuple[str, str]]
) -> dict[str, tuple[str, str]]:
    """Return each version constant whose string value changed, with its old and new value.

    A version constant (VERSION_CONSTANTS) that went as one string constant and is
    declared again, once, as one string constant changed only its value.
    """
    changed = {}
    for symbol in VERSION_CONSTANTS["ts"]:
        old = [d for s, d in gone.elements() if s == symbol]
        new = [d for s, d in head.elements() if s == symbol]
        if len(old) == len(new) == 1:
            before, after = STRING_CONSTANT.match(old[0]), STRING_CONSTANT.match(new[0])
            if before and after:
                changed[symbol] = (before["value"], after["value"])
    return changed


def parse_api_extractor(out: str) -> list[Reported]:
    """Read api_diff.py's TypeScript output: one JSON object per entry point.

    Each object names the entry point, its report under sdk/ts/api, API Extractor's
    warnings and errors about the tree, and the entry point's report at the last
    release (`base`) and in the tree (`head`), either null when the entry point did
    not exist. Every message is a finding; a stale or missing committed report is
    one finding with a fixed message, since API Extractor's names a temporary file.
    Every declaration line of `base` that is not in `head` is a finding, so a
    removed, renamed or changed declaration fails, and an added one does not.
    """
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not isinstance(row, dict) or not {"entry", "report", "messages"} <= row.keys():
            raise ValueError(f"not a line of api_diff.py ts output: {line[:200]!r}")
        report = row["report"]
        for msg in row["messages"]:
            text = REPORT_CHANGED if msg["id"] == "console-api-report-not-copied" else msg["text"]
            findings.append(Reported(report, msg["id"], text))
        base, head = row.get("base"), row.get("head")
        if base is None:
            continue
        now = declarations(head or "```ts\n```", row["entry"])
        gone = declarations(base, row["entry"]) - now
        values = changed_values(gone, now)
        for symbol, decl in sorted(gone.elements()):
            message = f"{symbol}: `{decl}` is no longer declared"
            if symbol in values:
                message = f"{symbol}: value changed from {values[symbol][0]} to {values[symbol][1]}"
            findings.append(Reported(report, "incompatible", message, symbol=symbol))
    return findings


API_FORMATS: dict[str, Format] = {
    # apidiff exits 0 whatever it reports, and 1 when it cannot load a package.
    "apidiff": Format(
        parse_apidiff,
        ran=frozenset({0}),
        keep=lambda r: (
            not (version_value_changed("go", r.symbol, r.message) or allowed("go", r.symbol))
        ),
        line_refs=False,
    ),
    # griffe check exits 1 when it reports a breakage.
    "griffe": Format(
        parse_griffe,
        ran=frozenset({0}),
        found=frozenset({1}),
        keep=lambda r: not allowed("python", r.symbol),
        line_refs=False,
    ),
    # api_diff.py exits 0 whatever API Extractor reports; a message about the tree
    # names no symbol, and is never allowed.
    "api-extractor": Format(
        parse_api_extractor,
        ran=frozenset({0}),
        keep=lambda r: (
            r.symbol is None
            or not (version_value_changed("ts", r.symbol, r.message) or allowed("ts", r.symbol))
        ),
        line_refs=False,
    ),
}
