"""The readers of the SDK API gates' tools, one Format per tool, as formats.py has for the rest.

An API gate's command is scripts/gates/api_diff.py, which runs the tool against
the last release and prints the tool's own output. Every finding is one
incompatible change to a public symbol, and carries that symbol spelled as the
tool spells it, so a changelog lists it in the same words. A finding has no line:
it is about a symbol, and an edit elsewhere in the file must not change it. Each
Format's `keep` drops the changes api_rules.py allows. ratchet.py reads
API_FORMATS by the name a gate passes as --format.

The module needs only the Python standard library.
"""

from __future__ import annotations

import re
from functools import cache

from api_rules import allowed
from formats import Format, Reported
from scope import REPO_ROOT

# `apidiff -m -incompatible` prints one `- OBJECT: CHANGE` line per change, and a
# removed or added package as `- package IMPORT/PATH: CHANGE`.
APIDIFF_PACKAGE = re.compile(r"^- package (?P<path>\S+): (?P<change>.+)$")
APIDIFF_OBJECT = re.compile(r"^- (?P<object>\./\S+): (?P<change>.+)$")


@cache
def go_module() -> str:
    """Return the module path go.mod declares."""
    for line in (REPO_ROOT / "go.mod").read_text(encoding="utf-8").splitlines():
        if line.startswith("module "):
            return line.split()[1]
    raise ValueError("go.mod declares no module")


def parse_apidiff(out: str) -> list[Reported]:
    """Read `apidiff -m -incompatible OLD NEW`, run from the repository root.

    An object is printed relative to the module root (`./sdk/go/core.Verify`,
    `./sdk/go/core.(*Client).Do`); that spelling is its symbol, and the finding's
    path is its package directory. A package is printed by its import path, which
    is its symbol. Any other line, such as the section headings apidiff prints
    without -incompatible, is refused.
    """
    findings = []
    for line in out.splitlines():
        if not line.strip():
            continue
        if m := APIDIFF_PACKAGE.match(line):
            symbol, path = m["path"], m["path"].removeprefix(go_module() + "/")
        elif m := APIDIFF_OBJECT.match(line):
            symbol = m["object"]
            directory, _, name = symbol.rpartition("/")
            path = f"{directory}/{name.split('.', 1)[0]}".removeprefix("./")
        else:
            raise ValueError(f"not a line of apidiff -incompatible output: {line!r}")
        message = f"{symbol}: {m['change']}"
        findings.append(Reported(path, "incompatible", message, symbol=symbol))
    return findings


API_FORMATS: dict[str, Format] = {
    # apidiff exits 0 whatever it reports, and 1 when it cannot load a package.
    "apidiff": Format(
        parse_apidiff,
        ran=frozenset({0}),
        keep=lambda r: not allowed("go", r.symbol),
        line_refs=False,
    ),
}
