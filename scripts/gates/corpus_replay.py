"""Whether each SDK replays each corpus: names its file, and reads every column it declares.

ADR-002 decision 1: every corpus is replayed by all three SDKs, and each replay reads
every column the corpus declares. A corpus no replay names asserts nothing, and the
divergence it was written to catch ships anyway; the SSRF redirect-depth and
multi-address gaps slipped through that way. Naming the file is necessary and not
sufficient: the hex half of wire-names-vectors.json was named by a replay that read
none of its columns, through two review rounds. So each language must also name every
column of every top-level list of rows in the file, fixture tables included.

The check is deliberately loose about how a replay reads a column (a quoted key, an
index, an attribute), because the three languages spell the same read differently.
There is no exemption mechanism.

The corpus-contract gate and scripts/gen-parity-matrix.py both read this module.
"""

from __future__ import annotations

import re
from typing import Any

from scope import hand_written, read

# The source tree and the gated language of each SDK's replays.
LANGUAGES = {
    "go": ("sdk/go/", "go"),
    "python": ("sdk/python/", "python"),
    "ts": ("sdk/ts/", "typescript"),
}


def replay_sources() -> dict[str, str]:
    """Return, per SDK, the text of its hand-written source files, joined.

    A file under a testdata directory is a fixture, not a replay, and is left out.
    """
    out = {}
    for lang, (tree, language) in LANGUAGES.items():
        paths = [
            p for p in hand_written([language]) if p.startswith(tree) and "/testdata/" not in p
        ]
        out[lang] = "\n".join(read(p) for p in paths)
    return out


def languages_naming(file: str, sources: dict[str, str]) -> list[str]:
    """Return the SDKs whose sources name the corpus file `file` in a string literal.

    The base name must be a whole path component that ends a string: preceded by a
    quote or a `/`, and followed by a quote. So request-acceptance-vectors.json does not
    count as acceptance-vectors.json, and a comment that mentions the file in passing
    does not count as a replay. A quoted mention in a comment still does; a replay that
    names its corpus by registry id instead closes that gap.
    """
    base = file.rsplit("/", 1)[-1]
    pattern = re.compile(r"""[\"'`/]""" + re.escape(base) + r"""[\"'`]""")
    return [lang for lang, text in sources.items() if pattern.search(text)]


def declared_columns(doc: Any) -> dict[str, set[str]]:
    """Return each top-level list of rows in a corpus document, and the columns its rows use.

    Top level only: anything deeper is the payload of a row (a message body, a schema
    under test), whose keys belong to the data, not to the corpus.
    """
    items = doc.items() if isinstance(doc, dict) else [("", doc)]
    lists: dict[str, set[str]] = {}
    for name, value in items:
        if isinstance(value, list) and value and all(isinstance(e, dict) for e in value):
            lists[name] = {key for entry in value for key in entry}
    return lists


def references(text: str, column: str) -> bool:
    """Return whether `text` names `column` as a key, an index or an attribute."""
    return re.search(r"""[\"'`\[.]""" + re.escape(column) + r"\b", text) is not None
