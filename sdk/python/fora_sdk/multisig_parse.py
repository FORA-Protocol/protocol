"""The verbatim inner value of each Signature-Input member — the Python port of Go
helpers.rawInnerByLabel / splitTopLevelMembers (verify.go).

RFC 9421 §2.5 terminates a signature base with the signer's exact inner list and
parameters, so a verifier rebuilds the base from the bytes as they arrived rather than
from a re-rendering. The structured-field parse itself is :mod:`fora_sdk.sfv`; this
module only finds, per label, the wire text after ``label=``.

Correctness on ADVERSARIAL headers (a comma inside a quoted keyid, backslash escapes,
top-level splitting) is pinned by tests/test_multisig_parse_edge.py.
"""

from __future__ import annotations


def split_top_level_members(s: str) -> list[str]:
    """Split one SFV dictionary header value on TOP-LEVEL commas.

    Honors quoted strings and their backslash escapes (Go splitTopLevelMembers) —
    a comma inside a quoted keyid must NOT tear the member in two.
    """
    parts: list[str] = []
    start = 0
    in_quote = False
    escaped = False
    for i, c in enumerate(s):
        if escaped:
            escaped = False
        elif c == "\\" and in_quote:
            escaped = True
        elif c == '"':
            in_quote = not in_quote
        elif c == "," and not in_quote:
            parts.append(s[start:i])
            start = i + 1
    parts.append(s[start:])
    return parts


def raw_inner_by_label(values: list[str]) -> dict[str, str]:
    """The VERBATIM value after ``label=`` for each label across the given
    Signature-Input header values (Go rawInnerByLabel). Later occurrences overwrite
    earlier ones, matching SFV dictionary last-wins semantics."""
    out: dict[str, str] = {}
    for v in values:
        for member in split_top_level_members(v):
            eq = member.find("=")
            if eq <= 0:
                continue
            out[member[:eq].strip()] = member[eq + 1 :].strip()
    return out
