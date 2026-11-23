"""The corpus-contract rules for the reason vocabulary and the expected-failure files.

The vocabulary (sdk/parity/reasons.json) holds every refusal token a corpus row may
record, each with its meaning: `{"note": ..., "reasons": {token: meaning}}`. A token
enters it in the change that first records it, and leaves when no row records it.

Each port's expected-failure file (named in the registry) lists the rows the port
does not meet yet: `{"note": ..., "entries": [{"row", "outcome", "why"}]}`. `row` is
a row pointer, `outcome` the outcome the port produces today, `why` the reason. The
replay asserts that outcome, so an entry fails when the row starts passing and when
the port fails it differently; this module checks the entries themselves.
"""

from __future__ import annotations

from typing import Any

import corpora
from corpora import Report

ENTRY_KEYS = frozenset({"row", "outcome", "why"})


def check_vocabulary(registry: corpora.Registry, report: Report) -> set[str]:
    """Report malformed vocabulary entries; return the tokens it defines."""
    doc = corpora.load_json(registry.reasons)
    reasons = doc.get("reasons") if isinstance(doc, dict) else None
    if not isinstance(reasons, dict):
        report.add(registry.reasons, "corpus-reason", "the file holds no reasons object")
        return set()
    for token, meaning in sorted(reasons.items()):
        if not corpora.TOKEN.match(token):
            report.add(
                registry.reasons, "corpus-reason", f"{token!r}: not a token, [a-z][a-z0-9_]*"
            )
        if not isinstance(meaning, str) or not meaning.strip():
            report.add(registry.reasons, "corpus-reason", f"{token}: has no meaning")
    return set(reasons)


def check_unused(
    registry: corpora.Registry, reasons: set[str], used: set[str], report: Report
) -> None:
    """Report vocabulary tokens no corpus row is refused for."""
    for token in sorted(reasons - used):
        report.add(registry.reasons, "corpus-reason", f"{token}: no corpus row is refused for it")


def check_expected_failures(
    registry: corpora.Registry, outcomes: dict[str, str], reasons: set[str], report: Report
) -> None:
    """Report malformed, duplicated and dangling entries in every port's expected-failure file."""
    for path in sorted(registry.expected_failures.values()):
        doc = corpora.load_json(path)
        entries = doc.get("entries") if isinstance(doc, dict) else None
        if not isinstance(entries, list):
            report.add(path, "corpus-expected-failure", "the file holds no entries list")
            continue
        seen: set[str] = set()
        for entry in entries:
            check_entry(path, entry, outcomes, reasons, report)
            pointer = str(entry.get("row")) if isinstance(entry, dict) else ""
            if pointer in seen:
                report.add(path, "corpus-expected-failure", f"{pointer}: listed more than once")
            seen.add(pointer)


def check_entry(
    path: str, entry: Any, outcomes: dict[str, str], reasons: set[str], report: Report
) -> None:
    """Report what is wrong with one expected-failure entry."""
    if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
        report.add(
            path, "corpus-expected-failure", f"{entry!r}: not an object of row, outcome, why"
        )
        return
    pointer, outcome = entry["row"], entry["outcome"]
    if corpora.split_pointer(pointer) is None or pointer not in outcomes:
        report.add(path, "corpus-pointer", f"{pointer!r}: names no registered corpus row")
        return
    token = corpora.outcome_token(outcome)
    if token is None:
        report.add(path, "corpus-expected-failure", f"{pointer}: {outcome!r} is not an outcome")
    elif token and token not in reasons:
        report.add(path, "corpus-reason", f"{pointer}: {token} is not in the vocabulary")
    elif not outcomes[pointer]:
        report.add(path, "corpus-expected-failure", f"{pointer}: the row records no outcome")
    elif outcome == outcomes[pointer]:
        report.add(path, "corpus-expected-failure", f"{pointer}: records the row's own outcome")
    if not isinstance(entry["why"], str) or not entry["why"].strip():
        report.add(path, "corpus-expected-failure", f"{pointer}: gives no reason why")
