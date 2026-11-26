#!/usr/bin/env python3
"""List every conformance corpus that breaks the ADR-002 contract, for the corpus-contract gate.

Each rule of docs/architecture/adr-002-conformance-corpora.md that a program can
check has one rule name here:

- corpus-unregistered: a tracked corpus file that no registry entry names, and a
  top-level list of rows in a registered file that is neither an entry nor a
  declared fixture.
- corpus-fixture: each declared fixture, one finding apiece, so the baseline holds
  the fixtures and a new one fails the gate.
- corpus-entry: a registry entry whose file or case list is missing or empty, whose
  rows are not each named by a distinct row key without a '#', and a declared
  fixture that names no list of rows in a registered file.
- corpus-replay: a corpus file an SDK's sources never name in a string literal.
- corpus-column: a column of a corpus an SDK's sources never read.
- corpus-outcome: rows without an outcome of the one format, `accepted` or
  `refused:<token>` (the size is the number of such rows in the case list), and,
  in a case list whose rows all record one, a retired outcome column, refusal detail
  that is not a list, and an accepted row that lists refusal detail.
- corpus-reason: a refusal token the vocabulary does not define, a vocabulary entry
  that is not a token with a meaning, and a token no corpus row is refused for.
- corpus-pointer: a row pointer, in a row's `supersedes` list or in an
  expected-failure entry, that is not `<corpus>#<row>` naming a registered corpus
  (and, in an expected-failure entry, one of its rows).
- corpus-expected-failure: an expected-failure entry that is not
  {row, outcome, why}, lists a row twice, or records the row's own outcome.

The script prints one `path<TAB>line<TAB>rule<TAB>size<TAB>message` row per finding, in
ratchet.py's `lines` format, with the line always `-`: each finding is about a file or a
registry entry, not a line. The gate holds them against its shrink-only baseline.

Usage: corpus_contract.py   (prints the rows; exits 0)
"""

from __future__ import annotations

import sys
from collections import Counter
from typing import Any

import corpora
import corpus_replay
import corpus_vocabulary
from corpora import Report
from scope import REPO_ROOT


def case_rows(corpus: corpora.Corpus, report: Report) -> list[dict[str, Any]]:
    """Return the rows of `corpus`, or report why they cannot be read and return none."""
    if not (REPO_ROOT / corpus.file).is_file():
        report.add(corpora.REGISTRY, "corpus-entry", f"{corpus.id}: no file {corpus.file}")
        return []
    found = corpora.rows(corpus)
    if not (isinstance(found, list) and found and all(isinstance(r, dict) for r in found)):
        where = f"list {corpus.list!r}" if corpus.list else "the file"
        report.add(corpora.REGISTRY, "corpus-entry", f"{corpus.id}: {where} holds no rows")
        return []
    return found


def check_row_keys(corpus: corpora.Corpus, found: list[dict[str, Any]], report: Report) -> None:
    """Report rows the row key does not name, and names that are not unique."""
    names = [r.get(corpus.row_key) for r in found]
    unnamed = sum(1 for n in names if not isinstance(n, str) or not n or "#" in n)
    if unnamed:
        report.add(
            corpora.REGISTRY,
            "corpus-entry",
            f"{corpus.id}: rows {corpus.row_key} does not name (a non-empty string without '#')",
            unnamed,
        )
    for name, count in sorted(Counter(n for n in names if isinstance(n, str)).items()):
        if count > 1:
            report.add(
                corpora.REGISTRY,
                "corpus-entry",
                f"{corpus.id}: {corpus.row_key} {name!r} names more than one row",
            )


def check_outcomes(
    corpus: corpora.Corpus, found: list[dict[str, Any]], reasons: set[str], report: Report
) -> set[str]:
    """Report rows without a well-formed outcome and unknown tokens; return the tokens used."""
    malformed, used = 0, set()
    for r in found:
        token = corpora.outcome_token(r.get("outcome"))
        if token is None:
            malformed += 1
        elif token:
            used.add(token)
            if token not in reasons:
                pointer = f"{corpus.id}#{r.get(corpus.row_key)}"
                report.add(
                    corpus.file, "corpus-reason", f"{pointer}: {token} is not in the vocabulary"
                )
    if malformed:
        report.add(
            corpus.file,
            "corpus-outcome",
            f"{corpus.id}: rows without an outcome, accepted or refused:<token>",
            malformed,
        )
        return used
    columns = {c for r in found for c in r}
    for column in sorted(columns & corpora.RETIRED_OUTCOME_COLUMNS):
        report.add(
            corpus.file,
            "corpus-outcome",
            f"{corpus.id}: column {column} states the outcome a second time",
        )
    check_accepted_detail(corpus, found, report)
    return used


def check_accepted_detail(
    corpus: corpora.Corpus, found: list[dict[str, Any]], report: Report
) -> None:
    """Report refusal detail that is not a list, and an accepted row that lists any, so
    the decision is not in a detail column."""
    for r in found:
        pointer = f"{corpus.id}#{r.get(corpus.row_key)}"
        for column in sorted(corpora.REFUSAL_DETAIL_COLUMNS & set(r)):
            if not isinstance(r[column], list):
                report.add(corpus.file, "corpus-outcome", f"{pointer}: {column} is not a list")
            elif r[column] and r.get("outcome") == "accepted":
                report.add(
                    corpus.file, "corpus-outcome", f"{pointer}: an accepted row lists {column}"
                )


def check_supersedes(
    corpus: corpora.Corpus, found: list[dict[str, Any]], registry: corpora.Registry, report: Report
) -> None:
    """Report `supersedes` values that are not lists of pointers to registered corpora.

    A superseded row is usually gone from its corpus, so only the corpus must exist.
    """
    for r in found:
        if "supersedes" not in r:
            continue
        value = r["supersedes"]
        pointers = value if isinstance(value, list) and value else [value]
        for p in pointers:
            parts = corpora.split_pointer(p)
            if parts is None or parts[0] not in registry.corpora:
                report.add(
                    corpus.file,
                    "corpus-pointer",
                    f"{corpus.id}#{r.get(corpus.row_key)}: supersedes {p!r}, "
                    "which is not <corpus>#<row> naming a registered corpus",
                )


def check_registered(registry: corpora.Registry, report: Report) -> None:
    """Report tracked corpus files no entry names, and entry ids a pointer cannot carry."""
    named = set(registry.files())
    for path in corpora.tracked_corpus_files():
        if path not in named:
            report.add(
                path, "corpus-unregistered", f"no entry of {corpora.REGISTRY} names this file"
            )
    check_lists(registry, report)
    for cid in registry.corpora:
        if not cid or "#" in cid:
            report.add(
                corpora.REGISTRY, "corpus-entry", f"{cid!r}: a corpus id is non-empty, without '#'"
            )


def check_lists(registry: corpora.Registry, report: Report) -> None:
    """Report lists of rows in a registered file that are neither entries nor fixtures,
    and declared fixtures that name no such list."""
    entries = {f"{c.file}#{c.list}" for c in registry.corpora.values()}
    found: set[str] = set()
    for path in registry.files():
        if not (REPO_ROOT / path).is_file():
            continue
        for name in corpus_replay.declared_columns(corpora.load_json(path)):
            found.add(f"{path}#{name}")
            if f"{path}#{name}" in registry.fixtures:
                # One finding per fixture, held by the baseline, so a fixture is never
                # added without the --base-ref check refusing it.
                report.add(path, "corpus-fixture", f"list {name!r} is a declared fixture")
            elif f"{path}#{name}" not in entries:
                report.add(
                    path,
                    "corpus-unregistered",
                    f"list {name!r} is neither a registry entry nor a declared fixture",
                )
    for fixture in sorted(registry.fixtures - found):
        report.add(
            corpora.REGISTRY,
            "corpus-entry",
            f"fixture {fixture!r} names no list of rows in a registered file",
        )


def check_replays(registry: corpora.Registry, report: Report) -> None:
    """Report corpus files an SDK never names, and columns an SDK never reads."""
    sources = corpus_replay.replay_sources()
    for path in registry.files():
        if not (REPO_ROOT / path).is_file():
            continue
        naming = corpus_replay.languages_naming(path, sources)
        for lang in sources:
            if lang not in naming:
                report.add(path, "corpus-replay", f"no {lang} replay names this file")
        lists = corpus_replay.declared_columns(corpora.load_json(path))
        for name, columns in sorted(lists.items()):
            for lang, text in sources.items():
                unread = sorted(c for c in columns if not corpus_replay.references(text, c))
                if unread:
                    where = f"list {name!r}" if name else "the rows"
                    report.add(
                        path, "corpus-column", f"{where}: the {lang} replay never reads {unread}"
                    )


def main() -> int:
    """Print one row per finding."""
    registry = corpora.load()
    report = Report()
    check_registered(registry, report)
    reasons = corpus_vocabulary.check_vocabulary(registry, report)
    used: set[str] = set()
    outcomes: dict[str, str] = {}
    for corpus in registry.corpora.values():
        found = case_rows(corpus, report)
        check_row_keys(corpus, found, report)
        used |= check_outcomes(corpus, found, reasons, report)
        check_supersedes(corpus, found, registry, report)
        for r in found:
            outcome = r.get("outcome")
            well_formed = corpora.outcome_token(outcome) is not None
            outcomes[f"{corpus.id}#{r.get(corpus.row_key)}"] = str(outcome) if well_formed else ""
    corpus_vocabulary.check_unused(registry, reasons, used, report)
    corpus_vocabulary.check_expected_failures(registry, outcomes, reasons, report)
    check_replays(registry, report)
    for row in report.rows:
        print(row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
