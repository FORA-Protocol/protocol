"""The corpus registry, sdk/parity/corpora.json, and the formats ADR-002 fixes.

The registry lists every conformance corpus: one entry per case list, keyed by the
corpus id, giving the file, the top-level key that holds the rows, and the column
that names each row. It also names the reason vocabulary and each port's
expected-failure file. Every gate that enumerates corpora reads it through this
module: the corpus-contract gate (scripts/gates/corpus_contract.py) and the parity
matrix (scripts/gen-parity-matrix.py).

The formats:

- An outcome is `accepted`, or `refused:<token>` with a token from the vocabulary.
- A row pointer is `<corpus id>#<row>`, where <row> is the value of the corpus's row
  key column in that row.
- A fixture is `<file>#<list>`: a top-level list of rows in a registered file that holds
  data for the cases rather than cases. Every list of rows in a registered file is either
  a registry entry or a declared fixture.

The module needs only the Python standard library.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from scope import REPO_ROOT, tracked

REGISTRY = "sdk/parity/corpora.json"

# Where a Go emitter's corpus lives. The registry must name every tracked file this
# pattern matches; it is used for nothing else.
CORPUS_FILES = ":(glob)sdk/go/**/testdata/*-vectors.json"

TOKEN = re.compile(r"[a-z][a-z0-9_]*\Z")

# The accept/refuse decision lives only in the outcome column (ADR-002 rule 3).
#
# RETIRED_OUTCOME_COLUMNS are the columns the corpora used before it to restate that
# decision as a flag or a single token, taken from the corpus files as they stood then.
# A case list whose rows all record an outcome carries none of them.
#
# REFUSAL_DETAIL_COLUMNS hold lists of what a refusal found: rule ids, schema keywords,
# field paths. They are results and stay, but each is a list, and an accepted row's are
# empty, so the decision cannot hide in one either.
RETIRED_OUTCOME_COLUMNS = frozenset(
    {
        "accepted",
        "allowed",
        "blocked",
        "error",
        "expected_error",
        "expected_reason",
        "expected_valid",
        "expected_verdict",
        "expected_verified",
        "failure",
        "identity_error",
        "ok",
        "reason",
        "reason_of",
        "refused",
        "strict_malformed",
        "structural",
        "valid",
        "verdict",
        "violation",
    }
)
REFUSAL_DETAIL_COLUMNS = frozenset(
    {
        "cross_field_rules",
        "expected_keywords",
        "expected_paths",
        "rules",
        "term_rules",
    }
)
OUTCOME = re.compile(r"(?:accepted|refused:(?P<token>[a-z][a-z0-9_]*))\Z")


@dataclass(frozen=True)
class Corpus:
    """One registry entry: a case list in a corpus file."""

    id: str
    file: str
    list: str
    row_key: str


@dataclass(frozen=True)
class Registry:
    """The parsed registry: its corpora, the vocabulary file and the expected-failure files."""

    corpora: dict[str, Corpus]
    fixtures: frozenset[str]
    reasons: str
    expected_failures: dict[str, str]

    def files(self) -> list[str]:
        """Return each corpus file the registry names, once, sorted."""
        return sorted({c.file for c in self.corpora.values()})


@dataclass
class Report:
    """A gate's findings so far, as rows of ratchet.py's `lines` format."""

    rows: list[str] = field(default_factory=list)

    def add(self, path: str, rule: str, message: str, size: int | None = None) -> None:
        """Add the finding `rule` at `path`; `size` is a count the baseline holds, if any."""
        self.rows.append(f"{path}\t-\t{rule}\t{'-' if size is None else size}\t{message}")


def load_json(path: str) -> Any:
    """Return the parsed JSON file at `path`, relative to the repository root."""
    return json.loads((REPO_ROOT / path).read_text(encoding="utf-8"))


def load() -> Registry:
    """Read the registry."""
    doc = load_json(REGISTRY)
    corpora = {
        cid: Corpus(cid, e["file"], e["list"], e["row_key"]) for cid, e in doc["corpora"].items()
    }
    fixtures = frozenset(doc["fixtures"])
    return Registry(corpora, fixtures, doc["reasons"], dict(doc["expected_failures"]))


def rows(corpus: Corpus) -> Any:
    """Return the case list `corpus` names, as the file holds it (not checked here)."""
    doc = load_json(corpus.file)
    if corpus.list == "":
        return doc
    return doc.get(corpus.list) if isinstance(doc, dict) else None


def outcome_token(outcome: object) -> str | None:
    """Return the token of a well-formed refused outcome, "" for `accepted`, None if malformed."""
    if not isinstance(outcome, str):
        return None
    m = OUTCOME.match(outcome)
    if m is None:
        return None
    return m.group("token") or ""


def split_pointer(pointer: object) -> tuple[str, str] | None:
    """Return (corpus id, row) for a well-formed pointer, or None."""
    if not isinstance(pointer, str):
        return None
    corpus, sep, row = pointer.partition("#")
    if not (corpus and sep and row) or "#" in row:
        return None
    return corpus, row


def tracked_corpus_files() -> list[str]:
    """Return every tracked file a Go emitter's corpus would live in, sorted."""
    return tracked(CORPUS_FILES)
