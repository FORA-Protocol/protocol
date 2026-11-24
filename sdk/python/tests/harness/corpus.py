"""The corpus locations, the corpus reader and the outcome a replay compares with.

The parity suites assert sdk/python's `fora_sdk` L1 helpers against the SHARED
Go-oracle vectors (never against copied app fixtures — Core Invariant). This
module centralizes the on-disk locations of those shared corpora so every suite
resolves them the same way, mirroring the sdk/ts sibling's relative-path imports
(`../../go/helpers/testdata/*.json`, `../../../conformance/corpus/crossfield.json`).

MINIMAL by intent: this file exposes the paths, a JSON loader, and the corpus
outcome helpers a replay compares with (``outcome_of`` and ``expected_outcome``). It
creates no package state and imports nothing from `fora_sdk`, so it never masks the
module-missing red the suites are meant to surface.
"""

from __future__ import annotations

import functools
import json
import pathlib
from typing import Any

# sdk/python/tests/harness/corpus.py -> repo root is parents[4]
# (harness -> tests -> python -> sdk -> <repo root>).
REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]

GO_TESTDATA = REPO_ROOT / "sdk" / "go" / "helpers" / "testdata"
# The fetching resolvers (WBA / well-known / endpoint) and their SSRF + revocation
# corpora live in the sdk/go/resolvers L2 package (the I/O layer, extracted from
# helpers). GO_TESTDATA stays the L1 crypto-vector home; this is its L2 sibling.
GO_RESOLVERS_TESTDATA = REPO_ROOT / "sdk" / "go" / "resolvers" / "testdata"
# The transport tier's corpus home. A corpus lives with the tier that can produce it,
# and the Connect error envelope can only be captured from a real connect-go handler —
# which neither helpers nor resolvers may import, since both are Connect-free by
# contract. Third home, same rules: emitted by Go, replayed by all three.
GO_CONNECT_TESTDATA = REPO_ROOT / "sdk" / "go" / "connect" / "testdata"
CONFORMANCE_CORPUS = REPO_ROOT / "conformance" / "corpus"


def load_json(path: pathlib.Path) -> Any:
    """Read+parse a shared corpus/vector file. Fails the test if it is absent.

    A missing vector file is a legitimate TDD-red signal for the two vectors the
    Go emitter has not yet produced (sign-request-vectors.json,
    acceptance-vectors.json); pytest surfaces the FileNotFoundError as a failure.
    """
    return json.loads(path.read_text())


# The corpus registry, which names this port's expected-failure file (ADR-002).
_REGISTRY = REPO_ROOT / "sdk" / "parity" / "corpora.json"


def outcome_of(accepted: bool, reason: str | None) -> str:
    """Return the corpus outcome (ADR-002 rule 3) of a call that accepted, or refused
    for ``reason``, the token the SDK reported. A refusal without a token renders as
    ``refused:``, which matches no row."""
    return "accepted" if accepted else f"refused:{reason or ''}"


@functools.cache
def _expected_failures() -> dict[str, str]:
    """This port's expected-failure entries, as row pointer -> the outcome it gives today."""
    registry = load_json(_REGISTRY)
    entries = load_json(REPO_ROOT / registry["expected_failures"]["python"])["entries"]
    return {str(e["row"]): str(e["outcome"]) for e in entries}


def expected_outcome(pointer: str, outcome: str) -> str:
    """Return the outcome a replay asserts for the row at ``pointer`` (``<corpus>#<row>``):
    the outcome this port's expected-failure file records for it, or else the row's own
    ``outcome``. So a listed row fails when it starts passing and when it fails
    differently (ADR-002 rule 6)."""
    return _expected_failures().get(pointer, outcome)
