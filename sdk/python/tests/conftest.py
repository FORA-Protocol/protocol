"""Shared pytest fixtures/paths for the sdk/python parity suites.

The parity suites assert sdk/python's `fora_sdk` L1 helpers against the SHARED
Go-oracle vectors (never against copied app fixtures — Core Invariant). This
module centralizes the on-disk locations of those shared corpora so every suite
resolves them the same way, mirroring the sdk/ts sibling's relative-path imports
(`../../go/helpers/testdata/*.json`, `../../../conformance/corpus/crossfield.json`).

MINIMAL by intent: this file exposes the paths, a JSON loader, the corpus outcome
helpers a replay compares with (``outcome_of`` and ``expected_outcome``) and the one
fixture that clears the SSRF environment (``ssrf_env``). It creates no package state and
imports nothing from `fora_sdk`, so it never masks the module-missing red the suites are
meant to surface.
"""

from __future__ import annotations

import functools
import json
import pathlib
from typing import Any

import pytest

# sdk/python/tests/conftest.py -> repo root is parents[3]
# (tests -> python -> sdk -> <repo root>).
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

GO_TESTDATA = _REPO_ROOT / "sdk" / "go" / "helpers" / "testdata"
# The fetching resolvers (WBA / well-known / endpoint) and their SSRF + revocation
# corpora live in the sdk/go/resolvers L2 package (the I/O layer, extracted from
# helpers). GO_TESTDATA stays the L1 crypto-vector home; this is its L2 sibling.
GO_RESOLVERS_TESTDATA = _REPO_ROOT / "sdk" / "go" / "resolvers" / "testdata"
# The transport tier's corpus home. A corpus lives with the tier that can produce it,
# and the Connect error envelope can only be captured from a real connect-go handler —
# which neither helpers nor resolvers may import, since both are Connect-free by
# contract. Third home, same rules: emitted by Go, replayed by all three.
GO_CONNECT_TESTDATA = _REPO_ROOT / "sdk" / "go" / "connect" / "testdata"
# The signing transport's corpus home. The signing window is a core face (core.Window,
# core.NewSigningTransport), and helpers may not import core, so its corpus is emitted
# from sdk/go/core. Fourth home, same rules.
GO_CORE_TESTDATA = _REPO_ROOT / "sdk" / "go" / "core" / "testdata"
CONFORMANCE_CORPUS = _REPO_ROOT / "conformance" / "corpus"


def load_json(path: pathlib.Path) -> Any:
    """Read+parse a shared corpus/vector file. Fails the test if it is absent.

    A missing vector file is a legitimate TDD-red signal for the two vectors the
    Go emitter has not yet produced (sign-request-vectors.json,
    acceptance-vectors.json); pytest surfaces the FileNotFoundError as a failure.
    """
    return json.loads(path.read_text())


# The corpus registry, which names this port's expected-failure file (ADR-002).
_REGISTRY = _REPO_ROOT / "sdk" / "parity" / "corpora.json"


def outcome_of(accepted: bool, reason: str | None) -> str:
    """Return the corpus outcome (ADR-002 rule 3) of a call that accepted, or refused
    for ``reason``, the token the SDK reported. A refusal without a token renders as
    ``refused:``, which matches no row."""
    return "accepted" if accepted else f"refused:{reason or ''}"


@functools.cache
def _expected_failures() -> dict[str, str]:
    """This port's expected-failure entries, as row pointer -> the outcome it gives today."""
    registry = load_json(_REGISTRY)
    entries = load_json(_REPO_ROOT / registry["expected_failures"]["python"])["entries"]
    return {str(e["row"]): str(e["outcome"]) for e in entries}


def expected_outcome(pointer: str, outcome: str) -> str:
    """Return the outcome a replay asserts for the row at ``pointer`` (``<corpus>#<row>``):
    the outcome this port's expected-failure file records for it, or else the row's own
    ``outcome``. So a listed row fails when it starts passing and when it fails
    differently (ADR-002 rule 6)."""
    return _expected_failures().get(pointer, outcome)


# What decides a resolver's transport outcome from the environment, and so what a test of
# that outcome must not inherit from the shell that runs it. SKIP_SSRF and ALLOW_INSECURE
# are the two flags the guarded clients read. The proxy variables are read by the plain
# client (``default_client`` leaves httpx's ``trust_env`` on, and httpx reads them through
# ``urllib.request.getproxies``, in either case), so a developer's proxy could otherwise
# carry a plain-client request. The guarded clients set ``trust_env=False`` and read none.
SSRF_ENV = (
    "SKIP_SSRF",
    "ALLOW_INSECURE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@pytest.fixture
def ssrf_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Clear every variable in ``SSRF_ENV`` for one test and return ``monkeypatch``, so a
    test that needs a flag sets it after this fixture has run. ``monkeypatch`` restores
    the shell's values afterwards."""
    for name in SSRF_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch
