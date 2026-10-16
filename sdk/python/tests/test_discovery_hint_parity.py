"""Replay of the shared discovery-hint corpus against the Go oracle.

Each ``parse`` row is fed to :func:`parse_discovery_hint` twice: as an
``httpx.Headers`` built from the row's ordered ``[name, value]`` pairs, which is
what an agent holds after a real fetch, and as a plain ``dict`` whenever the row
sends no header twice. Each ``reconcile`` row parses the same way and then checks
the hinted Exchange against the domains the publisher manifest lists. Pinned to
``discovery-hint-vectors.json``.
"""

from __future__ import annotations

import httpx
import pytest

from conftest import GO_TESTDATA, load_json

from fora_sdk import (
    ContentRulesHeader,
    DiscoveryHint,
    ExchangeHeader,
    parse_discovery_hint,
    reconcile_discovery_hint,
)

_DOC = load_json(GO_TESTDATA / "discovery-hint-vectors.json")
_PARSE = _DOC["parse"]
_RECONCILE = _DOC["reconcile"]


def _expected(hint: DiscoveryHint) -> dict[str, str]:
    """The hint in the corpus's vocabulary, where an unset value is ""."""
    return {
        "content_rules": hint.content_rules or "",
        "content_rules_state": hint.content_rules_state,
        "exchange": hint.exchange or "",
        "exchange_state": hint.exchange_state,
    }


def _wire_headers(pairs: list[list[str]]) -> httpx.Headers:
    """The pairs as httpx holds a received response's headers: raw bytes on the wire.

    A received header arrives as bytes, which httpx decodes on read (ASCII, then
    UTF-8); a ``str`` value it would instead refuse to encode outside ASCII. The
    non-ASCII rows therefore go in as UTF-8 bytes, the way a fetch delivers them.
    """
    return httpx.Headers([(name.encode(), value.encode("utf-8")) for name, value in pairs])


def _has_repeats(pairs: list[list[str]]) -> bool:
    names = [name.lower() for name, _ in pairs]
    return len(names) != len(set(names))


def test_header_names_match_the_constants() -> None:
    assert _DOC["header_names"] == {
        "content_rules": ContentRulesHeader,
        "exchange": ExchangeHeader,
    }


def test_every_state_and_agreement_is_exercised() -> None:
    states = {v["expected"][k] for v in _PARSE for k in ("content_rules_state", "exchange_state")}
    assert states == {"absent", "valid", "malformed"}
    assert {v["expected_agreement"] for v in _RECONCILE} == {"no_exchange", "listed", "unlisted"}


@pytest.mark.parametrize("vector", _PARSE, ids=[v["name"] for v in _PARSE])
def test_parse_matches_go_oracle(vector: dict) -> None:
    pairs = [(name, value) for name, value in vector["headers"]]
    got = parse_discovery_hint(vector["status"], _wire_headers(vector["headers"]))
    assert _expected(got) == vector["expected"]
    if not _has_repeats(vector["headers"]):
        assert _expected(parse_discovery_hint(vector["status"], dict(pairs))) == vector["expected"]


@pytest.mark.parametrize("vector", _RECONCILE, ids=[v["name"] for v in _RECONCILE])
def test_reconcile_matches_go_oracle(vector: dict) -> None:
    hint = parse_discovery_hint(vector["status"], _wire_headers(vector["headers"]))
    assert reconcile_discovery_hint(hint, vector["listed"]) == vector["expected_agreement"]


def test_hint_from_a_real_403() -> None:
    """The parser reads the headers of an httpx.Response, the type a fetch returns."""
    resp = httpx.Response(
        403,
        headers=[
            ("X-Content-Rules", "https://publisher.example/.well-known/fora.json"),
            ("X-FORA-Exchange", "exchange.example"),
        ],
    )
    hint = parse_discovery_hint(resp.status_code, resp.headers)
    assert hint == DiscoveryHint(
        "https://publisher.example/.well-known/fora.json", "valid", "exchange.example", "valid"
    )
    assert reconcile_discovery_hint(hint, ["exchange.example"]) == "listed"
    assert reconcile_discovery_hint(hint, ["other-exchange.example"]) == "unlisted"
