"""Replay of the refusal-header corpus (refusal-header-vectors.json), on both faces.

The corpus is the cross-language contract for which failures carry the header fields of
the answer that produced them: an answer of status 400 or above, on the RPC legs and the
delivery fetch, and never a redirect or a 2xx the client could not read. Each row serves its
own answer through the real client and checks what ``CallError.headers`` carries, the
status beside it, and the discovery hint a caller parses from the two.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from test_client import _IDS, FACES, Face, _config

import fora_sdk.sync as sync_client
from conftest import GO_CONNECT_TESTDATA, load_json
from fora_sdk import parse_discovery_hint
from fora_sdk.client import CallError, Client

_ROWS: list[dict[str, Any]] = load_json(GO_CONNECT_TESTDATA / "refusal-header-vectors.json")[
    "refusals"
]
_QUERY = {"exchange": "exchange.test", "uris": ["https://site.test/a"]}


def _serving(row: dict[str, Any]) -> httpx.MockTransport:
    """An answer of exactly the row's status, content type, body and field lines."""

    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        fields = [("content-type", row["content_type"])] + [
            (name, value) for name, value in row["headers"]
        ]
        return httpx.Response(row["status"], headers=fields, content=row["body"].encode())

    return httpx.MockTransport(respond)


def _failure(face: Face, row: dict[str, Any]) -> CallError:
    transport = _serving(row)
    config = _config(strict=row["strict"])
    client: Any = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )
    with pytest.raises(CallError) as caught:
        # Built inside the block: the blocking face runs the call as it is made.
        face.run(
            client.discover(dict(_QUERY))
            if row["leg"] == "rpc"
            else client.fetch("https://edge.test/doc")
        )
    return caught.value


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("row", _ROWS, ids=[r["name"] for r in _ROWS])
def test_a_failure_carries_what_the_corpus_records(face: Face, row: dict[str, Any]) -> None:
    failure = _failure(face, row)

    if not row["carried"]:
        # The whole set, not only the row's names: a failure that carries nothing carries
        # nothing at all.
        assert dict(failure.headers) == {}
    else:
        assert failure.status == row["status"]
        for name, value in row["carried"].items():
            assert failure.headers[name] == value
            assert value not in str(failure)

    hint = parse_discovery_hint(failure.status or 0, failure.headers)
    assert {
        "content_rules": hint.content_rules or "",
        "content_rules_state": hint.content_rules_state,
        "exchange": hint.exchange or "",
        "exchange_state": hint.exchange_state,
    } == row["hint"]


def test_the_corpus_pins_both_outcomes_on_both_legs() -> None:
    seen = {(row["leg"], bool(row["carried"])) for row in _ROWS}
    assert seen == {("rpc", True), ("rpc", False), ("content", True), ("content", False)}
    assert any(row["strict"] for row in _ROWS)
    assert any(row["hint"]["exchange_state"] == "valid" for row in _ROWS)
