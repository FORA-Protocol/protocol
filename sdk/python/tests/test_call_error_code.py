"""``CallError.code``: the Connect code a peer's answer carried, as its own field.

``reason`` already holds the peer's token, which for an RPC answer is the Connect code and
for a delivery edge is the edge's own refusal word. A caller that wants to branch on the
Connect code specifically had to know which of the two it was looking at. ``code`` is set
exactly where a Connect code exists: a Connect error envelope, and a non-JSON non-2xx
answer whose code is derived from the status the way connect-go derives it. Everywhere
else it is ``None``: a redirect the client refused to follow, a failure that happened
before anything was sent, a 2xx that was not JSON, and the content leg, which speaks the
edge's vocabulary rather than Connect's.

Driven through the client verbs on both faces, against the shared corpora the Go oracle
captured from a real connect-go client and handler.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from test_client import _IDS, FACES, Face, _config

import fora_sdk.sync as sync_client
from conftest import GO_CONNECT_TESTDATA, load_json
from fora_sdk.client import CallError, CallErrorKind, Client

_ENVELOPES = load_json(GO_CONNECT_TESTDATA / "connect-error-vectors.json")["vectors"]
_GATEWAYS = load_json(GO_CONNECT_TESTDATA / "transport-failure-vectors.json")[
    "transport_failures"
]
_QUERY = {"exchange": "exchange.test", "uris": ["https://site.test/a"]}


class _Answer:
    """An httpx transport answering one fixed status and raw body, recording requests."""

    def __init__(self, status: int, body: bytes = b"", headers: dict[str, str] | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.seen: list[httpx.Request] = []

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        return httpx.Response(self.status, content=self.body, headers=self.headers)

    def sync(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._respond))

    def async_(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._respond))


def _discover_fails(face: Face, answer: _Answer, query: dict[str, Any] | None = None,
                    **config: Any) -> CallError:
    client = face.client(_config(**config), answer)
    with pytest.raises(CallError) as caught:
        face.run(client.discover(dict(_QUERY) if query is None else query))
    return caught.value


# ---------------------------------------------------------------------------
# The two sites that carry a Connect code
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("vector", _ENVELOPES, ids=[v["name"] for v in _ENVELOPES])
def test_a_connect_envelope_sets_code_to_its_connect_code(
    face: Face, vector: dict[str, Any]
) -> None:
    answer = _Answer(vector["http_status"], json.dumps(vector["envelope"]).encode(),
                     {"content-type": "application/json"})

    failure = _discover_fails(face, answer)

    assert failure.code == vector["code"]
    # ``reason`` is unchanged by the new field: still the peer's token.
    assert failure.reason == vector["code"]
    assert failure.status == vector["http_status"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("vector", _GATEWAYS, ids=[v["name"] for v in _GATEWAYS])
def test_an_answer_not_from_the_service_sets_the_code_its_status_implies(
    face: Face, vector: dict[str, Any]
) -> None:
    """A gateway's HTML page, an empty body, an envelope with no code: connect-go derives
    the code from the status in each case, and so does this client."""
    answer = _Answer(vector["status"], vector["body"].encode())

    failure = _discover_fails(face, answer)

    assert failure.code == vector["reason"]
    assert failure.reason == vector["reason"]
    assert failure.kind is CallErrorKind[vector["kind"].upper()]


# ---------------------------------------------------------------------------
# Everywhere else, code is None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_refused_redirect_carries_no_code(face: Face, status: int) -> None:
    answer = _Answer(status, json.dumps({"code": "permission_denied"}).encode(),
                     {"location": "https://elsewhere.test/"})

    failure = _discover_fails(face, answer)

    assert failure.kind is CallErrorKind.UNREACHABLE
    assert failure.status == status
    assert failure.code is None


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_2xx_that_is_not_json_carries_no_code(face: Face) -> None:
    failure = _discover_fails(face, _Answer(200, b"<html>not json</html>"))

    assert failure.kind is CallErrorKind.MALFORMED
    assert failure.code is None


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_request_refused_before_sending_carries_no_code(face: Face) -> None:
    answer = _Answer(200, b"{}")

    # No recipient: the generated schema refuses the message before it is signed.
    failure = _discover_fails(face, answer, query={})

    assert failure.kind is CallErrorKind.MALFORMED
    assert failure.code is None
    assert answer.seen == []


class _FailingSigner:
    def sign_outbound(self, **_kwargs: Any) -> Any:
        raise RuntimeError("custody declined")


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_signature_that_could_not_be_made_carries_no_code(face: Face) -> None:
    answer = _Answer(200, b"{}")

    failure = _discover_fails(face, answer, signer=_FailingSigner())

    assert failure.kind is CallErrorKind.NOT_SIGNABLE
    assert failure.code is None
    assert answer.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_edge_refusal_on_the_content_leg_carries_no_code(face: Face) -> None:
    """The edge answers in its own vocabulary. "expired" is its token, carried in
    ``reason``; it is not a Connect code and must not appear as one."""
    answer = _Answer(403, json.dumps({"error": "denied", "reason": "expired"}).encode(),
                     {"content-type": "application/json"})
    config = _config()
    client = (
        Client(config, http=answer.async_())
        if face.name == "async"
        else sync_client.Client(config, http=answer.sync())
    )

    with pytest.raises(CallError) as caught:
        face.run(client.fetch("https://edge.test/x"))

    assert caught.value.kind is CallErrorKind.REFUSED
    assert caught.value.reason == "expired"
    assert caught.value.code is None


# ---------------------------------------------------------------------------
# The constructor
# ---------------------------------------------------------------------------


def test_the_constructor_defaults_code_to_none_and_keeps_a_given_one() -> None:
    assert CallError(CallErrorKind.MALFORMED, "discover").code is None
    given = CallError(CallErrorKind.REFUSED, "discover", status=403,
                      reason="permission_denied", code="permission_denied")
    assert given.code == "permission_denied"
    assert given.reason == "permission_denied"
