"""``CallError.headers``: the header fields of a refusal, and only of a refusal.

A peer's error answer says what it wants next in its header fields: a Web Bot Auth
verifier names the signature it requires in ``Accept-Signature``, a draining gateway sets
``Retry-After``, a delivery edge's 403 carries the discovery headers. ``headers`` carries
them for an answer of status 400 or above, on both legs and both faces. Every other
failure carries none: a local one, a transport one, a 2xx this client could not read, and a
refused redirect, whose ``Location`` names a URL the peer chose.

The constructor owns the rule, so every case below is the same rule seen from a different
site that builds the failure.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from test_call_error_code import _Answer, _discover_fails
from test_client import _IDS, FACES, Face, _config

import fora_sdk.sync as sync_client
from fora_sdk import AcceptSignatureHeader, parse_discovery_hint
from fora_sdk.client import CallError, CallErrorKind, Client
from fora_sdk.client._call import decode
from fora_sdk.pop import POP_ACCEPT_SIGNATURE
from fora_sdk.wba import accept_signature
from fora_sdk.wire import ContentRulesHeader, ExchangeHeader
from wire.models import ResourceResponse

_UNAUTHENTICATED = json.dumps(
    {"code": "unauthenticated", "message": "the request is not signed"}
).encode()
_JSON = {"content-type": "application/json"}
#: A value no message carries by accident, so its absence from ``str(err)`` is evidence.
_PROBE = "probe-6c1f0e"


def _assert_not_rendered(err: CallError) -> None:
    for name, value in err.headers.items():
        assert value not in str(err), f"the message renders {name}: {err}"


# ---------------------------------------------------------------------------
# The rule, at the constructor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("status", [None, 200, 204, 302, 304, 399])
def test_no_error_status_carries_no_fields(status: int | None) -> None:
    err = CallError(CallErrorKind.REFUSED, "op", status=status, headers={"X-Probe": _PROBE})

    assert dict(err.headers) == {}


@pytest.mark.parametrize("status", [400, 401, 403, 429, 503])
def test_an_error_status_carries_a_copy_of_its_fields(status: int) -> None:
    fields = {"X-Probe": _PROBE}
    err = CallError(CallErrorKind.REFUSED, "op", status=status, headers=fields)
    fields["X-Probe"] = "changed"

    assert err.headers["X-Probe"] == _PROBE
    # Read case-insensitively, as HTTP header fields are.
    assert err.headers["x-probe"] == _PROBE


def test_a_field_sent_on_two_lines_reads_as_one_joined_value() -> None:
    lines = httpx.Headers([("X-Probe", f"{_PROBE}-first"), ("X-Probe", f"{_PROBE}-second")])
    err = CallError(CallErrorKind.REFUSED, "op", status=400, headers=lines)

    assert err.headers["X-Probe"] == f"{_PROBE}-first, {_PROBE}-second"


def test_no_fields_given_carries_none() -> None:
    assert dict(CallError(CallErrorKind.REFUSED, "op", status=401).headers) == {}


def test_the_fields_are_never_rendered() -> None:
    err = CallError(CallErrorKind.REFUSED, "op", status=401, headers={"X-Probe": _PROBE})

    _assert_not_rendered(err)
    assert _PROBE not in repr(err)


# ---------------------------------------------------------------------------
# Every site that builds a failure from an RPC answer, on both faces
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_envelope_refusal_names_what_the_verifier_requires(face: Face) -> None:
    answer = _Answer(401, _UNAUTHENTICATED, {**_JSON, AcceptSignatureHeader: accept_signature()})

    failure = _discover_fails(face, answer)

    assert failure.kind is CallErrorKind.REFUSED
    assert failure.status == 401
    assert failure.headers[AcceptSignatureHeader] == accept_signature()
    _assert_not_rendered(failure)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_draining_gateway_says_when_to_come_back(face: Face) -> None:
    failure = _discover_fails(face, _Answer(503, b"draining", {"retry-after": "86400"}))

    assert failure.kind is CallErrorKind.UNREACHABLE
    assert failure.status == 503
    assert failure.headers["Retry-After"] == "86400"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_strictly_refused_envelope_keeps_its_fields(face: Face) -> None:
    envelope = json.dumps(
        {"code": "unauthenticated", "message": "not signed", "bogus": True}
    ).encode()
    answer = _Answer(401, envelope, {**_JSON, AcceptSignatureHeader: accept_signature()})

    failure = _discover_fails(face, answer, strict=True)

    assert failure.kind is CallErrorKind.MALFORMED
    assert failure.code == "unauthenticated"
    assert failure.status == 401
    assert failure.headers[AcceptSignatureHeader] == accept_signature()


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_refusal_in_a_coding_it_was_not_asked_for_keeps_its_fields(face: Face) -> None:
    answer = _Answer(401, b"\x1f\x8b", {"content-encoding": "gzip", "x-probe": _PROBE})

    failure = _discover_fails(face, answer)

    assert failure.kind is CallErrorKind.MALFORMED
    assert failure.status == 401
    assert failure.headers["X-Probe"] == _PROBE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_refusal_past_the_read_cap_keeps_its_fields(face: Face) -> None:
    answer = _Answer(401, b"x" * 64, {"x-probe": _PROBE})

    failure = _discover_fails(face, answer, max_rpc_read_bytes=8)

    assert failure.kind is CallErrorKind.TOO_LARGE
    assert failure.status == 401
    assert failure.headers["X-Probe"] == _PROBE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_refusal_nested_too_deep_keeps_its_fields(face: Face) -> None:
    answer = _Answer(400, b"[" * 40 + b"]" * 40, {**_JSON, "x-probe": _PROBE})

    failure = _discover_fails(face, answer)

    assert failure.kind is CallErrorKind.MALFORMED
    assert failure.status == 400
    assert failure.headers["X-Probe"] == _PROBE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_refused_redirect_carries_no_fields(face: Face) -> None:
    answer = _Answer(
        302, b"", {"location": f"https://elsewhere.test/next?token={_PROBE}", "x-probe": _PROBE}
    )

    failure = _discover_fails(face, answer)

    assert failure.kind is CallErrorKind.UNREACHABLE
    assert failure.status == 302
    assert dict(failure.headers) == {}


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_2xx_that_is_not_json_carries_no_fields(face: Face) -> None:
    failure = _discover_fails(face, _Answer(200, b"<html></html>", {"x-probe": _PROBE}))

    assert failure.kind is CallErrorKind.MALFORMED
    assert dict(failure.headers) == {}


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_strictly_refused_success_carries_no_fields(face: Face) -> None:
    body = json.dumps({"ver": "1.0", "bogus": 1}).encode()

    failure = _discover_fails(face, _Answer(200, body, {**_JSON, "x-probe": _PROBE}), strict=True)

    assert failure.kind is CallErrorKind.MALFORMED
    assert dict(failure.headers) == {}


def test_decode_still_takes_its_positional_arguments() -> None:
    with pytest.raises(CallError) as caught:
        decode("discover", 401, _UNAUTHENTICATED.decode(), ResourceResponse)

    assert caught.value.status == 401
    assert dict(caught.value.headers) == {}


# ---------------------------------------------------------------------------
# The delivery fetch
# ---------------------------------------------------------------------------


def _fetch_fails(face: Face, response: httpx.Response) -> CallError:
    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return response

    transport = httpx.MockTransport(respond)
    config = _config()
    client: Any = (
        Client(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.Client(config, http=httpx.Client(transport=transport))
    )
    with pytest.raises(CallError) as caught:
        face.run(client.fetch("https://edge.test/doc"))
    return caught.value


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_refused_proof_is_asked_for_again(face: Face) -> None:
    failure = _fetch_fails(
        face,
        httpx.Response(
            401,
            json={"error": "unauthorized", "reason": "pop_sig_invalid"},
            headers={AcceptSignatureHeader: POP_ACCEPT_SIGNATURE},
        ),
    )

    assert failure.status == 401
    assert failure.headers[AcceptSignatureHeader] == POP_ACCEPT_SIGNATURE
    _assert_not_rendered(failure)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_edge_403_names_where_the_terms_are(face: Face) -> None:
    rules = "https://publisher.test/.well-known/fora.json"
    failure = _fetch_fails(
        face,
        httpx.Response(
            403,
            json={"error": "forbidden"},
            headers={ContentRulesHeader: rules, ExchangeHeader: "exchange.test"},
        ),
    )

    hint = parse_discovery_hint(failure.status or 0, failure.headers)
    assert (hint.content_rules, hint.content_rules_state) == (rules, "valid")
    assert (hint.exchange, hint.exchange_state) == ("exchange.test", "valid")


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_edge_redirect_carries_no_fields(face: Face) -> None:
    failure = _fetch_fails(
        face,
        httpx.Response(
            302,
            headers={"location": f"https://elsewhere.test/doc?token={_PROBE}", "x-probe": _PROBE},
        ),
    )

    assert failure.kind is CallErrorKind.UNREACHABLE
    assert dict(failure.headers) == {}
