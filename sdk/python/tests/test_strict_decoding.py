"""Strict response decoding: ``ClientConfig(strict=True)``.

The generated models accept a field they do not know, because a peer on a newer minor
version may send one. A conformance harness wants the opposite, so a strict client
refuses an answer carrying an unknown field at any depth, an answer breaking a
field-level rule, and an answer breaking a cross-field rule the proto states. The shape
comes from the published strict JSON Schema of the response message and the SDK's
cross-field rules — nothing here restates it.

Each case runs the real client on both faces against an in-process peer that verifies the
request signature, and contrasts the strict client with the default one on the same
answer, so a passing refusal cannot come from something other than ``strict``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_peer import SignedPeer
from test_client import AGENT_SEED, FACES, Face, _config

import fora_sdk.sync as sync_client
from fora_sdk.client import CallError, CallErrorKind, Client
from fora_sdk.client._call import decode
from fora_sdk.keyresolver import StaticKeyResolver
from wire.models import ResourceResponse

if TYPE_CHECKING:
    from collections.abc import Callable

_IDS = [f.name for f in FACES]
_KEYID = "agent.v1"
_AGENT_PUBLIC = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
_QUERY = {"exchange": "exchange.test", "uris": ["https://publisher.example/a"]}


def _client(face: Face, answer: Any, *, strict: bool, **overrides: Any) -> Any:
    peer = SignedPeer(
        keys=lambda _sa: StaticKeyResolver({_KEYID: _AGENT_PUBLIC}),
        answer=lambda _r: httpx.Response(200, content=json.dumps(answer).encode()),
    )
    config = _config(strict=strict, **overrides)
    if face.name == "async":
        return Client(config, http=peer.async_())
    return sync_client.Client(config, http=peer.sync())


def _refused(face: Face, call: Callable[[], Any]) -> CallError:
    # A thunk, so the sync face's call runs inside the raises block.
    with pytest.raises(CallError) as caught:
        face.run(call())
    assert caught.value.kind is CallErrorKind.MALFORMED
    return caught.value


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_unknown_top_level_field_is_refused(face: Face) -> None:
    answer = {"ver": "1.0", "exchange": "exchange.test", "surprise": 1}

    # The default client accepts it: a newer minor version may add a field.
    face.run(_client(face, answer, strict=False).discover(_QUERY))

    err = _refused(face, lambda: _client(face, answer, strict=True).discover(_QUERY))
    assert "surprise" in str(err)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_unknown_field_deep_in_the_answer_is_refused(face: Face) -> None:
    answer = {
        "ver": "1.0",
        "items": [{"offer_id": "o-1", "cost": {"amount": "1", "currency": "USD", "x": 1}}],
    }
    face.run(_client(face, answer, strict=False).execute(_raw()))

    err = _refused(face, lambda: _client(face, answer, strict=True).execute(_raw()))
    assert "/items/0/cost" in str(err)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_null_message_field_is_an_absent_one(face: Face) -> None:
    # A FORA server emits unpopulated fields, so an unset message arrives as null.
    answer = {
        "ver": "1.0",
        "exchange": "exchange.test",
        "rate_limit": None,
        "offer_groups": [],
        "offers": [],
        "ext": {"vendor": None},
    }
    result = face.run(_client(face, answer, strict=True).discover(_QUERY))
    assert result.exchange == "exchange.test"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_field_level_rule_is_enforced(face: Face) -> None:
    # TransactionResponse.items[].restriction_mismatches is an enum list; a name it does
    # not define is refused by the strict schema.
    answer = {"ver": "1.0", "items": [{"offer_id": "o-1", "restriction_mismatches": ["NOPE"]}]}
    err = _refused(face, lambda: _client(face, answer, strict=True).execute(_raw()))
    assert "restriction_mismatches" in str(err)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_cross_field_rule_on_a_nested_message_is_enforced(face: Face) -> None:
    # Pricing.per_unit.requires_unit, on an offer two levels down.
    offer = {
        "offer_id": "o-1",
        "exchange": "exchange.test",
        "pricing": {"model": "PRICING_MODEL_PER_UNIT", "rate": "1", "currency": "USD"},
    }
    answer = {"ver": "1.0", "exchange": "exchange.test", "offers": [offer]}
    face.run(_client(face, answer, strict=False).discover(_QUERY))

    err = _refused(face, lambda: _client(face, answer, strict=True).discover(_QUERY))
    assert "pricing.per_unit.requires_unit" in str(err)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_cross_field_rule_on_the_answer_itself_is_enforced(face: Face) -> None:
    answer = {"ver": "1.0", "terms_digest": "sha256:" + "0" * 64}

    class _Resolver:
        def resolve_endpoint(self, exchange: str) -> str:
            del exchange
            return "https://exchange.test"

    request = {"exchange": "exchange.test"}
    lenient = _client(face, answer, strict=False, endpoint_resolver=_Resolver())
    face.run(lenient.get_account_status(request))

    strict = _client(face, answer, strict=True, endpoint_resolver=_Resolver())
    err = _refused(face, lambda: strict.get_account_status(request))
    assert "get_account_status_response.terms_digest_requires_billing_ref" in str(err)


def _client_answering(face: Face, status: int, body: bytes, *, strict: bool) -> Any:
    peer = SignedPeer(
        keys=lambda _sa: StaticKeyResolver({_KEYID: _AGENT_PUBLIC}),
        answer=lambda _r: httpx.Response(status, content=body),
    )
    config = _config(strict=strict)
    if face.name == "async":
        return Client(config, http=peer.async_())
    return sync_client.Client(config, http=peer.sync())


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_error_envelope_with_an_unknown_member_is_refused(face: Face) -> None:
    body = json.dumps({"code": "permission_denied", "extra": 1}).encode()

    # The default client reads the peer's refusal and ignores the member.
    with pytest.raises(CallError) as lenient:
        face.run(_client_answering(face, 403, body, strict=False).discover(_QUERY))
    assert lenient.value.kind is CallErrorKind.REFUSED

    # The strict client refuses the envelope, and keeps the code the peer answered with.
    err = _refused(face, lambda: _client_answering(face, 403, body, strict=True).discover(_QUERY))
    assert err.code == "permission_denied"
    assert err.status == 403
    assert err.detail is None
    assert "extra" in str(err)


def _denial_value(extra: bytes = b"") -> str:
    """A binary ErrorDetail (a transaction denial), base64 the way connect-go writes it."""
    import base64

    reason = b"\x08\x02"  # TransactionDenial.reason = INSUFFICIENT_BALANCE
    raw = b"\x12\x02ok" + b"\x52" + bytes([len(reason)]) + reason + extra
    return base64.b64encode(raw).decode().rstrip("=")


def _envelope(**members: Any) -> str:
    return json.dumps(members)


def _entry(**members: Any) -> dict[str, Any]:
    return members


_DETAIL = "fora.v1.ErrorDetail"

#: (name, status, body, refused by a strict decode). Every case also runs leniently, which
#: must not refuse it as malformed: the strict refusal comes from ``strict`` alone.
_ENVELOPE_CASES: list[tuple[str, int, str, bool]] = [
    (
        "valid envelope",
        403,
        _envelope(
            code="permission_denied",
            message="no",
            details=[_entry(type=_DETAIL, value=_denial_value())],
        ),
        False,
    ),
    (
        "null members read as absent",
        500,
        _envelope(code="internal", message=None, details=None),
        False,
    ),
    (
        "a detail of another type is not decoded",
        500,
        _envelope(
            code="internal",
            details=[_entry(type="google.rpc.RetryInfo", value="AA", debug={"any": "thing"})],
        ),
        False,
    ),
    ("a body that is not JSON is a gateway's", 502, "<html>bad gateway</html>", False),
    ("an empty body is a gateway's", 503, "", False),
    ("no code", 500, _envelope(message="x"), True),
    ("code not a Connect code", 500, _envelope(code="teapot"), True),
    ("code not a string", 500, _envelope(code=13), True),
    ("message not a string", 500, _envelope(code="internal", message=1), True),
    ("JSON but not an object", 500, json.dumps(["internal"]), True),
    ("details not an array", 500, _envelope(code="internal", details={}), True),
    (
        "entry with an unknown member",
        500,
        _envelope(code="internal", details=[_entry(type="x", value="AA", extra=1)]),
        True,
    ),
    ("entry with no type", 500, _envelope(code="internal", details=[_entry(value="AA")]), True),
    (
        "entry with neither value nor debug",
        500,
        _envelope(code="internal", details=[_entry(type="x")]),
        True,
    ),
    (
        "value not base64",
        500,
        _envelope(code="internal", details=[_entry(type="x", value="*not*")]),
        True,
    ),
    (
        "binary ErrorDetail with an unknown field",
        403,
        _envelope(
            code="permission_denied",
            details=[_entry(type=_DETAIL, value=_denial_value(b"\x98\x06\x01"))],
        ),
        True,
    ),
    (
        "debug projection that is not an object",
        403,
        _envelope(code="permission_denied", details=[_entry(type=_DETAIL, debug="x")]),
        True,
    ),
    (
        "debug projection setting two reasons",
        403,
        _envelope(
            code="permission_denied",
            details=[
                _entry(
                    type=_DETAIL,
                    debug={
                        "transactionDenial": {"reason": "DENIAL_REASON_INSUFFICIENT_BALANCE"},
                        "disputeFailure": {"reason": "DISPUTE_FAILURE_REASON_DUPLICATE"},
                    },
                )
            ],
        ),
        True,
    ),
]


@pytest.mark.parametrize(
    ("status", "body", "refused"),
    [c[1:] for c in _ENVELOPE_CASES],
    ids=[c[0] for c in _ENVELOPE_CASES],
)
def test_error_envelope_rules(status: int, body: str, refused: bool) -> None:
    with pytest.raises(CallError) as lenient:
        decode("discover", status, body, ResourceResponse)
    assert lenient.value.kind is not CallErrorKind.MALFORMED

    with pytest.raises(CallError) as strict:
        decode("discover", status, body, ResourceResponse, strict=True)
    assert (strict.value.kind is CallErrorKind.MALFORMED) is refused, str(strict.value)
    # The strict read keeps the code the lenient read reports, refused or not.
    assert strict.value.code == lenient.value.code


def _raw() -> Any:
    from fora_sdk.client import RawBody

    return RawBody(b"{}")
