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
from fora_sdk.keyresolver import StaticKeyResolver

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


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_error_envelope_is_read_the_same_way(face: Face) -> None:
    peer = SignedPeer(
        keys=lambda _sa: StaticKeyResolver({_KEYID: _AGENT_PUBLIC}),
        answer=lambda _r: httpx.Response(
            403, content=json.dumps({"code": "permission_denied", "extra": 1}).encode()
        ),
    )
    config = _config(strict=True)
    client = (
        Client(config, http=peer.async_())
        if face.name == "async"
        else sync_client.Client(config, http=peer.sync())
    )
    with pytest.raises(CallError) as caught:
        face.run(client.discover(_QUERY))
    assert caught.value.kind is CallErrorKind.REFUSED
    assert caught.value.code == "permission_denied"


def _raw() -> Any:
    from fora_sdk.client import RawBody

    return RawBody(b"{}")
