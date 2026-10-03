"""BrokerClient.execute and the batch form of Client.execute, through the public faces.

The peer is :class:`signed_peer.SignedPeer`: it runs the SDK's own server-side verifier on
every request and refuses one that does not verify, so a passing test proves a Broker
would have authenticated the call, not only that bytes were sent. Behind the verifier it
answers the combined response a relaying Broker hands back. What the client owns —
building and signing the request, the local refusals, decoding the answer — is what these
tests assert. Mirrors sdk/go/connect/broker_execute_test.go.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_peer import SignedPeer, envelope_response
from test_client import AGENT_SEED, FACES, REQUESTER, Face, _config

import fora_sdk.sync as sync_client
from fora_sdk.client import BrokerClient, Client, ClientConfig
from fora_sdk.client.errors import CallError, CallErrorKind
from fora_sdk.core import (
    Mode,
    StaticOfferKeyResolver,
    Verifier,
    sign_offer_jcs,
    verify_offer_acceptance_jcs,
    verify_request_acceptance_jcs,
)
from fora_sdk.keyresolver import StaticKeyResolver
from fora_sdk.signing_transport import SigningTransport

_IDS = [f.name for f in FACES]
_KEYID = "agent.v1"
_DIRECTORY = "https://agent.test"
_AGENT_PUBLIC = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
_NOW = 1_700_000_000


def _agent_keys(_signature_agent: str) -> StaticKeyResolver:
    return StaticKeyResolver({_KEYID: _AGENT_PUBLIC})


def _signer(directory: str = _DIRECTORY) -> SigningTransport:
    return SigningTransport(signer_seed=AGENT_SEED, keyid=_KEYID, signature_agent=directory)


def _broker_config(**overrides: Any) -> ClientConfig:
    return _config(**{"base_url": "https://broker.test", "signer": _signer(), **overrides})


def _offer(offer_id: str, exchange: str) -> Any:
    """An offer issued by ``exchange``, signed by that Exchange's key and verified the way a
    client that resolved that key would."""
    seed = bytes([len(exchange)]) * 32
    offer: dict[str, Any] = {
        "offer_id": offer_id,
        "exchange": exchange,
        "expires_at": "2099-01-01T00:00:00Z",
    }
    signature, algorithm = sign_offer_jcs(seed=seed, offer=offer)
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    verifier = Verifier(
        mode=Mode.STRICT, resolver=StaticOfferKeyResolver({exchange: public}), now=lambda: _NOW
    )
    result = verifier.sort([{**offer, "signature": signature, "signature_algorithm": algorithm}])
    assert result.verified, result.rejected
    return result.verified[0]


def _broker(face: Face, config: ClientConfig, peer: SignedPeer) -> Any:
    if face.name == "async":
        return BrokerClient(config, http=peer.async_())
    return sync_client.BrokerClient(config, http=peer.sync())


def _answer(payload: dict[str, Any]) -> Any:
    return lambda _request: httpx.Response(200, json=payload)


_MIXED_ANSWER: dict[str, Any] = {
    "ver": "1.0",
    "items": [
        {
            "offer_id": "a1",
            "transaction_id": "tx-a1",
            "cost": {"amount": "1.25", "currency": "USD"},
        },
        {
            "offer_id": "b1",
            "refusal": {
                "exchange": "exchange-b.test",
                "code": "permission_denied",
                "detail": {
                    "domain": "fora.v1.ExchangeService",
                    "message": "no account",
                    "transaction_denial": {"reason": "DENIAL_REASON_ACCOUNT_NOT_REGISTERED"},
                },
            },
        },
        {
            "offer_id": "a2",
            "transaction_id": "tx-a2",
            "cost": {"amount": "1.25", "currency": "EUR"},
        },
    ],
    "exchanges": [
        {"exchange": "exchange-a.test", "offer_ids": ["a1", "a2"], "agent_identity_hash": "h"},
        {"exchange": "exchange-b.test", "offer_ids": ["b1"]},
    ],
    "totals": [{"amount": "1.25", "currency": "USD"}, {"amount": "1.25", "currency": "EUR"}],
}


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_mixed_batch_is_one_signed_request_and_the_combined_answer_decodes(face: Face) -> None:
    offers = [
        _offer("a1", "exchange-a.test"),
        _offer("b1", "exchange-b.test"),
        _offer("a2", "exchange-a.test"),
    ]
    peer = SignedPeer(keys=_agent_keys, answer=_answer(_MIXED_ANSWER))

    resp = face.run(_broker(face, _broker_config(), peer).execute(offers, idempotency_key="k-1"))

    received = peer.only()
    assert received.verdict.valid
    assert (
        str(received.request.url) == "https://broker.test/fora.v1.BrokerService/ExecuteTransaction"
    )
    body = json.loads(received.request.content)
    assert body["ver"] == "1.0"
    assert body["idempotency_key"] == "k-1"
    assert body["requester"] == REQUESTER
    assert [item["offer"]["offer_id"] for item in body["items"]] == ["a1", "b1", "a2"]
    pub = base64.b64encode(_AGENT_PUBLIC).decode()
    for item in body["items"]:
        assert verify_offer_acceptance_jcs(
            pubkey_b64=pub,
            signature_hex=item["agent_acceptance"]["signature"],
            offer_sig=item["offer"]["signature"],
            requester_id=REQUESTER["id"],
            requester_domain=REQUESTER["domain"],
            idempotency_key="k-1",
        )
    # One request acceptance over the complete ordered set, which every Exchange the Broker
    # relays to checks its own projection against.
    signed_items = [(i["offer"]["signature"], i["offer"]["exchange"]) for i in body["items"]]
    acceptance = body["agent_request_acceptance"]
    assert [(i["offer_sig"], i["exchange"]) for i in acceptance["payload"]["items"]] == signed_items
    assert verify_request_acceptance_jcs(
        pubkey_b64=pub,
        signature_hex=acceptance["signature"],
        items=signed_items,
        requester_id=REQUESTER["id"],
        requester_domain=REQUESTER["domain"],
        idempotency_key="k-1",
    )

    items = resp.items
    assert items[0].transaction_id == "tx-a1"
    assert items[0].refusal is None
    refusal = items[1].refusal
    assert refusal is not None
    assert refusal.code == "permission_denied"
    assert refusal.exchange == "exchange-b.test"
    assert refusal.detail.transaction_denial.reason.value == "DENIAL_REASON_ACCOUNT_NOT_REGISTERED"
    assert items[2].transaction_id == "tx-a2"
    # Per-currency totals stay apart: never summed across currencies.
    assert [(c.currency, c.amount) for c in resp.totals] == [("USD", "1.25"), ("EUR", "1.25")]
    assert [o.exchange for o in resp.exchanges] == ["exchange-a.test", "exchange-b.test"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_single_offer_is_the_one_item_purchase(face: Face) -> None:
    peer = SignedPeer(keys=_agent_keys, answer=_answer({"ver": "1.0"}))

    face.run(_broker(face, _broker_config(), peer).execute([_offer("a1", "exchange-a.test")]))

    body = json.loads(peer.only().request.content)
    assert len(body["items"]) == 1
    assert body["idempotency_key"]
    assert "agent_request_acceptance" in body


def _unaddressed() -> Any:
    offer = {"offer_id": "x", "expires_at": "2099-01-01T00:00:00Z", "signature": "ab"}
    off = Verifier(mode=Mode.OFF, resolver=StaticOfferKeyResolver({}), now=lambda: _NOW)
    return off.sort([offer]).verified[0]


_LOCAL_REFUSALS: list[tuple[str, dict[str, Any], str, CallErrorKind]] = [
    (
        "requester domain is not the signing directory",
        {"requester": {**REQUESTER, "domain": "someone-else.test"}},
        "offers",
        CallErrorKind.MALFORMED,
    ),
    (
        "no signature agent",
        {"signer": SigningTransport(signer_seed=AGENT_SEED, keyid=_KEYID)},
        "offers",
        CallErrorKind.MALFORMED,
    ),
    ("no requester", {"requester": None}, "offers", CallErrorKind.MALFORMED),
    # Every acceptance names the requester, so a requester missing either half cannot buy.
    (
        "requester with no id",
        {"requester": {**REQUESTER, "id": ""}},
        "offers",
        CallErrorKind.MALFORMED,
    ),
    (
        "requester with no domain",
        {"requester": {**REQUESTER, "domain": ""}},
        "offers",
        CallErrorKind.MALFORMED,
    ),
    ("no signer", {"signer": None}, "offers", CallErrorKind.NOT_SIGNABLE),
    ("no offers", {}, "none", CallErrorKind.MALFORMED),
    ("offer names no exchange", {"validation": "off"}, "unaddressed", CallErrorKind.MALFORMED),
]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize(
    ("name", "overrides", "which", "kind"), _LOCAL_REFUSALS, ids=[r[0] for r in _LOCAL_REFUSALS]
)
def test_every_precondition_is_refused_before_sending(
    face: Face, name: str, overrides: dict[str, Any], which: str, kind: CallErrorKind
) -> None:
    del name
    offers = {
        "offers": [_offer("a1", "exchange-a.test")],
        "none": [],
        "unaddressed": [_unaddressed()],
    }[which]
    peer = SignedPeer(keys=_agent_keys)

    with pytest.raises(CallError) as caught:
        face.run(_broker(face, _broker_config(**overrides), peer).execute(offers))

    assert caught.value.kind is kind
    assert peer.seen == [], "the Broker was contacted; this refusal must be local"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_explicit_443_and_case_are_the_same_directory(face: Face) -> None:
    peer = SignedPeer(keys=_agent_keys, answer=_answer({"ver": "1.0"}))
    config = _broker_config(signer=_signer("https://AGENT.test:443/.well-known/x"))

    face.run(_broker(face, config, peer).execute([_offer("a1", "exchange-a.test")]))

    assert peer.only().verdict.valid


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_brokers_own_refusal_is_a_call_error_with_its_typed_reason(face: Face) -> None:
    refused = envelope_response(
        401,
        {
            "code": "unauthenticated",
            "message": "requester mismatch",
            "details": [
                {
                    "type": "fora.v1.ErrorDetail",
                    "debug": {
                        "domain": "fora.v1.BrokerService",
                        "requestAuthFailure": {
                            "reason": "REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID"
                        },
                    },
                }
            ],
        },
    )
    peer = SignedPeer(keys=_agent_keys, answer=lambda _request: refused)

    with pytest.raises(CallError) as caught:
        face.run(_broker(face, _broker_config(), peer).execute([_offer("a1", "exchange-a.test")]))

    detail = caught.value.detail
    assert detail is not None
    assert detail.request_auth_failure is not None
    assert (
        detail.request_auth_failure.reason.value == "REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID"
    )


# ---------------------------------------------------------------------------
# Client.execute: the batch form at one Exchange
# ---------------------------------------------------------------------------


def _client(face: Face, config: ClientConfig, peer: SignedPeer) -> Any:
    if face.name == "async":
        return Client(config, http=peer.async_())
    return sync_client.Client(config, http=peer.sync())


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_client_execute_buys_several_offers_from_one_exchange(face: Face) -> None:
    peer = SignedPeer(keys=_agent_keys, answer=_answer({"ver": "1.0"}))
    offers = [_offer("o1", "exchange.test"), _offer("o2", "exchange.test")]

    face.run(_client(face, _config(), peer).execute(offers, idempotency_key="k-2"))

    received = peer.only()
    assert str(received.request.url).endswith("/fora.v1.ExchangeService/ExecuteTransaction")
    body = json.loads(received.request.content)
    assert [i["offer"]["offer_id"] for i in body["items"]] == ["o1", "o2"]
    assert len(body["agent_request_acceptance"]["payload"]["items"]) == 2


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_client_execute_refuses_offers_from_several_exchanges(face: Face) -> None:
    peer = SignedPeer(keys=_agent_keys)
    offers = [_offer("o1", "exchange.test"), _offer("o2", "exchange-b.test")]

    with pytest.raises(CallError) as caught:
        face.run(_client(face, _config(), peer).execute(offers))

    assert caught.value.kind is CallErrorKind.MALFORMED
    assert "BrokerClient.execute" in str(caught.value)
    assert peer.seen == []
