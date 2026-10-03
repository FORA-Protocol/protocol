"""Delivery verification: ``execute`` and ``fetch`` check a signed retrieval URL first.

An Exchange signs each retrieval URL with Ed25519 over ``"GET\\n<canonical URL>"``, names
its key by thumbprint in ``kid``, binds the URL to the buying agent with ``agent_id`` and
expires it at ``exp``. The client verifies all three against the key the Exchange
publishes in its Web Bot Auth directory, so a URL that could never be fetched is refused
when it arrives — with the edge's own reason vocabulary — instead of failing at the edge.

The key is resolved by the SDK's real ``WBAKeyResolver`` from a directory built with the
identity helpers and served in-process; the purchase runs the real client, on both
faces, against a peer that verifies the request signature.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_peer import SignedPeer
from test_broker_execute import _broker_config, _offer
from test_client import AGENT_SEED, FACES, Face, _config, _signed_offer, _verified

import fora_sdk.sync as sync_client
from fora_sdk.client import (
    BrokerClient,
    CallError,
    CallErrorKind,
    Client,
    ClientConfig,
    Delivery,
    RawBody,
)
from fora_sdk.core import Mode
from fora_sdk.identity import directory_document
from fora_sdk.keyresolver import StaticKeyResolver
from fora_sdk.resolvers import WBAKeyResolver
from fora_sdk.signedurl import sign_ed25519_signed_url
from fora_sdk.signing_transport import SigningTransport
from fora_sdk.thumbprint import thumbprint

if TYPE_CHECKING:
    from collections.abc import Callable

_IDS = [f.name for f in FACES]
_KEYID = "agent.v1"
_AGENT_PUBLIC = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
_AGENT = SigningTransport(signer_seed=AGENT_SEED, keyid=_KEYID).thumbprint
_EDGE = "https://edge.example/content/asset-1"


class _Exchange:
    """One Exchange's URL-signing key, and the directory that publishes it."""

    def __init__(self, domain: str) -> None:
        self.domain = domain
        self.key = Ed25519PrivateKey.generate()
        self.kid = thumbprint(self.key.public_key().public_bytes_raw())
        self.serve = True

    def sign(self, *, agent_id: str = _AGENT, exp: int | None = None, key: Any = None) -> str:
        return sign_ed25519_signed_url(
            _EDGE,
            seed=(key or self.key).private_bytes_raw(),
            kid=self.kid,
            agent_id=agent_id,
            exp=exp if exp is not None else int(time.time()) + 600,
        )


def _directories(*exchanges: _Exchange) -> WBAKeyResolver:
    """A real WBA resolver over an in-process origin serving each Exchange's directory."""
    by_host = {e.domain: e for e in exchanges}

    def respond(request: httpx.Request) -> httpx.Response:
        exchange = by_host.get(request.url.host)
        if exchange is None or not exchange.serve:
            return httpx.Response(503)
        document = directory_document([exchange.key.public_key()])
        return httpx.Response(200, content=json.dumps(document).encode())

    return WBAKeyResolver(http=httpx.Client(transport=httpx.MockTransport(respond)))


def _peer(answer: dict[str, Any]) -> SignedPeer:
    return SignedPeer(
        keys=lambda _sa: StaticKeyResolver({_KEYID: _AGENT_PUBLIC}),
        answer=lambda _r: httpx.Response(200, content=json.dumps(answer).encode()),
    )


def _client(face: Face, config: ClientConfig, peer: SignedPeer) -> Any:
    if face.name == "async":
        return Client(config, http=peer.async_())
    return sync_client.Client(config, http=peer.sync())


def _answer(url: str | None, *, stated: str = _AGENT, **item: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {"offer_id": "offer-1", "transaction_id": "tx-1", **item}
    if url is not None:
        entry["retrieval_endpoint"] = url
    return {"ver": "1.0", "agent_identity_hash": stated, "items": [entry]}


def _buy(face: Face, exchange: _Exchange, answer: dict[str, Any], **config: Any) -> Any:
    return face.run(_buy_call(face, exchange, answer, **config))


def _buy_call(face: Face, exchange: _Exchange, answer: dict[str, Any], **config: Any) -> Any:
    """The purchase of one verified offer from ``exchange``, not yet run."""
    offer, public = _signed_offer(exchange.domain)
    keys = config.pop("delivery_keys", None) or _directories(exchange)
    client = _client(face, _config(delivery_keys=keys, **config), _peer(answer))
    return client.execute(_verified(public, offer))


def _refusal(face: Face, call: Callable[[], Any]) -> CallError:
    with pytest.raises(CallError) as caught:
        face.run(call())
    return caught.value


def _reason(err: CallError) -> str:
    assert err.detail is not None, "a delivery refusal carries a typed retrieval_auth_failure"
    assert err.detail.domain == "fora.v1.Client"
    return str(err.detail.retrieval_auth_failure.reason.value)


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_verified_url_is_handed_back_with_its_binding(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    url = exchange.sign()

    result = _buy(face, exchange, _answer(url))

    assert result.items[0].retrieval_endpoint == url
    (delivery,) = result.deliveries
    assert delivery == Delivery(
        url=url,
        exchange="exchange.test",
        agent_id=_AGENT,
        key_id=exchange.kid,
        expires_at=delivery.expires_at,
    )
    assert delivery.expires_at > datetime.now(UTC)
    # Not part of the message: the result still dumps as the TransactionResponse.
    assert "deliveries" not in result.model_dump()


def _refused_purchase(face: Face, answer: dict[str, Any], **config: Any) -> CallError:
    exchange = config.pop("exchange")
    return _refusal(face, lambda: _buy_call(face, exchange, answer, **config))


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_url_signed_by_another_key_is_refused(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    forged = exchange.sign(key=Ed25519PrivateKey.generate())

    err = _refused_purchase(face, _answer(forged), exchange=exchange)

    assert err.kind is CallErrorKind.MALFORMED
    assert _reason(err) == "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH"
    assert "item 0 (tx-1)" in str(err), "the refusal names the item and its transaction"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_url_bound_to_another_agent_is_refused(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    other = thumbprint(Ed25519PrivateKey.generate().public_key().public_bytes_raw())

    err = _refused_purchase(
        face, _answer(exchange.sign(agent_id=other), stated=other), exchange=exchange
    )

    assert _reason(err) == "RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_bearer_url_under_a_stated_binding_is_refused(face: Face) -> None:
    exchange = _Exchange("exchange.test")

    err = _refused_purchase(face, _answer(exchange.sign(agent_id="")), exchange=exchange)

    assert _reason(err) == "RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_expired_url_is_refused(face: Face) -> None:
    exchange = _Exchange("exchange.test")

    err = _refused_purchase(
        face, _answer(exchange.sign(exp=int(time.time()) - 1)), exchange=exchange
    )

    assert _reason(err) == "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize(
    ("mangle", "reason"),
    [
        (lambda u: u.split("&sig=")[0], "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING"),
        (
            lambda u: u.replace("exp=", "expiry="),
            "RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING",
        ),
        (
            lambda u: u.replace("kid=", "kidx="),
            "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH",
        ),
    ],
    ids=["no-sig", "no-exp", "no-kid"],
)
def test_a_url_missing_a_part_is_refused(
    face: Face, mangle: Callable[[str], str], reason: str
) -> None:
    exchange = _Exchange("exchange.test")

    err = _refused_purchase(face, _answer(mangle(exchange.sign())), exchange=exchange)

    assert _reason(err) == reason


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_unreachable_key_directory_is_unreachable_not_a_verdict(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    exchange.serve = False

    err = _refused_purchase(face, _answer(exchange.sign()), exchange=exchange)

    assert err.kind is CallErrorKind.UNREACHABLE


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_bearer_url_under_no_stated_binding_verifies_unbound(face: Face) -> None:
    exchange = _Exchange("exchange.test")

    result = _buy(face, exchange, _answer(exchange.sign(agent_id=""), stated=""))

    assert result.deliveries[0].agent_id == ""


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_item_without_a_url_has_no_delivery(face: Face) -> None:
    exchange = _Exchange("exchange.test")

    result = _buy(face, exchange, _answer(None, denial_reason="DENIAL_REASON_RATE_LIMITED"))

    assert result.deliveries == (None,)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_verification_off_is_the_named_opt_out(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    forged = exchange.sign(key=Ed25519PrivateKey.generate())

    result = _buy(face, exchange, _answer(forged), delivery_verification=Mode.OFF)

    assert result.items[0].retrieval_endpoint == forged
    assert result.deliveries == ()


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_raw_purchase_is_decoded_but_not_verified(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    forged = exchange.sign(key=Ed25519PrivateKey.generate())
    client = _client(face, _config(delivery_keys=_directories(exchange)), _peer(_answer(forged)))

    result = face.run(client.execute(RawBody(b"{}")))

    assert result.deliveries == ()


# ---------------------------------------------------------------------------
# BrokerClient.execute — each URL against its own Exchange's key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_broker_purchase_verifies_each_url_against_its_own_exchange(face: Face) -> None:
    a, b = _Exchange("exchange-a.test"), _Exchange("exchange-b.test")
    answer = {
        "ver": "1.0",
        "items": [
            {"offer_id": "a1", "transaction_id": "tx-a", "retrieval_endpoint": a.sign()},
            {"offer_id": "b1", "transaction_id": "tx-b", "retrieval_endpoint": b.sign()},
        ],
        "exchanges": [
            {"exchange": "exchange-a.test", "offer_ids": ["a1"], "agent_identity_hash": _AGENT},
            {"exchange": "exchange-b.test", "offer_ids": ["b1"], "agent_identity_hash": _AGENT},
        ],
    }
    offers = [_offer("a1", "exchange-a.test"), _offer("b1", "exchange-b.test")]
    config = _broker_config(delivery_keys=_directories(a, b))
    peer = _peer(answer)
    broker = (
        BrokerClient(config, http=peer.async_())
        if face.name == "async"
        else (sync_client.BrokerClient(config, http=peer.sync()))
    )

    result = face.run(broker.execute(offers))

    assert [d.exchange for d in result.deliveries] == ["exchange-a.test", "exchange-b.test"]
    assert [d.key_id for d in result.deliveries] == [a.kid, b.kid]

    # B's URL signed with A's key fails: each URL is checked against its own Exchange.
    answer["items"][1]["retrieval_endpoint"] = b.sign(key=a.key)
    peer = _peer(answer)
    broker = (
        BrokerClient(config, http=peer.async_())
        if face.name == "async"
        else (sync_client.BrokerClient(config, http=peer.sync()))
    )
    err = _refusal(face, lambda: broker.execute(offers))
    assert _reason(err) == "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH"
    assert "item 1 (tx-b)" in str(err)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------


def _edge(seen: list[httpx.Request]) -> httpx.MockTransport:
    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"bytes", headers={"content-type": "text/plain"})

    return httpx.MockTransport(respond)


def _fetching(face: Face, exchange: _Exchange, seen: list[httpx.Request]) -> Any:
    config = _config(delivery_keys=_directories(exchange))
    if face.name == "async":
        return Client(config, http=httpx.AsyncClient(transport=_edge(seen)))
    return sync_client.Client(config, http=httpx.Client(transport=_edge(seen)))


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_fetch_verifies_a_delivery_and_returns_its_binding(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    seen: list[httpx.Request] = []
    client = _fetching(face, exchange, seen)
    url = exchange.sign()

    by_url = face.run(client.fetch(url, exchange="exchange.test"))
    assert by_url.body == b"bytes"
    assert by_url.binding is not None and by_url.binding.agent_id == _AGENT

    delivery = by_url.binding
    again = face.run(client.fetch(delivery))
    assert again.binding == delivery
    assert len(seen) == 2


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_fetch_refuses_an_unverifiable_url_before_anything_is_sent(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    seen: list[httpx.Request] = []
    client = _fetching(face, exchange, seen)
    forged = exchange.sign(key=Ed25519PrivateKey.generate())

    err = _refusal(face, lambda: client.fetch(forged, exchange="exchange.test"))

    assert err.kind is CallErrorKind.MALFORMED
    assert _reason(err) == "RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH"
    assert seen == [], "a URL the client knows the edge would refuse is never dialled"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_bare_url_is_fetched_as_given(face: Face) -> None:
    exchange = _Exchange("exchange.test")
    seen: list[httpx.Request] = []
    client = _fetching(face, exchange, seen)

    content = face.run(client.fetch(exchange.sign(key=Ed25519PrivateKey.generate())))

    assert content.binding is None
    assert len(seen) == 1
