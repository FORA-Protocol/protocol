"""Raw mode: a per-call ``RawBody`` sent exactly as given.

A harness probing how a service refuses a malformed message needs to put bytes on the
wire the SDK would never build — a missing ``ver``, a wrong type, an unknown member —
and still have them signed and the answer decoded. ``RawBody`` is that seam: it replaces
the request of any verb, the SDK fills in nothing and refuses nothing about the message,
and everything around the message (signing, ``before_sign``, the read cap, the decode)
works as for any call.

Every case runs the real client, on both faces, against a peer that verifies the RFC 9421
signature with the SDK's own server-side verifier, so "sent unchanged" also means "signed
over exactly those bytes".
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_peer import SignedPeer
from test_client import AGENT_SEED, FACES, Face, _config

import fora_sdk.sync as sync_client
from fora_sdk.client import (
    AdminClient,
    BrokerClient,
    CallError,
    CallErrorKind,
    CatalogClient,
    Client,
    ClientConfig,
    ExecuteResult,
    RawBody,
)
from fora_sdk.httpsig import content_digest
from fora_sdk.keyresolver import StaticKeyResolver

_IDS = [f.name for f in FACES]
_KEYID = "agent.v1"
_AGENT_PUBLIC = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()


def _keys(_signature_agent: str) -> StaticKeyResolver:
    return StaticKeyResolver({_KEYID: _AGENT_PUBLIC})


def _answering(body: dict[str, Any]) -> SignedPeer:
    return SignedPeer(keys=_keys, answer=lambda _r: httpx.Response(200, json=body))


def _face(face: Face, cls: str, config: ClientConfig, peer: SignedPeer) -> Any:
    async_classes = {
        "client": Client,
        "broker": BrokerClient,
        "catalog": CatalogClient,
        "admin": AdminClient,
    }
    sync_classes = {
        "client": sync_client.Client,
        "broker": sync_client.BrokerClient,
        "catalog": sync_client.CatalogClient,
        "admin": sync_client.AdminClient,
    }
    if face.name == "async":
        return async_classes[cls](config, http=peer.async_())
    return sync_classes[cls](config, http=peer.sync())


class _Resolver:
    """Resolves every Exchange to one origin, as an Exchange's own manifest would."""

    def resolve_endpoint(self, exchange: str) -> str:
        assert exchange == "exchange.test"
        return "https://exchange.test"


#: Bytes the SDK would never send: no ver, a field of the wrong type, an unknown member,
#: and whitespace the SDK's own serializer never writes.
_MALFORMED = b'{ "exchange": "exchange.test", "uris": "not-a-list", "surprise": true }'


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_raw_bytes_are_sent_and_signed_unchanged(face: Face) -> None:
    peer = _answering({"ver": "1.0", "exchange": "exchange.test"})
    client = _face(face, "client", _config(), peer)

    face.run(client.discover(RawBody(_MALFORMED)))

    got = peer.only()
    assert got.request.content == _MALFORMED
    # Signed over exactly those bytes: the digest is of the raw body, and the peer's
    # verifier accepted the signature that covers it.
    assert got.verdict.valid
    assert got.header("content-digest") == content_digest(_MALFORMED)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_json_value_is_serialized_once_and_nothing_is_filled_in(face: Face) -> None:
    peer = _answering({"ver": "1.0", "exchange": "exchange.test"})
    # A requester is configured, and still not stamped: raw mode fills in nothing.
    client = _face(face, "client", _config(), peer)

    face.run(client.discover(RawBody({"exchange": "exchange.test"})))

    assert peer.only().request.content == b'{"exchange":"exchange.test"}'


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_string_is_sent_as_its_utf8_bytes(face: Face) -> None:
    peer = _answering({"ver": "1.0"})
    client = _face(face, "catalog", _config(), peer)

    face.run(client.push_resources(RawBody('{"exchange":"exchange.test","note":"é"}')))

    assert peer.only().request.content == '{"exchange":"exchange.test","note":"é"}'.encode()


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_local_refusals_about_the_message_are_skipped(face: Face) -> None:
    # A catalog push naming no recipient is refused locally as not sent — unless raw.
    peer = _answering({"ver": "1.0"})
    client = _face(face, "catalog", _config(), peer)
    body = b'{"entries":[]}'

    face.run(client.push_resources(RawBody(body)))

    assert peer.only().request.content == body
    with pytest.raises(CallError) as caught:
        face.run(_face(face, "catalog", _config(), _answering({})).push_resources({"entries": []}))
    assert caught.value.kind is CallErrorKind.NOT_SENT


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_execute_takes_a_raw_purchase_and_decodes_the_answer(face: Face) -> None:
    answer = {"ver": "1.0", "items": [{"offer_id": "o-1", "transaction_id": "tx-1"}]}
    peer = _answering(answer)
    client = _face(face, "client", _config(), peer)
    body = b'{"items":[]}'

    result = face.run(client.execute(RawBody(body)))

    assert peer.only().request.content == body
    assert peer.only().request.url.path == "/fora.v1.ExchangeService/ExecuteTransaction"
    assert isinstance(result, ExecuteResult)
    assert result.items[0].transaction_id == "tx-1"
    # Nothing ties a raw answer to a request the SDK built, so nothing was verified.
    assert result.deliveries == ()


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_broker_purchase_takes_a_raw_body(face: Face) -> None:
    peer = _answering({"ver": "1.0"})
    client = _face(face, "broker", _config(base_url="https://broker.test"), peer)

    face.run(client.execute(RawBody(b"{}")))

    assert peer.only().request.url.path == "/fora.v1.BrokerService/ExecuteTransaction"
    assert peer.only().request.content == b"{}"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_routed_verb_still_reads_its_destination_from_the_body(face: Face) -> None:
    peer = _answering({"ver": "1.0", "report_id": "r-1"})
    client = _face(face, "client", _config(endpoint_resolver=_Resolver()), peer)
    body = b'{"exchange":"exchange.test","transaction_id":7}'

    face.run(client.report_usage(RawBody(body)))

    got = peer.only().request
    assert got.url == "https://exchange.test/fora.v1.ExchangeService/ReportUsage"
    assert got.content == body


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("body", [b"{}", b"not json", b'{"exchange": 5}'])
def test_a_routed_raw_body_with_no_usable_exchange_is_not_sent(face: Face, body: bytes) -> None:
    peer = _answering({})
    client = _face(face, "client", _config(endpoint_resolver=_Resolver()), peer)

    with pytest.raises(CallError) as caught:
        face.run(client.dispute(RawBody(body)))

    assert caught.value.kind is CallErrorKind.NOT_SENT
    assert peer.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_before_sign_still_runs_on_a_raw_body(face: Face) -> None:
    peer = _answering({"ver": "1.0", "rate": {"tenant_id": "tenant-1", "fee_rate_bps": 0}})
    seen: list[bytes] = []

    def hook(request: httpx.Request) -> httpx.Request:
        seen.append(request.read())
        return request

    client = _face(face, "admin", _config(before_sign=hook), peer)
    face.run(client.set_tenant_fee_rate(RawBody(b'{"rate":{}}')))

    assert seen == [b'{"rate":{}}']
    assert peer.only().request.content == b'{"rate":{}}'


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_answer_to_a_raw_call_is_decoded_as_usual(face: Face) -> None:
    # A refusal comes back typed; a malformed success answer is refused as malformed.
    peer = SignedPeer(
        keys=_keys,
        answer=lambda _r: httpx.Response(
            400, content=json.dumps({"code": "invalid_argument", "message": "bad"}).encode()
        ),
    )
    with pytest.raises(CallError) as caught:
        face.run(_face(face, "client", _config(), peer).discover(RawBody(b"{}")))
    assert caught.value.kind is CallErrorKind.REFUSED
    assert caught.value.code == "invalid_argument"

    camel = _answering({"ver": "1.0", "rateLimit": {}})
    with pytest.raises(CallError) as caught:
        face.run(_face(face, "client", _config(), camel).discover(RawBody(b"{}")))
    assert caught.value.kind is CallErrorKind.MALFORMED
