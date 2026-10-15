"""The operator client: ``AdminClient`` (Python side) — mirror of sdk/go/connect/admin_test.go.

It must cover every RPC of ``fora.admin.v1.AdminService`` and the two domain-verification
RPCs of ``fora.v1.ExchangeService``. The admin RPCs are enumerated from the proto file
rather than listed here, so an RPC added to the service fails this suite until the client
carries it.

Each call runs on both faces against an in-process peer that verifies the request
signature with the SDK's own server-side verifier and answers the generated response.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_peer import SignedPeer
from test_client import AGENT_SEED, FACES, Face, _config
from wire.models import SetTenantFeeRateRequest, TenantFeeRate

import fora_sdk.sync as sync_client
from fora_sdk.client import AdminClient, CallError, CallErrorKind, ClientConfig
from fora_sdk.keyresolver import StaticKeyResolver

_IDS = [f.name for f in FACES]
_KEYID = "agent.v1"
_AGENT_PUBLIC = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
_ADMIN_PROTO = (
    Path(__file__).resolve().parents[3] / "proto" / "fora" / "admin" / "v1" / "admin.proto"
)

_FEE = {"tenant_id": "tenant-1", "fee_rate_bps": 250, "notes": "launch rate"}
_POLICY = {
    "tenant_id": "tenant-1",
    "required_fields": ["consumed_quantity"],
    "window_seconds": 3600,
}

#: One call per RPC: the client method, the request, the answer, and the path it must reach.
_CALLS: dict[str, tuple[str, dict[str, Any], dict[str, Any], str]] = {
    "SetTenantFeeRate": (
        "set_tenant_fee_rate",
        {"rate": _FEE},
        {"ver": "1.0", "rate": _FEE},
        "/fora.admin.v1.AdminService/SetTenantFeeRate",
    ),
    "SetReportingPolicy": (
        "set_reporting_policy",
        {"policy": _POLICY},
        {"ver": "1.0", "policy": _POLICY},
        "/fora.admin.v1.AdminService/SetReportingPolicy",
    ),
    "RequestDomainVerification": (
        "request_domain_verification",
        {"exchange": "exchange.test", "domain": "publisher.example"},
        {
            "ver": "1.0",
            "token": "tok-1",
            "verification_url": "https://publisher.example/.well-known/fora-verify/tok-1",
        },
        "/fora.v1.ExchangeService/RequestDomainVerification",
    ),
    "ConfirmDomainVerification": (
        "confirm_domain_verification",
        {"exchange": "exchange.test", "domain": "publisher.example", "token": "tok-1"},
        {"ver": "1.0", "key_id": "k-1"},
        "/fora.v1.ExchangeService/ConfirmDomainVerification",
    ),
}


def _admin_rpcs() -> list[str]:
    """Every rpc of AdminService, read from the proto file."""
    text = _ADMIN_PROTO.read_text(encoding="utf-8")
    service = text[text.index("service AdminService") :]
    service = service[: service.index("\n}")]
    return re.findall(r"^\s*rpc (\w+)\(", service, flags=re.MULTILINE)


def _client(face: Face, config: ClientConfig, peer: SignedPeer) -> Any:
    if face.name == "async":
        return AdminClient(config, http=peer.async_())
    return sync_client.AdminClient(config, http=peer.sync())


def _peer(answer: dict[str, Any]) -> SignedPeer:
    return SignedPeer(
        keys=lambda _sa: StaticKeyResolver({_KEYID: _AGENT_PUBLIC}),
        answer=lambda _r: httpx.Response(200, content=json.dumps(answer).encode()),
    )


def test_every_admin_rpc_has_a_call_here() -> None:
    rpcs = _admin_rpcs()
    assert rpcs, "no rpc read from admin.proto; the enumeration is broken"
    assert set(rpcs) <= set(_CALLS), (
        f"AdminService RPCs with no client call: {set(rpcs) - set(_CALLS)}"
    )


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("rpc", sorted(_CALLS))
def test_each_rpc_reaches_its_path_stamped_signed_and_decoded(face: Face, rpc: str) -> None:
    method, request, answer, path = _CALLS[rpc]
    peer = _peer(answer)
    client = _client(face, _config(base_url="https://admin.test"), peer)

    result = face.run(getattr(client, method)(request))

    got = peer.only()
    assert got.request.url.path == path
    assert got.verdict.valid, "the request signature did not verify"
    sent = json.loads(got.request.content)
    assert sent == {"ver": "1.0", **request}
    assert result.model_dump(mode="json", exclude_unset=True) == answer


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_generated_model_is_accepted(face: Face) -> None:
    peer = _peer({"ver": "1.0", "rate": _FEE})
    client = _client(face, _config(base_url="https://admin.test"), peer)
    model = SetTenantFeeRateRequest(rate=TenantFeeRate(**_FEE))

    face.run(client.set_tenant_fee_rate(model))

    assert json.loads(peer.only().request.content) == {"ver": "1.0", "rate": _FEE}


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("method", ["request_domain_verification", "confirm_domain_verification"])
@pytest.mark.parametrize("exchange", [None, "https://exchange.test"])
def test_a_domain_request_with_no_bare_recipient_is_not_sent(
    face: Face, method: str, exchange: str | None
) -> None:
    peer = _peer({})
    client = _client(face, _config(base_url="https://admin.test"), peer)
    request: dict[str, Any] = {"domain": "publisher.example", "token": "tok-1"}
    if exchange is not None:
        request["exchange"] = exchange

    with pytest.raises(CallError) as caught:
        face.run(getattr(client, method)(request))

    assert caught.value.kind is CallErrorKind.NOT_SENT
    assert peer.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_request_the_service_could_only_refuse_is_not_sent(face: Face) -> None:
    peer = _peer({})
    client = _client(face, _config(base_url="https://admin.test"), peer)

    with pytest.raises(CallError) as caught:
        face.run(client.set_reporting_policy({"policy": {"required_fields": ["a", "a"]}}))

    assert caught.value.kind is CallErrorKind.MALFORMED
    assert peer.seen == []


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_unsigned_admin_call_goes_out_unsigned(face: Face) -> None:
    seen: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ver": "1.0", "rate": _FEE})

    transport = httpx.MockTransport(respond)
    config = _config(base_url="https://admin.test", signer=None)
    client = (
        AdminClient(config, http=httpx.AsyncClient(transport=transport))
        if face.name == "async"
        else sync_client.AdminClient(config, http=httpx.Client(transport=transport))
    )

    face.run(client.set_tenant_fee_rate({"rate": _FEE}))

    assert "signature" not in seen[0].headers
