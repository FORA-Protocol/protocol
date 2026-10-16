"""The pre-signing hook: ``ClientConfig.before_sign``.

A caller that needs to send a request the SDK would not build on its own (a test harness
probing how a server refuses a malformed message is the motivating case) gets ONE
supported seam: a callable that receives the stamped, validated request as an
``httpx.Request`` just before it is signed, and returns the request to sign instead. The
SDK still serializes once, signs exactly the bytes it sends and decodes the reply with its
own decoder, so the hook cannot become a way around signing or decoding.

Every case runs the real client, on both faces, against a peer that verifies the RFC 9421
signature with the SDK's own server-side verifier. That is what proves the signature
covers the PATCHED bytes rather than the ones the SDK first rendered.

The refusals are local and nothing is sent for any of them: a hook that raises, a hook
that moves the request to another method or URL (the address checks already ran against
the planned URL), and a hook that sets a header the signer itself emits.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from signed_peer import SignedPeer, envelope_response
from test_client import (
    _IDS,
    AGENT_SEED,
    FACES,
    Face,
    Recorder,
    _config,
    _signed_offer,
    _verifier,
)

import fora_sdk.sync as sync_client
from conftest import GO_CONNECT_TESTDATA, load_json
from fora_sdk.client import CallError, CallErrorKind, CatalogClient, ClientConfig
from fora_sdk.errordetail import reason
from fora_sdk.httpsig import content_digest
from fora_sdk.keyresolver import StaticKeyResolver

_KEYID = "agent.v1"
_AGENT_PUBLIC = Ed25519PrivateKey.from_private_bytes(AGENT_SEED).public_key().public_bytes_raw()
_PUSH_URL = "https://exchange.test/fora.v1.CatalogService/PushResources"
_DISCOVER_URL = "https://exchange.test/fora.v1.ExchangeService/DiscoverResources"
_REQUEST_ID = "req-before-sign-1"

#: The five header names the request signer emits. A hook may not set any of them, in
#: any letter case: the signer owns them, and a value the hook set would either be
#: overwritten silently or contradict the signature.
_SIGNER_HEADERS = ["Signature", "signature-input", "Content-Digest", "Signature-Agent",
                   "AUTHORIZATION"]

_CATALOG_REJECTION = next(
    v for v in load_json(GO_CONNECT_TESTDATA / "connect-error-vectors.json")["vectors"]
    if v["name"] == "catalog_rejection"
)


def _push() -> dict[str, Any]:
    return {
        "exchange": "exchange.test",
        "tenant_id": "tenant-1",
        "entries": [
            {
                "domain": "publisher.test",
                "path": "/x",
                "terms": [
                    {
                        "semantics": "TERM_SEMANTICS_ENUMERATED",
                        "pricing": {"model": "PRICING_MODEL_FREE", "rate": "0"},
                    }
                ],
            }
        ],
    }


def _agent_keys(_signature_agent: str) -> StaticKeyResolver:
    return StaticKeyResolver({_KEYID: _AGENT_PUBLIC})


def _hooked(hook: Any, **overrides: Any) -> ClientConfig:
    return _config(before_sign=hook, request_id=lambda: _REQUEST_ID, **overrides)


def _catalog(face: Face, config: ClientConfig, peer: Any) -> Any:
    if face.name == "async":
        return CatalogClient(config, http=peer.async_())
    return sync_client.CatalogClient(config, http=peer.sync())


def _rebuilt(request: httpx.Request, **changes: Any) -> httpx.Request:
    """The request a hook returns: the one it was handed, with ``changes`` applied.

    Built from the received headers verbatim, Content-Length included, which is what a
    caller rebuilding a request naturally does. A patched body therefore arrives here
    carrying the ORIGINAL length, and the SDK has to drop it.
    """
    return httpx.Request(
        changes.get("method", request.method),
        changes.get("url", request.url),
        headers=changes.get("headers", request.headers),
        content=changes.get("content", request.content),
    )


def _baseline_body(face: Face) -> bytes:
    """The body the SDK sends for :func:`_push` with no hook installed."""
    peer = SignedPeer(keys=_agent_keys)
    face.run(_catalog(face, _config(request_id=lambda: _REQUEST_ID), peer).push_resources(_push()))
    return peer.only().request.content


# ---------------------------------------------------------------------------
# What the hook is handed, and what is signed afterwards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_hook_receives_the_stamped_request_before_any_signature(face: Face) -> None:
    handed: list[httpx.Request] = []

    def hook(request: httpx.Request) -> httpx.Request:
        handed.append(request)
        return request

    peer = SignedPeer(keys=_agent_keys)
    face.run(_catalog(face, _hooked(hook), peer).push_resources(_push()))

    assert len(handed) == 1
    seen = handed[0]
    assert seen.method == "POST"
    assert seen.url == httpx.URL(_PUSH_URL)
    # Serialized once, envelope already stamped: the hook sees the exact bytes the SDK
    # would have sent without it.
    assert seen.content == _baseline_body(face)
    assert json.loads(seen.content)["ver"] == "1.0"
    assert seen.headers["content-type"] == "application/json"
    assert seen.headers["connect-protocol-version"] == "1"
    assert seen.headers["x-request-id"] == _REQUEST_ID
    # Called BEFORE signing, so none of the signer's headers exist yet.
    present = {name.lower() for name in seen.headers}
    assert present.isdisjoint({name.lower() for name in _SIGNER_HEADERS})


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_hook_returning_its_argument_sends_the_unaltered_request(face: Face) -> None:
    peer = SignedPeer(keys=_agent_keys)
    face.run(_catalog(face, _hooked(lambda request: request), peer).push_resources(_push()))

    got = peer.only()
    assert got.verdict.valid
    assert got.request.content == _baseline_body(face)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_patched_body_is_signed_over_the_patched_bytes_with_its_own_length(
    face: Face,
) -> None:
    patched_message = _push()
    patched_message["entries"][0]["title"] = "added after validation"
    patched = json.dumps(patched_message, separators=(",", ":")).encode()

    def hook(request: httpx.Request) -> httpx.Request:
        return _rebuilt(request, content=patched)

    peer = SignedPeer(keys=_agent_keys)
    response = face.run(_catalog(face, _hooked(hook), peer).push_resources(_push()))

    got = peer.only()
    assert got.request.content == patched
    # The signature verifies over the bytes that arrived, not the ones first rendered.
    assert got.verdict.valid, got.verdict.reason
    assert got.header("content-digest") == content_digest(patched)
    # The stale length the hook carried over is dropped, not sent.
    assert got.header("content-length") == str(len(patched))
    assert got.header("x-request-id") == _REQUEST_ID
    # The reply is decoded as usual.
    assert type(response).__name__ == "PushResourcesResponse"


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize(
    ("name", "value"),
    [("Host", "elsewhere.test"), ("Content-Length", "999")],
    ids=["host", "content-length"],
)
def test_a_transport_header_set_by_the_hook_never_reaches_the_peer(
    face: Face, name: str, value: str
) -> None:
    """Host and Content-Length are computed from the planned URL and the bytes sent.

    A hook that sets either is not refused: its value is dropped. A Host the hook chose
    would move the request to another virtual host behind the address the SDK checked,
    and the signature would still verify, because it covers the planned URL rather than
    the Host header. A Content-Length the hook chose would contradict the body.
    """
    def hook(request: httpx.Request) -> httpx.Request:
        headers = dict(request.headers)
        headers[name] = value
        return _rebuilt(request, headers=headers)

    peer = SignedPeer(keys=_agent_keys)
    face.run(_catalog(face, _hooked(hook), peer).push_resources(_push()))

    got = peer.only()
    assert got.verdict.valid, got.verdict.reason
    assert got.request.url == httpx.URL(_PUSH_URL)
    assert got.header("host") == "exchange.test"
    assert got.request.content == _baseline_body(face)
    assert got.header("content-length") == str(len(got.request.content))


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_patched_request_refused_by_the_peer_surfaces_the_typed_refusal(
    face: Face,
) -> None:
    """The lane's motivating case, end to end.

    A valid request passes local validation, the hook breaks one entry, the peer accepts
    the SIGNATURE over the patched bytes and refuses the CONTENT with a typed reason. The
    caller reads that refusal from CallError: the class, the status, the Connect code and
    the typed protocol reason.
    """
    def hook(request: httpx.Request) -> httpx.Request:
        message = json.loads(request.content)
        message["entries"][0]["path"] = "no-leading-slash"
        return _rebuilt(request, content=json.dumps(message).encode())

    def refuse_malformed_entries(request: httpx.Request) -> httpx.Response:
        entry = json.loads(request.content)["entries"][0]
        if not entry["path"].startswith("/"):
            return envelope_response(_CATALOG_REJECTION["http_status"],
                                     _CATALOG_REJECTION["envelope"])
        return httpx.Response(200, json={"ver": "1.0"})

    peer = SignedPeer(keys=_agent_keys, answer=refuse_malformed_entries)
    with pytest.raises(CallError) as caught:
        face.run(_catalog(face, _hooked(hook), peer).push_resources(_push()))

    assert peer.only().verdict.valid, "the peer must have refused the content, not the signature"
    failure = caught.value
    assert failure.kind is CallErrorKind.REFUSED
    assert failure.op == "push resources"
    assert failure.status == _CATALOG_REJECTION["http_status"]
    assert failure.reason == _CATALOG_REJECTION["code"]
    assert failure.code == _CATALOG_REJECTION["code"]
    assert failure.peer_message == _CATALOG_REJECTION["peer_message"]
    typed = reason(failure.detail)
    assert typed is not None
    assert typed.value == _CATALOG_REJECTION["expect"]["reason_enum"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_the_planned_url_compares_the_way_httpx_normalizes_it(face: Face) -> None:
    """``:443`` on an https origin is the same URL once httpx parses it.

    The hook hands back the request it received, whose URL httpx already normalized. A
    comparison against the raw planned string would refuse a hook that changed nothing.
    """
    rec = Recorder({"ver": "1.0"})
    config = _hooked(lambda request: request, base_url="https://exchange.test:443")
    face.run(_catalog(face, config, rec).push_resources(_push()))

    assert len(rec.seen) == 1
    assert rec.seen[0].url == httpx.URL(_PUSH_URL)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_without_a_signer_the_hook_may_set_authorization(face: Face) -> None:
    """With no signer configured nothing collides with a hook's header, so none is
    refused."""
    def hook(request: httpx.Request) -> httpx.Request:
        headers = dict(request.headers)
        headers["Authorization"] = "Bearer hook-token"
        return _rebuilt(request, headers=headers)

    rec = Recorder({"ver": "1.0"})
    face.run(_catalog(face, _hooked(hook, signer=None), rec).push_resources(_push()))

    assert len(rec.seen) == 1
    assert rec.seen[0].headers["authorization"] == "Bearer hook-token"
    assert "signature" not in rec.seen[0].headers


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_discovery_attribution_reads_the_callers_message_not_the_patched_one(
    face: Face,
) -> None:
    """A flat offer list is attributed to the query's only URI. That URI is the one the
    caller asked about, even when the hook rewrote the URIs on the wire."""
    offer, public = _signed_offer()

    def hook(request: httpx.Request) -> httpx.Request:
        message = json.loads(request.content)
        message["uris"] = ["https://site.test/rewritten"]
        return _rebuilt(request, content=json.dumps(message).encode())

    def flat_offers(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ver": "1.0", "exchange": "exchange.test",
                                         "offers": [offer]})

    peer = SignedPeer(keys=_agent_keys, answer=flat_offers)
    client = face.client(_hooked(hook, verifier=_verifier(public)), peer)
    result = face.run(client.discover({"exchange": "exchange.test",
                                       "uris": ["https://site.test/asked"]}))

    got = peer.only()
    assert got.verdict.valid, got.verdict.reason
    assert json.loads(got.request.content)["uris"] == ["https://site.test/rewritten"]
    assert got.request.url == httpx.URL(_DISCOVER_URL)
    assert [g.uri for g in result.groups] == ["https://site.test/asked"]
    assert len(result.groups[0].result.verified) == 1


# ---------------------------------------------------------------------------
# Refusals: each is MALFORMED, local, and sends nothing
# ---------------------------------------------------------------------------


def _assert_refused_unsent(face: Face, hook: Any) -> CallError:
    peer = SignedPeer(keys=_agent_keys)
    with pytest.raises(CallError) as caught:
        face.run(_catalog(face, _hooked(hook), peer).push_resources(_push()))
    assert caught.value.kind is CallErrorKind.MALFORMED
    assert caught.value.op == "push resources"
    assert caught.value.status is None
    assert peer.seen == [], "a refused hook result must never reach the wire"
    return caught.value


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("name", _SIGNER_HEADERS)
def test_a_hook_that_sets_a_signer_header_is_refused(face: Face, name: str) -> None:
    def hook(request: httpx.Request) -> httpx.Request:
        headers = dict(request.headers)
        headers[name] = "set-by-the-hook"
        return _rebuilt(request, headers=headers)

    _assert_refused_unsent(face, hook)


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize(
    "url",
    [
        "https://exchange.test/fora.v1.CatalogService/RemoveResources",
        "https://elsewhere.test/fora.v1.CatalogService/PushResources",
        "http://exchange.test/fora.v1.CatalogService/PushResources",
        "https://exchange.test:8443/fora.v1.CatalogService/PushResources",
        _PUSH_URL + "?extra=1",
    ],
    ids=["other-method", "other-host", "other-scheme", "other-port", "added-query"],
)
def test_a_hook_that_moves_the_request_to_another_url_is_refused(face: Face, url: str) -> None:
    _assert_refused_unsent(face, lambda request: _rebuilt(request, url=url))


@pytest.mark.parametrize("face", FACES, ids=_IDS)
@pytest.mark.parametrize("method", ["GET", "PUT"])
def test_a_hook_that_changes_the_method_is_refused(face: Face, method: str) -> None:
    _assert_refused_unsent(face, lambda request: _rebuilt(request, method=method))


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_hook_that_raises_is_refused_and_carries_the_cause(face: Face) -> None:
    boom = RuntimeError("the hook failed")

    def hook(_request: httpx.Request) -> httpx.Request:
        raise boom

    failure = _assert_refused_unsent(face, hook)
    assert failure.cause is boom or failure.__cause__ is boom
