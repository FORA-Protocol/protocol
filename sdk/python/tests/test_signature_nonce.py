"""SigningTransport stamps a fresh RFC 9421 nonce on every signature.

Ed25519 is deterministic and created/expires have one-second resolution, so
without the nonce two identical requests in the same second sign to the same
bytes and the replay store refuses the second one. These tests pin that the
nonce removes that collision and that replay protection still holds.
"""

from __future__ import annotations

import base64
import re

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fora_sdk.httpsig import sign_request, verify_request_server  # type: ignore[attr-defined]
from fora_sdk.keyresolver import StaticKeyResolver
from fora_sdk.signing_transport import SigningTransport

_SEED = bytes(range(1, 33))
_KEYID = "agent.test.v1"
_DIRECTORY = "https://agent.example"
_URL = "https://exchange.example/fora.v1.ExchangeService/DiscoverResources"
_BODY = b'{"ver":"1"}'
_CREATED, _EXPIRES = 1_700_000_000, 1_700_000_300
_NOW = _CREATED + 10
_NONCE = re.compile(r';nonce="([^"]*)"')


class _MemoryReplayStore:
    def __init__(self) -> None:
        self.seen: set[str] = set()

    def seen_nonce(self, nonce: str) -> bool:
        return nonce in self.seen

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:  # noqa: ARG002
        if nonce in self.seen:
            return True
        self.seen.add(nonce)
        return False


def _pub() -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(_SEED)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def _transport() -> SigningTransport:
    # A fixed window: created/expires are identical on every signature, the
    # collision condition.
    return SigningTransport(
        signer_seed=_SEED,
        keyid=_KEYID,
        signature_agent=_DIRECTORY,
        window=lambda: (_CREATED, _EXPIRES),
    )


def _sign(transport: SigningTransport | None = None) -> dict[str, str]:
    transport = transport or _transport()
    return transport.sign_outbound(method="POST", url=_URL, body=_BODY, authorization="").headers


class _Server:
    def __init__(self) -> None:
        self.store = _MemoryReplayStore()
        self.resolver = StaticKeyResolver({_KEYID: _pub()})

    def verify(self, headers: dict[str, str]) -> object:
        return verify_request_server(
            method="POST",
            url=_URL,
            body=_BODY,
            headers=headers,
            resolver=self.resolver,
            replay_store=self.store,
            now=_NOW,
            max_signature_age=_EXPIRES - _CREATED,
        )


def test_identical_requests_get_unique_signatures_and_both_pass() -> None:
    server = _Server()
    # One transport for both requests: a nonce made once per transport instead of
    # once per signature would make these two requests collide.
    transport = _transport()
    first, second = _sign(transport), _sign(transport)

    n1 = _NONCE.search(first["signature-input"])
    n2 = _NONCE.search(second["signature-input"])
    assert n1 and n2
    # 64 random bytes, 86 base64url characters: the length the Web Bot Auth test
    # vectors use, and the one widely deployed verifiers require.
    assert len(n1.group(1)) == 86
    assert len(base64.urlsafe_b64decode(n1.group(1) + "==")) == 64
    assert n1.group(1) != n2.group(1)
    assert first["signature"] != second["signature"]
    # Only the nonce differs: created/expires are unchanged.
    assert _NONCE.sub("", first["signature-input"]) == _NONCE.sub("", second["signature-input"])

    assert server.verify(first).valid is True  # type: ignore[attr-defined]
    assert server.verify(second).valid is True  # type: ignore[attr-defined]


def test_exact_replay_is_rejected() -> None:
    server = _Server()
    headers = _sign()
    assert server.verify(headers).valid is True  # type: ignore[attr-defined]
    verdict = server.verify(dict(headers))
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "replay"  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "edit",
    [
        lambda s: _NONCE.sub(';nonce="' + "A" * 86 + '"', s),
        lambda s: _NONCE.sub("", s),
    ],
    ids=["changed", "removed"],
)
def test_changed_or_removed_nonce_fails_verification(edit: object) -> None:
    headers = _sign()
    headers["signature-input"] = edit(headers["signature-input"])  # type: ignore[operator]
    verdict = _Server().verify(headers)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]


def test_a_signature_without_nonce_is_accepted() -> None:
    # WG-00 lets a signer omit the nonce; a FORA verifier accepts one without it.
    signed = sign_request(
        method="POST",
        url=_URL,
        body=_BODY,
        authorization="",
        signer_seed=_SEED,
        keyid=_KEYID,
        created=_CREATED,
        expires=_EXPIRES,
        signature_agent=_DIRECTORY,
    )
    assert "nonce" not in signed.signature_input
    headers = {
        "content-digest": signed.content_digest,
        "signature-input": signed.signature_input,
        "signature": signed.signature,
        "authorization": "",
        "signature-agent": signed.signature_agent,
    }
    assert _Server().verify(headers).valid is True  # type: ignore[attr-defined]


def test_rng_failure_raises_and_signs_nothing() -> None:
    transport = _transport()

    def broken() -> str:
        raise OSError("entropy source unavailable")

    transport._nonce = broken
    with pytest.raises(OSError):
        transport.sign_outbound(method="POST", url=_URL, body=_BODY, authorization="")


def test_empty_nonce_source_is_refused() -> None:
    transport = _transport()
    transport._nonce = lambda: ""
    with pytest.raises(ValueError, match="empty nonce"):
        transport.sign_outbound(method="POST", url=_URL, body=_BODY, authorization="")


@pytest.mark.parametrize("nonce", ['abc";expires=1', "a\\b", "a b", "abc=", "a+b/c", "\u00e9"])
def test_helper_rejects_nonce_outside_base64url(nonce: str) -> None:
    # A quote would end the quoted parameter early, and the SDKs would write
    # different bytes for the same input. Go and TS test the same cases.
    with pytest.raises(ValueError, match="base64url"):
        sign_request(
            method="POST",
            url=_URL,
            body=_BODY,
            authorization="",
            signer_seed=_SEED,
            keyid=_KEYID,
            created=_CREATED,
            expires=_EXPIRES,
            signature_agent=_DIRECTORY,
            nonce=nonce,
        )
