"""Identity helpers: mint an agent identity a verifier can resolve, with no hand assembly.

Three public helpers, each closing one step a caller otherwise writes by hand:

- ``generate_key()`` returns a fresh Ed25519 key and its RFC 7638 thumbprint, which is
  the keyid every FORA signature names;
- ``directory_document(keys)`` returns the Web Bot Auth key-directory JSON for a key set,
  in the schema the SDK's own WBA resolver reads, each key carrying the validity window
  the resolver requires before it will hand the key out;
- ``signing_transport_for(key, directory)`` returns a ``SigningTransport`` that signs as
  that identity: the keyid is the key's thumbprint and Signature-Agent is the directory.

The proof is the verify path, end to end. The directory document is served by a real
in-process origin and parsed by ``WBAKeyResolver``. A request signed through the client
with the transport the third helper built reaches a peer that resolves the caller's key
from the covered Signature-Agent header, the way an Exchange does, and verifies the
signature with ``verify_request_server``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resolvers_harness import Origin, loopback_client
from signed_peer import SignedPeer
from test_client import _IDS, FACES, Face

import fora_sdk
from fora_sdk.b64 import b64url_nopad
from fora_sdk.client import CallError, CallErrorKind, ClientConfig
from fora_sdk.resolvers import ResolverError, UnknownKeyError, WBAKeyResolver
from fora_sdk.signing_transport import SigningTransport
from fora_sdk.thumbprint import thumbprint

if TYPE_CHECKING:
    from collections.abc import Iterator

_JWK_MEMBERS = {"kty", "crv", "alg", "use", "x", "not_before", "not_after"}


@pytest.fixture
def origin() -> Iterator[Origin]:
    served = Origin()
    yield served
    served.close()


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def _resolver() -> WBAKeyResolver:
    # The real clock: the window directory_document chooses must contain "now".
    return WBAKeyResolver(http=loopback_client(), scheme="http")


class _DirectoryKeys:
    """The KeyResolver an Exchange builds per request: the keyid resolved against the
    directory the covered Signature-Agent header names. A key the directory does not
    hold resolves to nothing, which the verifier reports as a signature failure."""

    def __init__(self, wba: WBAKeyResolver, signature_agent: str) -> None:
        self._wba = wba
        self._directory = signature_agent.strip('"')

    def resolve(self, keyid: str | None) -> bytes | None:
        try:
            return self._wba.resolve(keyid or "", self._directory)
        except ResolverError:
            return None


def _exchange_peer() -> SignedPeer:
    wba = _resolver()
    return SignedPeer(keys=lambda agent: _DirectoryKeys(wba, agent))


def _discover_as(face: Face, signer: SigningTransport, peer: SignedPeer) -> None:
    config = ClientConfig(base_url="https://exchange.test", signer=signer)
    face.run(face.client(config, peer).discover({"exchange": "exchange.test"}))


# ---------------------------------------------------------------------------
# generate_key
# ---------------------------------------------------------------------------


def test_generate_key_returns_a_fresh_key_and_its_thumbprint() -> None:
    key, keyid = fora_sdk.generate_key()
    other, other_keyid = fora_sdk.generate_key()

    assert isinstance(key, Ed25519PrivateKey)
    assert keyid == thumbprint(_raw(key))
    assert _raw(other) != _raw(key)
    assert other_keyid != keyid


# ---------------------------------------------------------------------------
# directory_document
# ---------------------------------------------------------------------------


def test_directory_document_carries_each_key_with_its_validity_window() -> None:
    first, _ = fora_sdk.generate_key()
    second, _ = fora_sdk.generate_key()
    now = datetime.now(UTC)

    document = fora_sdk.directory_document([first.public_key(), second.public_key()])

    assert set(document) == {"keys"}
    assert [jwk["x"] for jwk in document["keys"]] == [
        b64url_nopad(_raw(first)),
        b64url_nopad(_raw(second)),
    ]
    for jwk in document["keys"]:
        assert set(jwk) == _JWK_MEMBERS
        assert (jwk["kty"], jwk["crv"], jwk["alg"], jwk["use"]) == ("OKP", "Ed25519", "EdDSA",
                                                                    "sig")
        not_before = datetime.fromisoformat(jwk["not_before"])
        not_after = datetime.fromisoformat(jwk["not_after"])
        assert not_before.tzinfo is not None
        assert not_after.tzinfo is not None
        assert not_before <= now < not_after


def test_the_sdk_resolver_reads_every_key_of_a_served_document(origin: Origin) -> None:
    first, first_id = fora_sdk.generate_key()
    second, second_id = fora_sdk.generate_key()
    origin.set_wba(json.dumps(fora_sdk.directory_document([first.public_key(),
                                                           second.public_key()])))
    resolver = _resolver()

    assert resolver.resolve(first_id, origin.url) == _raw(first)
    assert resolver.resolve(second_id, origin.url) == _raw(second)


def test_a_key_outside_the_served_document_does_not_resolve(origin: Origin) -> None:
    listed, _ = fora_sdk.generate_key()
    _, unlisted_id = fora_sdk.generate_key()
    origin.set_wba(json.dumps(fora_sdk.directory_document([listed.public_key()])))

    with pytest.raises(UnknownKeyError):
        _resolver().resolve(unlisted_id, origin.url)


# ---------------------------------------------------------------------------
# signing_transport_for, through the client and the verifier
# ---------------------------------------------------------------------------


def test_signing_transport_for_signs_as_the_identity() -> None:
    key, keyid = fora_sdk.generate_key()
    directory = "https://agent.example"

    transport = fora_sdk.signing_transport_for(key, directory)

    assert isinstance(transport, SigningTransport)
    signed = transport.sign_outbound(
        method="POST", url="https://exchange.test/x", body=b"{}", authorization=""
    )
    assert signed.headers["signature-agent"] == directory
    assert f'keyid="{keyid}"' in signed.headers["signature-input"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_fresh_identity_is_accepted_by_a_verifier_reading_its_directory(
    face: Face, origin: Origin
) -> None:
    key, keyid = fora_sdk.generate_key()
    origin.set_wba(json.dumps(fora_sdk.directory_document([key.public_key()])))
    peer = _exchange_peer()

    _discover_as(face, fora_sdk.signing_transport_for(key, origin.url), peer)

    got = peer.only()
    assert got.verdict.valid, got.verdict.reason
    assert got.header("signature-agent") == origin.url
    assert f'keyid="{keyid}"' in (got.header("signature-input") or "")


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_identity_its_directory_does_not_list_is_refused(face: Face, origin: Origin) -> None:
    """Signing with one fresh key while the served directory lists another: the peer
    resolves no key, the verifier refuses the signature, and the client reports the
    peer's refusal."""
    listed, _ = fora_sdk.generate_key()
    impostor, _ = fora_sdk.generate_key()
    origin.set_wba(json.dumps(fora_sdk.directory_document([listed.public_key()])))
    peer = _exchange_peer()

    with pytest.raises(CallError) as caught:
        _discover_as(face, fora_sdk.signing_transport_for(impostor, origin.url), peer)

    got = peer.only()
    assert not got.verdict.valid
    assert got.verdict.reason == "signature"
    assert caught.value.kind is CallErrorKind.REFUSED
    assert caught.value.status == 401
    assert caught.value.reason == "unauthenticated"
