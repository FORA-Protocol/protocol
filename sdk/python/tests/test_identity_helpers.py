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
in-process origin, signed by the keys it lists as the Web Bot Auth profile requires
(the harness signs it with ``sign_directory_response``), and parsed by
``WBAKeyResolver``. A request signed through the client with the transport the third
helper built reaches a peer that resolves the caller's key in the directory the
signature's covered Signature-Agent member names, the way an Exchange does, and
verifies the signature with ``verify_request_server``.
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resolvers_harness import Origin, loopback_client, register_directory_key
from signed_peer import SignedPeer
from test_client import _IDS, FACES, Face

import fora_sdk
from fora_sdk.b64 import b64url_nopad
from fora_sdk.client import CallError, CallErrorKind, ClientConfig
from fora_sdk.resolvers import (
    DirectoryUnavailableError,
    ResolverError,
    UnknownKeyError,
    WBAKeyResolver,
)
from fora_sdk.signing_transport import SigningTransport
from fora_sdk.thumbprint import thumbprint

if TYPE_CHECKING:
    from collections.abc import Iterator

_JWK_MEMBERS = {"kty", "crv", "alg", "use", "x", "not_before", "not_after"}


@pytest.fixture
def origin() -> Iterator[Origin]:
    served = Origin(tls=True)
    yield served
    served.close()


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def _resolver() -> WBAKeyResolver:
    # The real clock: the window directory_document chooses must contain "now".
    return WBAKeyResolver(http=loopback_client())


class _DirectoryKeys:
    """The KeyResolver an Exchange wires: each keyid resolved in the directory the
    signature's covered Signature-Agent member names. A key the directory does not hold
    resolves to nothing, which the verifier reports as a signature failure."""

    def __init__(self, wba: WBAKeyResolver) -> None:
        self._wba = wba

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        try:
            return self._wba.resolve(keyid or "", directory)
        except ResolverError:
            return None


def _exchange_peer() -> SignedPeer:
    keys = _DirectoryKeys(_resolver())
    return SignedPeer(keys=lambda _agent: keys)


def _minted() -> tuple[Ed25519PrivateKey, str]:
    """A fresh identity whose key signs the served directory that lists it."""
    key, keyid = fora_sdk.generate_key()
    register_directory_key(key)
    return key, keyid


def _discover_as(face: Face, signer: SigningTransport, peer: SignedPeer) -> None:
    config = ClientConfig(base_url="https://exchange.test", signer=signer)
    # A query names its requester; on a direct request that is the host of the
    # directory the request is signed as.
    domain = urllib.parse.urlsplit(signer.signature_agent).netloc
    requester = {"id": "agent", "domain": domain, "type": "REQUESTER_TYPE_AGENT"}
    face.run(face.client(config, peer).discover({"exchange": "exchange.test", "requester": requester}))


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
        assert (jwk["kty"], jwk["crv"], jwk["alg"], jwk["use"]) == (
            "OKP",
            "Ed25519",
            "EdDSA",
            "sig",
        )
        not_before = datetime.fromisoformat(jwk["not_before"])
        not_after = datetime.fromisoformat(jwk["not_after"])
        assert not_before.tzinfo is not None
        assert not_after.tzinfo is not None
        assert not_before <= now < not_after


def test_the_sdk_resolver_reads_every_key_of_a_served_document(origin: Origin) -> None:
    first, first_id = _minted()
    second, second_id = _minted()
    origin.set_wba(
        json.dumps(fora_sdk.directory_document([first.public_key(), second.public_key()]))
    )
    resolver = _resolver()

    assert resolver.resolve(first_id, origin.origin) == _raw(first)
    assert resolver.resolve(second_id, origin.origin) == _raw(second)


def test_a_key_outside_the_served_document_does_not_resolve(origin: Origin) -> None:
    listed, _ = _minted()
    _, unlisted_id = _minted()
    origin.set_wba(json.dumps(fora_sdk.directory_document([listed.public_key()])))

    with pytest.raises(UnknownKeyError):
        _resolver().resolve(unlisted_id, origin.origin)


def test_a_listed_key_that_did_not_sign_the_directory_does_not_resolve(origin: Origin) -> None:
    # Both listed, only one signed the response: the resolver hands out only that one,
    # and a directory nobody signed is a directory it cannot use at all.
    signer, signer_id = _minted()
    unsigned, unsigned_id = fora_sdk.generate_key()
    origin.set_wba(
        json.dumps(fora_sdk.directory_document([signer.public_key(), unsigned.public_key()]))
    )
    resolver = _resolver()

    assert resolver.resolve(signer_id, origin.origin) == _raw(signer)
    with pytest.raises(UnknownKeyError):
        resolver.resolve(unsigned_id, origin.origin)

    origin.set_wba(json.dumps(fora_sdk.directory_document([unsigned.public_key()])))
    with pytest.raises(DirectoryUnavailableError):
        _resolver().resolve(unsigned_id, origin.origin)


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
    assert signed.headers["signature-agent"] == f'sig1="{directory}"'
    assert f'keyid="{keyid}"' in signed.headers["signature-input"]


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_a_fresh_identity_is_accepted_by_a_verifier_reading_its_directory(
    face: Face, origin: Origin
) -> None:
    key, keyid = _minted()
    origin.set_wba(json.dumps(fora_sdk.directory_document([key.public_key()])))
    peer = _exchange_peer()

    _discover_as(face, fora_sdk.signing_transport_for(key, origin.origin), peer)

    got = peer.only()
    assert got.verdict.valid, got.verdict.reason
    assert got.verdict.signature_agent == origin.origin
    assert got.header("signature-agent") == f'sig1="{origin.origin}"'
    assert f'keyid="{keyid}"' in (got.header("signature-input") or "")


@pytest.mark.parametrize("face", FACES, ids=_IDS)
def test_an_identity_its_directory_does_not_list_is_refused(face: Face, origin: Origin) -> None:
    """Signing with one fresh key while the served directory lists another: the peer
    resolves no key, the verifier refuses the signature, and the client reports the
    peer's refusal."""
    listed, _ = _minted()
    impostor, _ = _minted()
    origin.set_wba(json.dumps(fora_sdk.directory_document([listed.public_key()])))
    peer = _exchange_peer()

    with pytest.raises(CallError) as caught:
        _discover_as(face, fora_sdk.signing_transport_for(impostor, origin.origin), peer)

    got = peer.only()
    assert not got.verdict.valid
    assert got.verdict.reason == "signature"
    assert caught.value.kind is CallErrorKind.REFUSED
    assert caught.value.status == 401
    assert caught.value.reason == "unauthenticated"
