"""SigningTransport under the Web Bot Auth profile: the per-request signer source, the
append mode and coverage of an earlier signature, and the five-minute window.

Each behavior is proved through the verifier a peer runs: a signature the transport
emits is checked by ``verify_multisig_request_server`` with a resolver that answers
only for the directory each key is published in, so a signature resolved through the
wrong member finds no key.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk.httpsig import sign_request
from fora_sdk.server_verify import verify_multisig_request_server
from fora_sdk.signing_transport import OutboundRequest, SigningTransport
from fora_sdk.thumbprint import thumbprint
from fora_sdk.wba import SignatureAgentNotOriginError, SignatureLifetimeError
from fora_sdk.window import monotonic_window

_URL = "https://exchange.example/fora.v1.ExchangeService/ExecuteTransaction"
_BODY = b'{"idempotency_key":"idem-1"}'
_CREATED = 1_700_000_000
_EXPIRES = _CREATED + 300
_AGENT_SEED = bytes(range(1, 33))
_BROKER_SEED = bytes(range(2, 34))
_AGENT_DIR = "https://agent.example"
_BROKER_DIR = "https://broker.example"


def _identity(seed: bytes) -> tuple[str, bytes]:
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return thumbprint(pub), pub


class _Directories:
    """A KeyResolver that answers only for the directory each key is published in."""

    def __init__(self, *published: tuple[str, bytes]) -> None:
        self._keys: dict[tuple[str, str], bytes] = {}
        for directory, seed in published:
            keyid, pub = _identity(seed)
            self._keys[(directory, keyid)] = pub

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        return self._keys.get((directory, str(keyid)))


def _verify(headers: dict[str, str], *published: tuple[str, bytes]) -> object:
    return verify_multisig_request_server(
        method="POST",
        url=_URL,
        body=_BODY,
        headers=headers,
        resolver=_Directories(*published),
        now=_CREATED + 10,
    )


def _transport(seed: bytes, directory: str, **kwargs: object) -> SigningTransport:
    keyid, _ = _identity(seed)
    return SigningTransport(
        signer_seed=seed,
        keyid=keyid,
        signature_agent=directory,
        window=lambda: (_CREATED, _EXPIRES),
        **kwargs,  # type: ignore[arg-type]
    )


def _send(transport: SigningTransport, headers: dict[str, str] | None = None) -> dict[str, str]:
    signed = transport.sign_outbound(
        method="POST", url=_URL, body=_BODY, authorization="", headers=headers
    )
    return signed.headers


# --- the per-request signer source ----------------------------------------------------


def test_a_signer_source_names_the_signer_per_request() -> None:
    asked: list[OutboundRequest] = []

    def source(request: OutboundRequest) -> tuple[bytes, str, str]:
        asked.append(request)
        keyid, _ = _identity(_AGENT_SEED)
        return _AGENT_SEED, keyid, _AGENT_DIR

    transport = SigningTransport(signer_source=source, window=lambda: (_CREATED, _EXPIRES))
    first, second = _send(transport), _send(transport)

    # Two identical requests in the same second: a fresh nonce each, distinct signatures,
    # both verifying in the source's directory.
    assert first["signature"] != second["signature"]
    for headers in (first, second):
        verdict = _verify(headers, (_AGENT_DIR, _AGENT_SEED))
        assert verdict.valid is True, verdict.reason  # type: ignore[attr-defined]
        assert verdict.directories == (_AGENT_DIR,)  # type: ignore[attr-defined]
    assert [(r.method, r.url, r.body) for r in asked] == [("POST", _URL, _BODY)] * 2


def test_a_failing_signer_source_signs_nothing() -> None:
    def source(_request: OutboundRequest) -> tuple[bytes, str, str]:
        raise LookupError("no identity for this caller")

    transport = SigningTransport(signer_source=source)
    with pytest.raises(LookupError):
        _send(transport)


def test_a_signer_source_naming_no_origin_signs_nothing() -> None:
    transport = SigningTransport(signer_source=lambda _r: (_AGENT_SEED, "k", "agent.example"))
    with pytest.raises(SignatureAgentNotOriginError):
        _send(transport)


def test_a_transport_needs_a_key_or_a_source() -> None:
    with pytest.raises(ValueError, match="signer_seed or a signer_source"):
        SigningTransport(keyid="k", signature_agent=_AGENT_DIR)


# --- append mode and coverage of an earlier signature ----------------------------------


def test_append_only_signs_a_fresh_request_as_sig1() -> None:
    nonce = "AAECAwQF"
    transport = _transport(_AGENT_SEED, _AGENT_DIR, append_only=True)
    transport._nonce = lambda: nonce
    headers = _send(transport)
    keyid, _ = _identity(_AGENT_SEED)
    fresh = sign_request(
        method="POST", url=_URL, body=_BODY, authorization="", signer_seed=_AGENT_SEED,
        keyid=keyid, created=_CREATED, expires=_EXPIRES, signature_agent=_AGENT_DIR,
        nonce=nonce,
    )  # fmt: skip
    assert headers["signature-input"] == fresh.signature_input
    assert headers["signature-agent"] == fresh.signature_agent


@pytest.mark.parametrize("append_only", [False, True])
def test_a_signed_request_gets_a_second_signature_beside_the_first(append_only: bool) -> None:
    agent = _send(_transport(_AGENT_SEED, _AGENT_DIR))
    relayed = _send(_transport(_BROKER_SEED, _BROKER_DIR, append_only=append_only), agent)

    assert relayed["signature-input"].startswith(agent["signature-input"] + ", sig2=(")
    assert relayed["signature"].startswith(agent["signature"] + ", sig2=:")
    assert relayed["signature-agent"] == f'sig1="{_AGENT_DIR}", sig2="{_BROKER_DIR}"'
    # Independent: the second signature covers only its own request and member.
    assert '"signature";key="sig1"' not in relayed["signature-input"]
    verdict = _verify(relayed, (_AGENT_DIR, _AGENT_SEED), (_BROKER_DIR, _BROKER_SEED))
    assert verdict.valid is True, verdict.reason  # type: ignore[attr-defined]
    assert verdict.directories == (_AGENT_DIR, _BROKER_DIR)  # type: ignore[attr-defined]


def test_cover_previous_covers_the_earlier_signature_completely() -> None:
    agent = _send(_transport(_AGENT_SEED, _AGENT_DIR))
    forwarded = _send(_transport(_BROKER_SEED, _BROKER_DIR, cover_previous=True), agent)

    sig2 = forwarded["signature-input"].split(", sig2=")[1]
    for component in (
        '"signature-agent";key="sig1"',
        '"signature";key="sig1"',
        '"signature-input";key="sig1"',
    ):
        assert component in sig2
    verdict = _verify(forwarded, (_AGENT_DIR, _AGENT_SEED), (_BROKER_DIR, _BROKER_SEED))
    assert verdict.valid is True, verdict.reason  # type: ignore[attr-defined]

    # Covered, so the earlier signature can no longer be swapped out from under it.
    tampered = dict(forwarded)
    tampered["signature"] = forwarded["signature"].replace(
        agent["signature"], _send(_transport(_AGENT_SEED, _AGENT_DIR))["signature"]
    )
    verdict = _verify(tampered, (_AGENT_DIR, _AGENT_SEED), (_BROKER_DIR, _BROKER_SEED))
    assert verdict.valid is False  # type: ignore[attr-defined]


# --- the window -------------------------------------------------------------------------


def test_a_window_longer_than_five_minutes_signs_nothing() -> None:
    keyid, _ = _identity(_AGENT_SEED)
    transport = SigningTransport(
        signer_seed=_AGENT_SEED,
        keyid=keyid,
        signature_agent=_AGENT_DIR,
        now=lambda: float(_CREATED),
        ttl_sec=600,
    )
    with pytest.raises(SignatureLifetimeError):
        _send(transport)


def test_the_monotonic_window_signs_at_the_clock_time() -> None:
    window = monotonic_window(lambda: float(_CREATED), 300)
    assert [window() for _ in range(3)] == [(_CREATED, _EXPIRES)] * 3
