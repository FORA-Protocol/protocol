"""sdk/python outbound-sign face — TRANSPORT-NEUTRAL, the client analogue of the
Go RoundTripper sign face (sdk/go/core/transport.go).

``SigningTransport.sign_outbound`` assembles the Web Bot Auth headers for one outbound
request (RFC 9530 Content-Digest over the EXACT body bytes, the signer's Signature-Agent
member, Signature-Input and Signature) via the shipped L1 ``httpsig`` byte oracle; it
adds NO new crypto and performs NO IO. It is NOT an HTTP client binding: it imports no
httpx and wraps no transport — the consumer owns the actual transport and applies the
returned headers itself.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TypeAlias

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk._sigbase import joined_header
from fora_sdk.b64 import b64url_nopad
from fora_sdk.core import sign_offer_acceptance_jcs, sign_request_acceptance_jcs
from fora_sdk.httpsig import SignedRequest, append_signature, sign_request
from fora_sdk.pop import AgentBinding, sign_agent_binding
from fora_sdk.thumbprint import thumbprint
from fora_sdk.wba import MAX_SIGNATURE_LIFETIME
from fora_sdk.window import Window, clock_window

# Default freshness window (seconds) for the created/expires params when the caller does
# not inject one: the longest a Web Bot Auth request signature may live. A longer
# injected window is refused at signing.
_DEFAULT_TTL_SEC = MAX_SIGNATURE_LIFETIME

# Entropy per signature nonce: 64 bytes, 86 base64url characters. 64 bytes is the length
# the Web Bot Auth test vectors use, and widely deployed verifiers refuse any other.
_NONCE_BYTES = 64


def _new_nonce() -> str:
    """A fresh RFC 9421 nonce: 64 random bytes, base64url without padding.

    ``secrets`` reads the OS CSPRNG and raises when it cannot; the error
    propagates, so nothing is signed and nothing is sent without a nonce.
    """
    return b64url_nopad(secrets.token_bytes(_NONCE_BYTES))


@dataclass(frozen=True)
class OutboundRequest:
    """The request a :data:`SignerSource` is asked to name a signer for, before it is
    signed: the request line, the exact body and the headers it already carries."""

    method: str
    url: str
    body: bytes
    headers: Mapping[str, str] = field(default_factory=dict)


#: Resolves the signer for one request, for a service that signs as many identities —
#: an identity service signing as the calling agent, a console signing as the calling
#: publisher. Returns ``(signer_seed, keyid, signature_agent)``: the 32-byte Ed25519
#: seed, the RFC 9421 keyid, and the signer's key-directory origin. The Python peer of
#: Go ``core.SignerSource``. An exception it raises means nothing is signed or sent.
SignerSource: TypeAlias = Callable[[OutboundRequest], tuple[bytes, str, str]]


@dataclass(frozen=True)
class SignedOutbound:
    """The signed outbound request: the RFC 9421 headers to attach to the send."""

    method: str
    url: str
    body: bytes
    headers: dict[str, str]


class SigningTransport:
    """Signs outbound requests via the core sign seam (RFC 9421 over exact body bytes).

    The signer is either fixed — ``signer_seed``, ``keyid`` and ``signature_agent`` — or
    resolved per request by ``signer_source``, which overrides the fixed one. The clock
    is injectable for determinism. ``sign_outbound`` returns the request plus EVERY
    covered header at the value that entered the signature base: Content-Digest,
    Signature-Agent, Signature-Input, Signature and an Authorization whose value may be
    empty.
    """

    def __init__(
        self,
        *,
        signer_seed: bytes | None = None,
        keyid: str = "",
        now: Callable[[], float] | None = None,
        ttl_sec: int = _DEFAULT_TTL_SEC,
        signature_agent: str = "",
        window: Window | None = None,
        signer_source: SignerSource | None = None,
        append_only: bool = False,
        cover_previous: bool = False,
    ) -> None:
        """Build a signing transport.

        ``signature_agent`` is the signer's key-directory origin, such as
        ``"https://agent.example"``, written as the Signature-Agent member every
        signature covers. It is required unless ``signer_source`` supplies it per
        request: signing with none raises
        :class:`~fora_sdk.wba.SignatureAgentRequiredError`, and a value that is not an
        https origin :class:`~fora_sdk.wba.SignatureAgentNotOriginError`, before
        anything is sent.

        ``append_only`` routes every request through ``append_signature`` (Go
        ``WithAppendSigner``, TS ``appendOnly``): a fresh request gets ``sig1``, and a
        request already carrying signatures gets one more, with its own label and
        member, the earlier ones untouched. Without it, a request whose headers carry a
        Signature is appended to and any other is signed fresh. ``cover_previous``
        makes an appended signature cover the last earlier one completely (Go
        ``WithCoverPrevious``), as WG-00 §5.2.2 permits a party forwarding a request
        unchanged; a party that changed the request must not set it.
        """
        if signer_seed is None and signer_source is None:
            raise ValueError("signing transport needs a signer_seed or a signer_source")
        self._signer_seed = signer_seed
        self._keyid = keyid
        self._now = now or time.time
        self._ttl_sec = ttl_sec
        self._signature_agent = signature_agent
        self._source = signer_source
        self._append_only = append_only
        self._cover_previous = cover_previous
        # Source (created, expires) from an injected Window, defaulting to a
        # clock_window over now/ttl_sec. clock_window int()-truncates to whole seconds.
        self._window = window or clock_window(self._now, self._ttl_sec)
        # Nonce source for each signature. Tests replace it to get deterministic bytes.
        # sign_outbound refuses an empty nonce.
        self._nonce: Callable[[], str] = _new_nonce

    @property
    def signature_agent(self) -> str:
        """The key-directory origin this transport signs as — the Signature-Agent member
        origin, possibly empty when a ``signer_source`` names it per request. Read-only:
        a relayed purchase checks that ``requester.domain`` names this directory's host,
        because a Broker refuses a request whose requester is not the directory its
        signature resolved from."""
        return self._signature_agent

    def _fixed_seed(self) -> bytes:
        if self._signer_seed is None:
            raise ValueError(
                "signing transport has no fixed key: its signer_source names one per request"
            )
        return self._signer_seed

    @property
    def thumbprint(self) -> str:
        """The RFC 7638 thumbprint of the key this transport signs with: the agent identity
        a delivery URL is bound to (``agent_id``) and an Exchange states as
        ``agent_identity_hash``. Derived from the key itself, never from ``keyid``, which
        is whatever label the caller chose."""
        public = Ed25519PrivateKey.from_private_bytes(self._fixed_seed()).public_key()
        return thumbprint(public.public_bytes_raw())

    def sign_offer_acceptance(
        self,
        *,
        offer_sig: str,
        requester_id: str,
        requester_domain: str,
        idempotency_key: str,
    ) -> tuple[str, str]:
        """Sign the detached acceptance a purchase carries; return ``(hex_signature, alg)``.

        It signs with the REQUEST signer's key, and there is deliberately no option for a
        separate acceptance key. The protocol carries one agent identity:
        ``agent_identity_hash`` is defined as the thumbprint of the agent's request-signing
        key, an Exchange verifies the detached acceptance against the key registered for
        the caller its request signature identified, and the delivery URL is bound to that
        same thumbprint. A second key would be refused at execute, and any URL it did
        produce could never be fetched — the presented key would not match the binding.

        It lives on the transport so the key stays in one place: the client composes this
        seam and never handles key material, which is the shape the Go oracle has, where
        the acceptance is signed by passing the injected Signer itself.
        """
        return sign_offer_acceptance_jcs(
            seed=self._fixed_seed(),
            offer_sig=offer_sig,
            requester_id=requester_id,
            requester_domain=requester_domain,
            idempotency_key=idempotency_key,
        )

    def sign_request_acceptance(
        self,
        *,
        items: list[tuple[str, str]],
        requester_id: str,
        requester_domain: str,
        idempotency_key: str,
    ) -> tuple[str, str]:
        """Sign the complete ordered execute set with the request-signing key."""
        return sign_request_acceptance_jcs(
            seed=self._fixed_seed(),
            items=items,
            requester_id=requester_id,
            requester_domain=requester_domain,
            idempotency_key=idempotency_key,
        )

    def sign_agent_binding(self, *, url: str, window: Window) -> AgentBinding:
        """Mint the proof of possession for one bound delivery GET: the agent key,
        Signature-Agent, Signature-Input and Signature headers.

        The SAME key as the request signer, for the same reason as
        :meth:`sign_offer_acceptance`: the delivery URL is bound to the thumbprint of the
        agent's request-signing key, so a proof minted under any other key presents an
        identity the URL was not issued to. It names this transport's directory and
        carries a fresh 64-byte nonce, as every request signature does.
        """
        created, expires = window()
        nonce = self._fresh_nonce()
        return sign_agent_binding(
            url=url,
            signer_seed=self._fixed_seed(),
            created=created,
            expires=expires,
            signature_agent=self._signature_agent,
            nonce=nonce,
        )

    def _fresh_nonce(self) -> str:
        nonce = self._nonce()
        if not nonce:
            # A missing nonce brings back the same-second collision: never sign without one.
            raise ValueError("signing transport: nonce source returned an empty nonce")
        return nonce

    def _identity_for(self, request: OutboundRequest) -> tuple[bytes, str, str]:
        """The signer and directory for ``request``: the source's when one is configured,
        the transport's own otherwise."""
        if self._source is None:
            return self._fixed_seed(), self._keyid, self._signature_agent
        return self._source(request)

    def sign_outbound(
        self,
        *,
        method: str,
        url: str,
        body: bytes,
        authorization: str,
        window: Window | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> SignedOutbound:
        """Sign an outbound request; return it with the RFC 9421 headers attached.

        Authorization is always bound — pass an empty string when the caller holds no
        token, which BINDS that emptiness. The header is still emitted and still sent; an
        absent header is a different thing entirely and a verifier refuses it.

        ``headers`` are the headers the request already carries. When they include a
        Signature, or when the transport is ``append_only``, the new signature is
        appended beside the earlier ones (their Signature-Input, Signature and
        Signature-Agent members kept as they are) and the returned values are the whole
        merged headers; otherwise the request is signed fresh as ``sig1``.

        ``window`` overrides the one this transport was built with. It must be ONE
        INSTANCE held by the caller rather than a fresh one per call: a monotonic window
        carries the running maximum, and one built per request has none.

        Every call signs with a fresh 64-byte nonce, so two identical requests in the
        same second still produce different signatures and a replay store accepts both.
        Resending the returned headers unchanged is still a replay. A profile refusal (no
        or a non-origin directory, a window longer than five minutes) raises a
        :class:`~fora_sdk.wba.SignatureProfileError` and nothing is signed.
        """
        carried = dict(headers or {})
        seed, keyid, directory = self._identity_for(
            OutboundRequest(method=method, url=url, body=body, headers=carried)
        )
        created, expires = (window or self._window)()
        nonce = self._fresh_nonce()
        signed: SignedRequest
        if self._append_only or joined_header(carried, "signature"):
            signed = append_signature(
                method=method,
                url=url,
                body=body,
                authorization=authorization,
                signer_seed=seed,
                keyid=keyid,
                created=created,
                expires=expires,
                signature_agent=directory,
                prev_signature_input=joined_header(carried, "signature-input") or "",
                prev_signature=joined_header(carried, "signature") or "",
                prev_signature_agent=joined_header(carried, "signature-agent") or "",
                nonce=nonce,
                cover_previous=self._cover_previous,
            )
        else:
            signed = sign_request(
                method=method,
                url=url,
                body=body,
                authorization=authorization,
                signer_seed=seed,
                keyid=keyid,
                created=created,
                expires=expires,
                signature_agent=directory,
                nonce=nonce,
            )
        # EVERY covered header, at exactly the value that entered the signature base —
        # empty values included. See docs/design-history.md, "A covered header the peer
        # never receives is not bound". Taken straight off ``signed``, never re-read from
        # the arguments, so the emitted value and the bound one cannot drift.
        return SignedOutbound(
            method=method,
            url=url,
            body=body,
            headers={
                "content-digest": signed.content_digest,
                "signature-input": signed.signature_input,
                "signature": signed.signature,
                "authorization": signed.authorization,
                "signature-agent": signed.signature_agent,
            },
        )
