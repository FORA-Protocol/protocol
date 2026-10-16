"""Framework-agnostic RFC 9421 SERVER-verify faces (ADR-020 §4).

The Python sibling of sdk/go/connectserver's verify path. Where
``httpsig.verify_request`` is the pure primitive (an already-resolved key, explicit
header values), these are the SERVER entries a Broker/Exchange built in Python wires
behind its framework (ASGI). Each (a) reads Signature-Input / Signature off the request
headers, (b) applies the Web Bot Auth profile and the FORA RPC covered set, (c) resolves
every keyid through an INJECTED :class:`~fora_sdk.keyresolver.KeyResolver` in the key
directory that signature's own covered Signature-Agent member names (the SDK owns no
keys), (d) reads time through an INJECTED clock, and (e) returns a VERDICT carrying the
reject reason of the Go connectserver taxonomy (classify.go ``RejectReason.String()``)
— never a thrown exception at the SDK boundary. The single-signature face also runs the
two-phase replay check over an INJECTED store (the SDK owns no replay state).

A verdict refusing a request for a missing component, a wrong tag, a Signature-Agent
form the profile refuses, or no signature at all carries ``accept_signature``: the
Accept-Signature value to answer the 401 with (WG-00 §5.3).
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from ._sigbase import SignatureCheckError
from ._sigverify import Request, verify_all, verify_first
from .httpsig import VerifiedRequest
from .wba import SignatureProfileError, accept_signature_for

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._sigverify import Resolve
    from .keyresolver import KeyResolver

# RejectReason — the classified verify-gate reject vocabulary, mirroring the Go
# connectserver taxonomy (classify.go RejectReason.String()). The tokens are stable
# audit values a consumer's log / dashboards key on; do not rename them. The
# single-sig face (verify_request_server) emits "signature"/"replay"; the multisig
# face (verify_multisig_request_server) emits "hop_budget"/"broken_chain"/
# "signature". TS splits the same vocabulary by face (RejectReason /
# MultisigRejectReason); Python mirrors Go's single four-token domain.
RejectReason = Literal["signature", "replay", "broken_chain", "hop_budget"]

_REASON_SIGNATURE: RejectReason = "signature"
_REASON_REPLAY: RejectReason = "replay"
_REASON_HOP_BUDGET: RejectReason = "hop_budget"
_REASON_BROKEN_CHAIN: RejectReason = "broken_chain"

# Default replay TTL, mirroring connectserver WithReplayTTL(5m). The injected
# store may ignore it; it is passed through unchanged.
_DEFAULT_REPLAY_TTL_SEC = 300


@runtime_checkable
class ReplayStore(Protocol):
    """Injected replay-nonce store (mirrors Go core.ReplayStore).

    The SDK ships NO default store — replay state lives entirely in the injected
    implementation. ``seen_nonce`` is the read-only first phase; ``seen_or_add``
    is the commit phase (returns True if the nonce was already present).
    """

    def seen_nonce(self, nonce: str) -> bool:
        """Return True if ``nonce`` was already recorded (read-only)."""
        ...

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:
        """Record ``nonce`` (TTL ``ttl_seconds``); return True if already present."""
        ...


def _resolve_through(resolver: KeyResolver) -> Resolve:
    """Adapt the injected resolver to the core's lookup: each signature's key is asked
    for in the directory THAT signature names."""
    return lambda directory, keyid: resolver.resolve(keyid, directory)


def _replay_nonce(keyid: str, signature: bytes) -> str:
    """The replay-store key: keyid + NUL + std-base64(signature bytes).

    Mirrors connectserver.replayNonce. The bytes are the parsed ones, re-encoded
    canonically, so the key does not depend on incidental wire whitespace.
    """
    return keyid + "\x00" + base64.b64encode(signature).decode()


def verify_request_server(
    *,
    method: str,
    url: str,
    body: bytes,
    headers: Mapping[str, str],
    resolver: KeyResolver,
    replay_store: ReplayStore | None = None,
    now: int,
    replay_ttl_seconds: int = _DEFAULT_REPLAY_TTL_SEC,
    max_signature_age: int = 0,
) -> VerifiedRequest:
    """Verify an inbound FORA request's first signature; return a reason-tagged verdict.

    ``headers`` carries at least ``signature-input``, ``signature``,
    ``content-digest``, ``authorization`` and ``signature-agent``. Lowercased keys are
    the convention, but every name is matched case-insensitively and repeated spellings
    of one name are JOINED with ", " before the base is rebuilt — the wire has one field
    per name however a mapping spells it, and the oracle reads it that way. A covered
    header the request does not carry at all is refused.

    The first signature in header order is verified, as Go ``VerifyRequestResolved``
    does; the others still count toward the rule that the legacy String Signature-Agent
    is accepted only on a request carrying one signature. Its keyid resolves ONLY
    through ``resolver``, in the directory its covered Signature-Agent member names;
    replay state lives ONLY in ``replay_store`` when supplied (omit it to disable replay
    detection); time is ``now`` (unix seconds). ``max_signature_age`` (seconds) clamps
    the declared lifetime (``expires - created``); 0 / omitted means unbounded,
    inclusive at the bound.

    The verdict's reason is ``"signature"`` (every authenticity, freshness, key,
    covered-set, form and lifetime failure) or ``"replay"``. A valid verdict carries
    the signer's directory in ``signature_agent``.
    """
    request = Request(method=method, url=url, body=body, headers=headers)
    try:
        verified = verify_first(
            request, _resolve_through(resolver), now=now, max_signature_age=max_signature_age
        )
    except (SignatureCheckError, SignatureProfileError) as exc:
        return VerifiedRequest(
            valid=False, reason=_REASON_SIGNATURE, accept_signature=accept_signature_for(exc)
        )
    if replay_store is not None:
        nonce = _replay_nonce(verified.keyid, verified.signature)
        # Two-phase (read-only seen, then seen_or_add) mirrors connectserver.verify so a
        # part-way rejection never burns the nonce.
        if replay_store.seen_nonce(nonce) or replay_store.seen_or_add(nonce, replay_ttl_seconds):
            return VerifiedRequest(valid=False, reason=_REASON_REPLAY)
    return VerifiedRequest(valid=True, signature_agent=verified.signature_agent)


@dataclass(frozen=True)
class MultisigVerdict:
    """The multi-signature verify verdict, never raised — always returned.

    Valid: the verified keyids and the key directory each one was resolved in, both in
    header order. Invalid: the classified reason, and ``accept_signature`` when the
    refusal is one the profile answers with Accept-Signature.
    """

    valid: bool
    reason: RejectReason | None = None
    keyids: tuple[str, ...] = ()
    directories: tuple[str, ...] = ()
    accept_signature: str | None = None


def verify_multisig_request_server(
    *,
    method: str,
    url: str,
    body: bytes,
    headers: Mapping[str, str],
    resolver: KeyResolver,
    now: int,
    max_signatures: int = 0,
    max_signature_age: int = 0,
) -> MultisigVerdict:
    """Verify EVERY signature on an inbound FORA request; return a reason-tagged verdict.

    The hop budget comes FIRST (``hop_budget``; every signature counts, 0 / omitted
    means unbounded; an Exchange passes the ``max_intermediary_hops`` it publishes,
    whose refusal the protocol answers with ``resource_exhausted``, HTTP 429), then
    the completeness of every coverage of an earlier signature
    (``broken_chain``: a signature covering ``"signature";key=X`` must cover
    ``"signature-input";key=X`` and every component X lists, and X must appear earlier),
    then each signature on its own (``signature``) — the precedence of Go
    ``VerifyMultisigRequest``. Each keyid resolves ONLY through ``resolver``, in the
    directory that signature's own covered Signature-Agent member names; a signature
    covering several members follows the one keyed to its label. Labels carry no
    meaning. ``max_signature_age`` clamps each signature's lifetime as in
    :func:`verify_request_server`. No replay check: the Go helpers oracle performs none.

    ``headers`` is read as for :func:`verify_request_server`.
    """
    request = Request(method=method, url=url, body=body, headers=headers)
    try:
        verified = verify_all(
            request,
            _resolve_through(resolver),
            now=now,
            max_signatures=max_signatures,
            max_signature_age=max_signature_age,
        )
    except SignatureCheckError as exc:
        if exc.reason == _REASON_HOP_BUDGET:
            return MultisigVerdict(False, _REASON_HOP_BUDGET)
        if exc.reason == _REASON_BROKEN_CHAIN:
            return MultisigVerdict(False, _REASON_BROKEN_CHAIN)
        return MultisigVerdict(False, _REASON_SIGNATURE, accept_signature=accept_signature_for(exc))
    except SignatureProfileError as exc:
        return MultisigVerdict(False, _REASON_SIGNATURE, accept_signature=accept_signature_for(exc))
    return MultisigVerdict(
        True,
        None,
        tuple(v.keyid for v in verified),
        tuple(v.signature_agent for v in verified),
    )
