"""Acceptance signers that admit an empty requester, for a test proving a verifier refuses
them.

fora.proto requires an acceptance to name its requester: "A signer refuses to sign bytes
that name an empty requester, and a verifier refuses an acceptance whose canonical bytes
name one, even when the signature over those bytes verifies." The signers in
:mod:`fora_sdk.core` are that signer, so they cannot produce the one input a verifier's
refusal is tested with. The four functions here are their twins with that single refusal
skipped. They render through the same canonical form and keep every other refusal, so an
acceptance they sign is valid in every respect but the requester, and a verifier's refusal
of it is attributable to that alone. The ``refused`` lists of the shared
``acceptance-vectors.json`` and ``request-acceptance-vectors.json`` record exactly what they
produce.

This module is test support: nothing in the SDK imports it, it is not re-exported from
:mod:`fora_sdk`, and an acceptance it signs is one a conforming party must never send. Go's
``helperstest`` and TypeScript's ``@fora-protocol/sdk/testing`` are its twins.
"""

from __future__ import annotations

from fora_sdk.core import _acceptance_payload, _request_acceptance_payload, _sign_payload

__all__ = [
    "jcs_acceptance_payload_any_requester",
    "jcs_request_acceptance_payload_any_requester",
    "sign_offer_acceptance_any_requester",
    "sign_request_acceptance_any_requester",
]


def _any_requester(_requester_id: str, _requester_domain: str) -> None:
    """Admit every requester, an empty one included."""


def jcs_acceptance_payload_any_requester(
    *,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> bytes:
    """:func:`fora_sdk.core.jcs_acceptance_payload` without its refusal of an empty
    requester id or domain."""
    return _acceptance_payload(
        offer_sig=offer_sig,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
        requester_check=_any_requester,
    )


def sign_offer_acceptance_any_requester(
    *,
    seed: bytes,
    offer_sig: str,
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> tuple[str, str]:
    """:func:`fora_sdk.core.sign_offer_acceptance_jcs` without its refusal of an empty
    requester id or domain; returns ``(hex_signature, "EdDSA")``."""
    payload = jcs_acceptance_payload_any_requester(
        offer_sig=offer_sig,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
    )
    return _sign_payload(seed, payload)


def jcs_request_acceptance_payload_any_requester(
    *,
    items: list[tuple[str, str]],
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> bytes:
    """:func:`fora_sdk.core.jcs_request_acceptance_payload` without its refusal of an
    empty requester id or domain."""
    return _request_acceptance_payload(
        items=items,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
        requester_check=_any_requester,
    )


def sign_request_acceptance_any_requester(
    *,
    seed: bytes,
    items: list[tuple[str, str]],
    requester_id: str,
    requester_domain: str,
    idempotency_key: str,
) -> tuple[str, str]:
    """:func:`fora_sdk.core.sign_request_acceptance_jcs` without its refusal of an empty
    requester id or domain; returns ``(hex_signature, "EdDSA")``."""
    payload = jcs_request_acceptance_payload_any_requester(
        items=items,
        requester_id=requester_id,
        requester_domain=requester_domain,
        idempotency_key=idempotency_key,
    )
    return _sign_payload(seed, payload)
