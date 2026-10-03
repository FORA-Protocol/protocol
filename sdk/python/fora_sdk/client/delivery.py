"""Delivery verification: check a signed retrieval URL before anything relies on it.

A purchase answers with one signed retrieval URL per item. The Exchange signs it with
Ed25519 over ``"GET\\n<canonical URL>"``; the URL names the signing key in ``kid``, may bind
itself to the buying agent with ``agent_id`` (the RFC 7638 thumbprint of the agent's
request-signing key), and expires at ``exp``. The delivery edge checks all three. This
module checks them first, on the agent's side, so a URL that could never be fetched — a
forged one relayed by a Broker, one bound to somebody else, one already expired — is
refused when it arrives rather than surfacing as an edge 403 later.

The signing key comes from the issuing Exchange's Web Bot Auth key directory, resolved by
``kid`` (the key's thumbprint) through an injected resolver, which by default is the
SDK's own SSRF-guarded :class:`~fora_sdk.resolvers.wba.WBAKeyResolver`. The signature and
expiry check is the shared :func:`~fora_sdk.signedurl.verify_ed25519_signed_url`, so the
byte contract is the one the three SDKs and the edge already agree on.

A refusal is a ``MALFORMED`` :class:`~fora_sdk.client.errors.CallError` carrying a
``retrieval_auth_failure`` detail the SDK synthesizes, in the vocabulary the edge itself
answers with, so a caller branches on one set of reasons whichever side checked. A key
directory that cannot be reached is ``UNREACHABLE`` instead: nothing was decided about
the URL.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import PrivateAttr
from wire.models import (
    BrokerTransactionResponse,
    RetrievalAuthFailureReason,
    TransactionResponse,
)

from fora_sdk.errordetail import retrieval_auth_failure_detail
from fora_sdk.resolvers.errors import DirectoryUnavailableError, ResolverError
from fora_sdk.signedurl import _parse_query_pairs, verify_ed25519_signed_url

from .errors import CallError, CallErrorKind

if TYPE_CHECKING:
    from collections.abc import Callable

#: The ErrorDetail domain of a refusal this client computed: the client's own tier,
#: because no peer reached a verdict. The same value the registration pre-check uses.
CLIENT_ERROR_DOMAIN = "fora.v1.Client"

_REASONS = {
    "missing_sig": RetrievalAuthFailureReason.RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING,
    "missing_exp": RetrievalAuthFailureReason.RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING,
    "expired": RetrievalAuthFailureReason.RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED,
    "bad_sig_encoding": (
        RetrievalAuthFailureReason.RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH
    ),
    "signature_mismatch": (
        RetrievalAuthFailureReason.RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH
    ),
}
_THUMBPRINT_MISMATCH = RetrievalAuthFailureReason.RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH


@dataclass(frozen=True)
class Delivery:
    """A signed retrieval URL whose signature, agent binding and expiry this client verified.

    ``execute`` hands one back per result item that carries a URL, and ``fetch`` accepts
    one in place of the bare URL and verifies it again before sending.
    """

    #: The signed retrieval URL, exactly as the Exchange issued it.
    url: str
    #: The bare domain of the Exchange whose key verified the signature.
    exchange: str
    #: The agent thumbprint the URL is bound to; ``""`` for a bearer URL.
    agent_id: str
    #: The ``kid`` the URL names: the thumbprint of the Exchange's URL-signing key.
    key_id: str
    #: When the URL stops being honoured (its ``exp``), in UTC.
    expires_at: datetime


class DeliveryKeyResolver(Protocol):
    """Resolves the key an Exchange signs delivery URLs with.

    ``keyid`` is the URL's ``kid`` (a key thumbprint) and ``directory`` the Exchange's bare
    domain, whose Web Bot Auth directory publishes the key. Returns the raw 32-byte
    Ed25519 public key. :class:`~fora_sdk.resolvers.wba.WBAKeyResolver` satisfies it.
    """

    def resolve(self, keyid: str, directory: str) -> bytes: ...


@dataclass(frozen=True)
class Expected:
    """What one URL is checked against: whose key signed it, and whom it must be bound to."""

    #: The bare domain of the Exchange whose directory publishes the URL-signing key.
    exchange: str
    #: This agent's thumbprint.
    agent: str
    #: The agent_identity_hash the answer stated; ``""`` when it stated none.
    stated: str = ""


def verify_delivery(
    op: str, url: str, expected: Expected, keys: DeliveryKeyResolver, where: str = ""
) -> Delivery:
    """Verify one retrieval URL against ``expected.exchange``'s key; return the binding.

    The binding rule: a URL carrying ``agent_id`` must carry this agent's thumbprint, and
    when the answer stated an ``agent_identity_hash`` the URL must carry that value. A
    URL with no ``agent_id`` under an answer that stated none is a bearer URL the
    protocol allows, and verifies with ``agent_id`` empty. ``where`` prefixes the message
    of a refusal ("item 2 (tx-9)"), so a batch failure names its item.
    """
    prefix = f"{where}: " if where else ""
    exchange = expected.exchange

    def resolve(kid: str | None) -> bytes | None:
        if not kid:
            return None
        try:
            return keys.resolve(kid, exchange)
        except DirectoryUnavailableError as exc:
            raise CallError(
                CallErrorKind.UNREACHABLE,
                op,
                cause=f"{prefix}the key directory of {exchange} could not be read: {exc}",
            ) from exc
        except ResolverError:
            return None

    verdict = verify_ed25519_signed_url(url, now=int(time.time()), resolve_key=resolve)
    if not verdict.valid:
        reason = _REASONS.get(verdict.reason or "", _REASONS["signature_mismatch"])
        raise _refusal(op, reason, f"{prefix}the delivery URL does not verify ({verdict.reason})")
    agent_id = verdict.agent_id or ""
    if agent_id and agent_id != expected.agent:
        raise _refusal(
            op, _THUMBPRINT_MISMATCH, f"{prefix}the delivery URL is bound to another agent"
        )
    if expected.stated and agent_id != expected.stated:
        raise _refusal(
            op,
            _THUMBPRINT_MISMATCH,
            f"{prefix}the delivery URL is not bound to the agent_identity_hash the answer states",
        )
    return Delivery(
        url=url,
        exchange=exchange,
        agent_id=agent_id,
        key_id=verdict.kid or "",
        expires_at=datetime.fromtimestamp(_exp_of(url), tz=UTC),
    )


def _exp_of(url: str) -> int:
    """The URL's ``exp``, which the verify above already proved present and numeric."""
    _prefix, _sep, query = url.partition("?")
    return int(dict(_parse_query_pairs(query))["exp"])


def _refusal(op: str, reason: RetrievalAuthFailureReason, message: str) -> CallError:
    return CallError(
        CallErrorKind.MALFORMED,
        op,
        cause=message,
        detail=retrieval_auth_failure_detail(CLIENT_ERROR_DOMAIN, message, reason),
    )


def verify_items(
    op: str,
    items: list[Any],
    expected_of: Callable[[int, Any], Expected],
    keys: DeliveryKeyResolver,
) -> tuple[Delivery | None, ...]:
    """Verify every result item that carries a retrieval URL, in order.

    ``expected_of(index, item)`` states what the item's URL is checked against: the
    Exchange that issued the item's offer and the binding that Exchange's answer stated.
    An item with no URL — denied, refused upstream, or not delivered by signed URL — has
    none.
    """
    out: list[Delivery | None] = []
    for i, item in enumerate(items):
        url = getattr(item, "retrieval_endpoint", None)
        if not url:
            out.append(None)
            continue
        tx = getattr(item, "transaction_id", "") or ""
        where = f"item {i} ({tx})" if tx else f"item {i}"
        out.append(verify_delivery(op, url, expected_of(i, item), keys, where))
    return tuple(out)


class ExecuteResult(TransactionResponse):
    """The answer to ``Client.execute``: the TransactionResponse, plus the verified URLs.

    It IS the generated ``TransactionResponse`` — every field, every method, the same
    ``model_dump`` — with one addition that is not part of the message:
    :attr:`deliveries`, one entry per result item, the :class:`Delivery` this client
    verified for it, or ``None`` where the item carries no retrieval URL.
    """

    _deliveries: tuple[Delivery | None, ...] = PrivateAttr(default=())

    @property
    def deliveries(self) -> tuple[Delivery | None, ...]:
        """The verified binding of each item's retrieval URL, index-aligned with ``items``.

        Empty when verification is off or the call was raw: then nothing was verified.
        """
        return self._deliveries


class BrokerExecuteResult(BrokerTransactionResponse):
    """The answer to ``BrokerClient.execute``, plus the verified URLs. See
    :class:`ExecuteResult`."""

    _deliveries: tuple[Delivery | None, ...] = PrivateAttr(default=())

    @property
    def deliveries(self) -> tuple[Delivery | None, ...]:
        """The verified binding of each item's retrieval URL, index-aligned with ``items``."""
        return self._deliveries
