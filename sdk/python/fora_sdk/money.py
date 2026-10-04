"""Money (ADR-020) — Python port of the sdk/go oracle (helpers/money.go).

FORA money fields (Pricing.rate, Cost.amount, *.unit_cost) are exact decimal
strings — never floats — constrained by protovalidate to the wire pattern below:
non-negative, no sign, no exponent, optional fractional part, empty string for
"unset". The surface is stdlib ``decimal.Decimal``; ``canonicalize_money``
reproduces the Go shopspring round-trip byte-for-byte: strip insignificant
LEADING integer zeros AND trailing fractional zeros + a bare trailing dot, in
PLAIN notation (``format(d, "f")`` — never ``str(d)``, which emits scientific
notation for small fractions where Go does not, e.g. ``str(Decimal("0.0000001"))``
== ``"1E-7"``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import (
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
    localcontext,
)
from typing import Any

# _MONEY_WIRE mirrors the protovalidate constraint ``^([0-9]+([.][0-9]+)?)?$``
# exactly (kept in lockstep with fora.proto Pricing.rate). The empty string
# matches the pattern but is rejected by parse_money as "unset".
_MONEY_WIRE = re.compile(r"^([0-9]+([.][0-9]+)?)?$")

# _MONEY_MAX_LEN mirrors the protovalidate string.max_len = 32 on
# Pricing.rate/Cost.amount/unit_cost.
_MONEY_MAX_LEN = 32


def parse_money(s: str) -> Decimal:
    """Parse a canonical wire decimal string into an exact ``Decimal``.

    Rejects the empty (unset) string and any value the wire pattern forbids —
    signs, exponents, a leading dot — so a value that would fail the server's
    protovalidate never silently parses here.
    """
    if s == "":
        msg = "money: empty money string (field is unset)"
        raise ValueError(msg)
    # Mirror protovalidate string.max_len = 32 (fora.proto Pricing.rate) so a
    # pattern-valid but over-length value is rejected here, not only server-side.
    if len(s) > _MONEY_MAX_LEN:
        msg = f"money: string length {len(s)} exceeds max {_MONEY_MAX_LEN}"
        raise ValueError(msg)
    if not _MONEY_WIRE.match(s):
        msg = f"money: {s!r} is not a canonical money string"
        raise ValueError(msg)
    return Decimal(s)


def format_money(d: Decimal) -> str:
    """Render an exact ``Decimal`` as the canonical wire string: no sign, no
    exponent, insignificant LEADING integer zeros dropped and insignificant
    trailing fractional zeros + a bare trailing dot stripped. A negative value is
    rejected — FORA money is non-negative.
    """
    if d < 0:
        msg = f"money: negative money {d} is not representable on the wire"
        raise ValueError(msg)
    s = format(d, "f")  # plain notation — never scientific, matching Go's String().
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


def canonicalize_money(s: str) -> str:
    """Normalize a wire decimal string to its canonical form (parse then format)."""
    return format_money(parse_money(s))


# ---- metered settlement ----------------------------------------------------
# Port of the sdk/go oracle (helpers/settlement.go); fora.proto Pricing states the
# rule. A PER_UNIT price is charged per unit consumed. The estimate E, the rate R
# and the tolerance T in basis points (1000 when absent) on the offer's own pricing
# fix what a metered purchase can cost: the agent accepts E x R at purchase, and the
# usage report settles the consumed quantity C at min(C, Q) x R, where the ceiling
# is Q = E x (10000 + T) / 10000. The quantity above Q is held for dispute, never
# charged automatically.
#
# Every value is exact. The arithmetic runs in a local context whose precision far
# exceeds any input the wire admits (rates are capped at 32 characters, quantities
# at int64), and with Inexact trapped, so a step that would round raises instead of
# returning a rounded figure. The process-wide context — 28 digits by default — is
# never consulted.

DEFAULT_ESTIMATE_TOLERANCE_BPS = 1000
"""The tolerance a metered price settles within when it states none: 10%."""

MAX_ESTIMATE_TOLERANCE_BPS = 10000
"""The largest tolerance the wire accepts: a ceiling of twice the estimate."""

_PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT"
_INT64_MAX = 2**63 - 1
_WIRE_INT_RE = re.compile(r"^-?[0-9]+$")


@dataclass(frozen=True)
class MeteredSettlement:
    """What a metered purchase settles to, every value a canonical decimal string.

    Quantities are in the price's unit and may be fractional (``ceiling_quantity``
    and what derives from it); amounts are in the price's currency. When the price
    states no estimate there is no ceiling: ``accepted_amount``, ``ceiling_quantity``
    and ``ceiling_amount`` are ``None``, the whole consumed quantity is charged, and
    nothing is held.
    """

    accepted_amount: str | None
    """E x R: what the agent accepted at purchase. ``None`` without an estimate."""
    ceiling_quantity: str | None
    """Q = E x (10000 + T) / 10000. ``None`` without an estimate."""
    ceiling_amount: str | None
    """Q x R: the most the purchase is charged without a dispute. ``None`` without an
    estimate."""
    charged_quantity: str
    """min(C, Q), or C without an estimate."""
    charged_amount: str
    """charged_quantity x R: what the report settles to."""
    held_quantity: str
    """max(0, C - Q): the quantity held for dispute. Always 0 without an estimate."""
    held_amount: str
    """held_quantity x R: held for dispute, never charged automatically."""


def _wire_int(v: Any) -> int | None:
    """An int32/int64 proto-JSON value: a JSON integer, or the decimal string form
    proto-JSON also accepts. ``bool`` is not an integer here, though Python says so."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and _WIRE_INT_RE.match(v):
        return int(v)
    return None


def _model(pricing: Any) -> str:
    if not isinstance(pricing, Mapping):
        return ""
    model = pricing.get("model")
    return model if isinstance(model, str) else ""


def is_metered_offer(offer: Mapping[str, Any]) -> bool:
    """Whether ``offer`` (canonical proto-JSON) is metered: its pricing is PER_UNIT.

    ``Offer.pricing`` is the offer's one price and the term it sells carries none
    (fora.proto Offer, the offer.metered.estimate_positive and
    offer.terms.pricing_unset rules), so a term is never consulted. Python peer of Go
    ``helpers.IsMeteredOffer``."""
    return _model(offer.get("pricing")) == _PRICING_MODEL_PER_UNIT


def check_offer_terms_unpriced(offer: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` when any term of ``offer`` (canonical proto-JSON) carries
    ``pricing``; return quietly otherwise.

    An offer states its price once, in ``Offer.pricing``, and the term it sells carries
    none (fora.proto Offer, the offer.terms.pricing_unset rule). This is that rule as a
    standalone check, for a signer or a verifier that runs without wire validation. A
    present ``pricing`` key counts whatever its value, as ``has()`` does. Python peer of
    Go ``helpers.CheckOfferTermsUnpriced``.
    """
    if not isinstance(offer, Mapping):
        msg = "money: offer is not an object"
        raise ValueError(msg)
    terms = offer.get("terms")
    if not isinstance(terms, list):
        return
    for i, t in enumerate(terms):
        if isinstance(t, Mapping) and t.get("pricing") is not None:
            msg = f"money: an offer's term carries pricing; the offer's price is Offer.pricing (terms[{i}])"
            raise ValueError(msg)


def _stated_estimate(pricing: Mapping[str, Any]) -> int | None:
    """The ``estimated_quantity`` ``pricing`` states, or ``None`` when it states none.

    Raise ``ValueError`` for a stated estimate that is not a positive integer: an
    estimate is optional, but one that is stated is positive."""
    raw = pricing.get("estimated_quantity")
    if raw is None:
        return None
    estimate = _wire_int(raw)
    if estimate is None or estimate <= 0:
        msg = f"money: metered pricing states an estimated_quantity that is not positive: {raw!r}"
        raise ValueError(msg)
    return estimate


def check_metered_estimate(offer: Mapping[str, Any]) -> None:
    """Raise ``ValueError`` when ``offer`` is metered and its pricing states an
    ``estimated_quantity`` that is not positive; return quietly otherwise.

    A metered offer that states no estimate passes: the estimate is optional, and
    without one the purchase settles with no ceiling. The
    offer.metered.estimate_positive rule as a standalone check, for a verifier that
    runs without wire validation. A non-metered offer passes whatever its pricing
    says.
    """
    if not isinstance(offer, Mapping):
        msg = "money: offer is not an object"
        raise ValueError(msg)
    if not is_metered_offer(offer):
        return
    pricing = offer.get("pricing")
    if isinstance(pricing, Mapping):
        _stated_estimate(pricing)


def estimate_tolerance_bps(pricing: Mapping[str, Any]) -> int:
    """The tolerance ``pricing`` settles within: its ``estimate_tolerance_bps`` when
    present (an explicit 0 included), else the 1000 default. Bounds are not checked
    here; :func:`settle_metered_usage` and :func:`metered_settlement_cap` do."""
    raw = pricing.get("estimate_tolerance_bps") if isinstance(pricing, Mapping) else None
    if raw is None:
        return DEFAULT_ESTIMATE_TOLERANCE_BPS
    bps = _wire_int(raw)
    if bps is None:
        msg = f"money: estimate_tolerance_bps {raw!r} is not an integer"
        raise ValueError(msg)
    return bps


def _exact() -> Context:
    return Context(prec=200, traps=[Inexact, InvalidOperation, Overflow, DivisionByZero])


def _metered_terms(pricing: Mapping[str, Any]) -> tuple[Decimal | None, Decimal, Decimal | None]:
    """Check ``pricing`` is a metered price that can settle; return (E, R, Q).

    E and Q are ``None`` when the price states no estimate."""
    if not isinstance(pricing, Mapping):
        msg = "money: pricing is not an object"
        raise ValueError(msg)
    if _model(pricing) != _PRICING_MODEL_PER_UNIT:
        msg = f"money: pricing is not metered (PER_UNIT): model is {_model(pricing)!r}"
        raise ValueError(msg)
    estimate = _stated_estimate(pricing)
    rate_raw = pricing.get("rate", "")
    rate = parse_money(rate_raw if isinstance(rate_raw, str) else "")
    bps = estimate_tolerance_bps(pricing)
    if not 0 <= bps <= MAX_ESTIMATE_TOLERANCE_BPS:
        msg = f"money: estimate_tolerance_bps {bps} is outside 0..{MAX_ESTIMATE_TOLERANCE_BPS}"
        raise ValueError(msg)
    if estimate is None:
        return None, rate, None
    with localcontext(_exact()):
        e = Decimal(estimate)
        ceiling = (e * Decimal(10000 + bps)).scaleb(-4)
    return e, rate, ceiling


def metered_settlement_cap(pricing: Mapping[str, Any]) -> str | None:
    """Q x R for a metered price: the most a purchase under it is charged without a
    dispute.

    ``None`` when the price states no estimate: it then has no ceiling, and nothing in
    it bounds the charge. Raises ``ValueError`` for a price that is not PER_UNIT,
    states an estimate that is not positive, carries no valid rate, or states a
    tolerance outside 0..10000.
    """
    _, rate, ceiling = _metered_terms(pricing)
    if ceiling is None:
        return None
    with localcontext(_exact()):
        return format_money(ceiling * rate)


def settle_metered_usage(pricing: Mapping[str, Any], consumed_quantity: int) -> MeteredSettlement:
    """Settle a usage report of ``consumed_quantity`` against a metered price — the
    offer's own pricing, which is the copy settlement reads. Without an estimate the
    whole quantity is charged at the rate and nothing is held.

    Raises ``ValueError`` for what :func:`metered_settlement_cap` refuses, and for a
    quantity that is negative or not an integer.
    """
    estimate, rate, ceiling = _metered_terms(pricing)
    if isinstance(consumed_quantity, bool) or not isinstance(consumed_quantity, int):
        msg = f"money: consumed quantity {consumed_quantity!r} is not an integer"
        raise ValueError(msg)
    if not 0 <= consumed_quantity <= _INT64_MAX:
        msg = f"money: consumed quantity {consumed_quantity} is outside 0..{_INT64_MAX}"
        raise ValueError(msg)
    with localcontext(_exact()):
        consumed = Decimal(consumed_quantity)
        if estimate is None or ceiling is None:
            return MeteredSettlement(
                accepted_amount=None,
                ceiling_quantity=None,
                ceiling_amount=None,
                charged_quantity=format_money(consumed),
                charged_amount=format_money(consumed * rate),
                held_quantity="0",
                held_amount="0",
            )
        charged = min(consumed, ceiling)
        held = max(Decimal(0), consumed - ceiling)
        return MeteredSettlement(
            accepted_amount=format_money(estimate * rate),
            ceiling_quantity=format_money(ceiling),
            ceiling_amount=format_money(ceiling * rate),
            charged_quantity=format_money(charged),
            charged_amount=format_money(charged * rate),
            held_quantity=format_money(held),
            held_amount=format_money(held * rate),
        )
