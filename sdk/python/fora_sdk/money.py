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
from decimal import Decimal
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


# ---- metered offers ---------------------------------------------------------
# Port of the sdk/go oracle (helpers/metered.go); fora.proto Pricing states the
# rule. A PER_UNIT price is metered: the publisher states the rate and the unit,
# and the offer may also state an estimate. A metered purchase charges estimate x
# rate, or one unit's rate without an estimate, and the charge is final.

_PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT"
_WIRE_INT_RE = re.compile(r"^-?[0-9]+$")


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
    without one the purchase charges one unit at the rate (1 × R) instead of the
    estimate times the rate (E × R). Either charge is final, and a usage report
    afterwards is only a record. The offer.metered.estimate_positive rule as a
    standalone check, for a verifier that runs without wire validation. A
    non-metered offer passes whatever its pricing says.
    """
    if not isinstance(offer, Mapping):
        msg = "money: offer is not an object"
        raise ValueError(msg)
    if not is_metered_offer(offer):
        return
    pricing = offer.get("pricing")
    if isinstance(pricing, Mapping):
        _stated_estimate(pricing)
