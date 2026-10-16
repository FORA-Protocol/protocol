"""Metered offers: which offers are metered, and the checks a verifier and a signer run.

Mirror of the sdk/ts sibling (sdk/ts/tests/metered-offer.parity.test.ts). A PER_UNIT
offer is metered; it may state an estimate, positive when stated, and the term it
sells carries no pricing.
"""

from __future__ import annotations

import pytest

from fora_sdk import (
    check_metered_estimate,
    check_offer_terms_unpriced,
    is_metered_offer,
)

_PER_UNIT = {"model": "PRICING_MODEL_PER_UNIT"}
_FLAT = {"model": "PRICING_MODEL_FLAT"}


@pytest.mark.parametrize(
    ("offer", "metered", "refused"),
    [
        ({"pricing": {**_PER_UNIT, "estimated_quantity": 1}}, True, False),
        ({"pricing": {**_PER_UNIT, "estimated_quantity": "7"}}, True, False),
        # The estimate is optional; one that is stated is positive.
        ({"pricing": dict(_PER_UNIT)}, True, False),
        ({"pricing": {**_PER_UNIT, "estimated_quantity": None}}, True, False),
        ({"pricing": {**_PER_UNIT, "estimated_quantity": 0}}, True, True),
        ({"pricing": {**_PER_UNIT, "estimated_quantity": -3}}, True, True),
        ({"pricing": {**_PER_UNIT, "estimated_quantity": True}}, True, True),
        # A priced term no longer makes an offer metered: Offer.pricing is the one
        # price, and a priced term is refused by check_offer_terms_unpriced instead.
        ({"pricing": dict(_FLAT), "terms": [{"pricing": dict(_PER_UNIT)}]}, False, False),
        ({"pricing": dict(_FLAT)}, False, False),
        ({}, False, False),
    ],
)
def test_metered_estimate_check(offer: dict[str, object], metered: bool, refused: bool) -> None:
    assert is_metered_offer(offer) is metered
    if refused:
        with pytest.raises(ValueError):
            check_metered_estimate(offer)
    else:
        check_metered_estimate(offer)


@pytest.mark.parametrize(
    ("offer", "refused"),
    [
        ({"pricing": dict(_FLAT), "terms": [{"semantics": "TERM_SEMANTICS_ENUMERATED"}]}, False),
        ({"pricing": dict(_FLAT)}, False),
        ({}, False),
        # A term repeating the offer's own price is still a second copy.
        ({"pricing": dict(_FLAT), "terms": [{"pricing": dict(_FLAT)}]}, True),
        ({"pricing": dict(_FLAT), "terms": [{"pricing": dict(_PER_UNIT)}]}, True),
        # An empty pricing object is pricing present, as has() reads it.
        ({"pricing": dict(_FLAT), "terms": [{"pricing": {}}]}, True),
    ],
)
def test_offer_terms_unpriced_check(offer: dict[str, object], refused: bool) -> None:
    if refused:
        with pytest.raises(ValueError, match="Offer.pricing"):
            check_offer_terms_unpriced(offer)
    else:
        check_offer_terms_unpriced(offer)


def test_offer_terms_unpriced_refuses_a_non_object() -> None:
    with pytest.raises(ValueError):
        check_offer_terms_unpriced("offer")  # type: ignore[arg-type]
