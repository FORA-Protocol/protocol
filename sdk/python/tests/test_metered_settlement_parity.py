"""Metered settlement parity against the Go oracle.

Mirror of the sdk/ts sibling (sdk/ts/tests/metered-settlement.parity.test.ts). The
settlement of a metered purchase is arithmetic the agent and the Exchange must agree
on to the last digit: the agent derives what it owes from the signed offer and its
own report, and no amount travels on the wire to reconcile the two. Every row of
sdk/go/helpers/testdata/metered-settlement-vectors.json is replayed through
``settle_metered_usage`` and ``metered_settlement_cap``. Two rows need 42
significant digits, past the 28 of Python's default decimal context, so a port that
leaned on that context would round and fail them.
"""

from __future__ import annotations

import dataclasses
from decimal import getcontext

import pytest

from conftest import GO_TESTDATA, load_json
from fora_sdk import (
    check_offer_terms_unpriced,
    DEFAULT_ESTIMATE_TOLERANCE_BPS,
    check_metered_estimate,
    estimate_tolerance_bps,
    is_metered_offer,
    metered_settlement_cap,
    settle_metered_usage,
)

_DOC = load_json(GO_TESTDATA / "metered-settlement-vectors.json")
_VECTORS = _DOC["vectors"]


def test_corpus_shape() -> None:
    assert _VECTORS, "metered-settlement corpus is empty — the replay below would be vacuous"
    assert any(v["error"] for v in _VECTORS)
    assert any(not v["error"] for v in _VECTORS)


def test_default_tolerance_matches_oracle() -> None:
    assert _DOC["default_estimate_tolerance_bps"] == DEFAULT_ESTIMATE_TOLERANCE_BPS


@pytest.mark.parametrize("vec", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_settlement_matches_oracle(vec: dict[str, object]) -> None:
    pricing = vec["pricing"]
    consumed = vec["consumed_quantity"]
    assert isinstance(pricing, dict)
    assert isinstance(consumed, int)
    if vec["error"]:
        with pytest.raises(ValueError):
            settle_metered_usage(pricing, consumed)
        if vec["cap_error"]:
            with pytest.raises(ValueError):
                metered_settlement_cap(pricing)
        else:
            metered_settlement_cap(pricing)
        return
    got = dataclasses.asdict(settle_metered_usage(pricing, consumed))
    assert got == vec["expected"]
    expected = vec["expected"]
    assert isinstance(expected, dict)
    # A row without an estimate records a null ceiling, and the cap is then None.
    assert metered_settlement_cap(pricing) == expected["ceiling_amount"]


def test_corpus_covers_both_shapes() -> None:
    """The replay settles a price with an estimate and one without: a corpus that
    lost either would leave that shape of settlement untested."""
    settled = [v for v in _VECTORS if not v["error"]]
    assert any(v["expected"]["ceiling_amount"] is None for v in settled)
    assert any(v["expected"]["ceiling_amount"] is not None for v in settled)


def test_process_context_untouched() -> None:
    """The exact rows run in a local context; the caller's context is left as found."""
    before = getcontext().prec
    for vec in _VECTORS:
        if not vec["error"]:
            settle_metered_usage(vec["pricing"], vec["consumed_quantity"])
    assert getcontext().prec == before


def test_tolerance_default_and_explicit_zero() -> None:
    assert estimate_tolerance_bps({}) == 1000
    assert estimate_tolerance_bps({"estimate_tolerance_bps": 0}) == 0
    assert estimate_tolerance_bps({"estimate_tolerance_bps": "250"}) == 250


def test_consumed_must_be_an_integer() -> None:
    pricing = {
        "model": "PRICING_MODEL_PER_UNIT",
        "rate": "0.00002",
        "unit": "tokens",
        "estimated_quantity": 2500,
    }
    for bad in (True, 1.5, "10"):
        with pytest.raises(ValueError):
            settle_metered_usage(pricing, bad)  # type: ignore[arg-type]


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
