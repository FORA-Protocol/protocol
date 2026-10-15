"""The refusals of the acceptance canonicalizers and signers, pinned.

The exact text, and which refusal wins when an input has several faults. The renderer and
the checks around it are shared with code that skips one of them (``fora_sdk.testing``), so
the order and the wording are part of what must not move; downstream suites match the text.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from fora_sdk.core import (
    jcs_acceptance_payload,
    jcs_request_acceptance_payload,
    sign_offer_acceptance_jcs,
    sign_request_acceptance_jcs,
    verify_offer_acceptance_jcs,
    verify_request_acceptance_jcs,
)

_SEED = bytes(range(32))
_NAMED = {"requester_id": "agent-1", "requester_domain": "agent.example", "idempotency_key": "idem"}
_UNSIGNED = "cannot accept an unsigned offer (empty offer signature)"
_NO_ID = "acceptance names an empty requester: requester_id is empty"
_NO_DOMAIN = "acceptance names an empty requester: requester_domain is empty"
_NO_ITEMS = "request acceptance requires at least one item"


def _with(**changes: Any) -> dict[str, Any]:
    return {**_NAMED, **changes}


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        (_with(offer_sig=""), _UNSIGNED),
        (_with(offer_sig="sig", requester_id=""), _NO_ID),
        (_with(offer_sig="sig", requester_domain=""), _NO_DOMAIN),
        # An unsigned offer is refused before an empty requester.
        (_with(offer_sig="", requester_id=""), _UNSIGNED),
        (_with(offer_sig="sig", requester_id="", requester_domain=""), _NO_ID),
    ],
)
def test_the_offer_acceptance_refusals(fields: dict[str, Any], message: str) -> None:
    for call in (
        lambda: jcs_acceptance_payload(**fields),
        lambda: sign_offer_acceptance_jcs(seed=_SEED, **fields),
        lambda: verify_offer_acceptance_jcs(pubkey_b64="AA==", signature_hex="00", **fields),
    ):
        with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
            call()


_ITEM = ("sig", "one.example")


@pytest.mark.parametrize(
    ("items", "fields", "message"),
    [
        ([], _NAMED, _NO_ITEMS),
        ([("", "one.example")], _NAMED, "request acceptance item 0 has an empty offer signature"),
        ([("sig", "")], _NAMED, "request acceptance item 0 has an empty exchange"),
        (
            [_ITEM, ("", "one.example")],
            _NAMED,
            "request acceptance item 1 has an empty offer signature",
        ),
        ([_ITEM], _with(requester_id=""), _NO_ID),
        ([_ITEM], _with(requester_domain=""), _NO_DOMAIN),
        # An empty requester is refused before no items and before an empty item field.
        ([], _with(requester_id=""), _NO_ID),
        ([("", "")], _with(requester_domain=""), _NO_DOMAIN),
        # Within an item, an empty offer signature is refused before an empty exchange.
        ([("", "")], _NAMED, "request acceptance item 0 has an empty offer signature"),
    ],
)
def test_the_request_acceptance_refusals(
    items: list[tuple[str, str]], fields: dict[str, Any], message: str
) -> None:
    for call in (
        lambda: jcs_request_acceptance_payload(items=items, **fields),
        lambda: sign_request_acceptance_jcs(seed=_SEED, items=items, **fields),
    ):
        with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
            call()
    assert not verify_request_acceptance_jcs(
        pubkey_b64="AA==", signature_hex="00", items=items, **fields
    )
