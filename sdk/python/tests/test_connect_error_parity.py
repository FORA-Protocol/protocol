"""Connect error-envelope parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors the sdk/ts sibling sdk/ts/tests/connect-error.parity.test.ts and the Go leg
sdk/go/connect/connect_error_corpus_test.go.

``error-detail-vectors.json`` pins the DETAIL's own proto-JSON. This corpus pins the
ENVELOPE the detail arrives in. A detail entry carries the binary ErrorDetail in
``value`` (base64) — the authoritative copy, and the only one Go reads — and usually a
``debug`` projection beside it. This SDK reads ``value`` and falls back to ``debug`` only
when ``value`` is absent; the derived rows (``*.value_only``, ``value_wins_over_debug``,
``undecodable_value_skipped``) hold that order.

The ``debug`` projection is lowerCamelCase and no server option changes it — connect-go
builds it with its own protojson codec at default options — while the response bodies the
same server emits are snake_case. Reading ``debug`` with a snake-only model therefore used
to return a detail carrying ``domain`` and ``message`` (single words spell the same either
way) and NO typed reason, for a refusal the Exchange had named precisely.

Every captured vector came from a real connect-go handler, so the reader is asserted
against what the wire does rather than against a description of it. Each row is also
decoded through the client, which must report the row's Connect code on
``CallError.code``.
"""

from __future__ import annotations

import json

import pytest

from conftest import GO_CONNECT_TESTDATA, load_json
from fora_sdk.client._call import decode
from fora_sdk.client.errors import CallError
from fora_sdk.errordetail import error_detail_from, reason
from fora_sdk.wire import to_wire
from wire.models import ResourceResponse

_VECTORS = load_json(GO_CONNECT_TESTDATA / "connect-error-vectors.json")["vectors"]


def test_connect_error_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_reader_extracts_go_projection_from_the_envelope(vector: dict) -> None:
    detail = error_detail_from(vector["envelope"])
    expect = vector["expect"]

    # The status connect-go maps this code onto. Recorded by the emitter and, until now,
    # read by nobody — so the corpus carried a column that asserted nothing. It matters
    # because the reader below is reached from a non-2xx, and which non-2xx decides the
    # failure CLASS when an envelope names no code of its own.
    assert isinstance(vector["http_status"], int)
    assert 400 <= vector["http_status"] < 600, (
        f"{vector['name']}: code {vector['code']!r} maps to {vector['http_status']}, "
        "which is not an error status"
    )

    # BEFORE the early return, because the row that carries no detail is the one this
    # column exists for: its envelope has a ``message`` of its own and the client must
    # still report none. The field lives on the CallError, one tier above the detail the
    # rest of this replay projects, so it is read off a real decode.
    #
    # The rule is provenance: it carries a message the PEER emitted and nothing else. A
    # transport's synthesized text is not that — connect-go writes a status line where
    # this client writes nothing — so filling the field from the envelope would make its
    # value a property of the language rather than of the answer.
    with pytest.raises(CallError) as caught:
        decode("discover", vector["http_status"], json.dumps(vector["envelope"]), ResourceResponse)
    assert (caught.value.peer_message or "") == vector["peer_message"], vector["name"]
    # The Connect code the server classified the failure as, on its own field: the class a
    # caller branches on when it needs more than refused-or-unreachable.
    assert caught.value.code == vector["code"], vector["name"]

    if not expect["has_detail"]:
        assert detail is None, "an envelope carrying no ErrorDetail must read as none"
        assert expect["detail"] is None
        return

    assert detail is not None, (
        "no ErrorDetail extracted from an envelope that carries one — the reader is "
        "looking at the wrong member, or the debug projection was not decoded"
    )
    assert detail.domain == expect["domain"]
    assert detail.message == expect["message"]
    # The whole detail, under the proto names: a nested member lost on the way
    # (field_errors, a metadata entry) fails here even when the projection matches.
    assert to_wire(detail) == expect["detail"], vector["name"]
    assert caught.value.detail is not None
    assert to_wire(caught.value.detail) == expect["detail"]

    # Metadata keys are the EMITTER's, not the proto's. The corpus carries a
    # deliberately lowerCamelCase key so a normalizer that walked into the map would
    # rewrite it and fail here.
    assert (detail.metadata or {}) == (expect["metadata"] or {})

    got = reason(detail)
    if not expect["reason_field"]:
        assert got is None, f"reader invented a reason ({got}) the oracle does not report"
        return
    assert got is not None, (
        f"reader lost the typed reason {expect['reason_enum']} the Exchange sent — "
        "a fail-open read of the one field a caller branches on"
    )
    assert got.value == expect["reason_enum"]
    block = getattr(detail, expect["reason_field"])
    assert block is not None, (
        f"reason arrived under a different oneof member than {expect['reason_field']!r}"
    )


def test_camel_case_debug_projection_is_decoded() -> None:
    """The regression itself, stated once in the open rather than only via the corpus.

    A snake-only read of this envelope parses successfully and reports no reason — which
    is why nothing caught it before the corpus existed. The entry carries no ``value``,
    which is the one case the projection is read for.
    """
    envelope = {
        "code": "permission_denied",
        "message": "balance too low",
        "details": [
            {
                "type": "fora.v1.ErrorDetail",
                "debug": {
                    "domain": "fora.v1.ExchangeService",
                    "message": "balance too low",
                    "transactionDenial": {"reason": "DENIAL_REASON_INSUFFICIENT_BALANCE"},
                },
            }
        ],
    }
    detail = error_detail_from(envelope)
    assert detail is not None
    got = reason(detail)
    assert got is not None and got.value == "DENIAL_REASON_INSUFFICIENT_BALANCE"
