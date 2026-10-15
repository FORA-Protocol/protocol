"""Binary ErrorDetail decoding (Python side) — replay of the shared Go-oracle corpus.

Mirrors sdk/ts/tests/errordetail-wire.parity.test.ts and the Go leg
sdk/go/connect/gen_error_detail_wire_vectors_test.go.

This SDK reads a Connect error's typed reason from ``details[].value``, the binary
ErrorDetail, through a table-driven decoder instead of a protobuf runtime. The table is
a second statement of the shape, so ``error-detail-wire-vectors.json`` pins it from both
sides: ``wire`` is the same table read from the compiled descriptor, and must be EQUAL to
this SDK's; ``vectors`` are binary encodings, between them setting every field of every
message in the subtree, each with the proto-JSON Go decodes it to.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from conftest import GO_CONNECT_TESTDATA, load_json
from fora_sdk._errordetail_wire import (
    ENUMS,
    MESSAGES,
    REASON_ONEOF,
    WireDecodeError,
    decode_error_detail,
    decode_error_detail_value,
)
from fora_sdk.errordetail import ERROR_DETAIL_TYPE, REASON_FIELDS, error_detail_from
from fora_sdk.wire import to_wire

_CORPUS = load_json(GO_CONNECT_TESTDATA / "error-detail-wire-vectors.json")
_VECTORS: list[dict[str, Any]] = _CORPUS["vectors"]


def _table_row(field: Any) -> dict[str, Any]:
    """One field rendered the way the corpus writes it: empty members omitted."""
    row = {
        "name": field.name,
        "number": field.number,
        "kind": field.kind,
        "type": field.type,
        "repeated": field.repeated,
        "map_key": field.map_key,
        "map_value": field.map_value,
    }
    return {k: v for k, v in row.items() if v not in ("", False)}


def test_message_table_equals_the_descriptor() -> None:
    mine = {name: [_table_row(f) for f in fields] for name, fields in MESSAGES.items()}
    assert mine == _CORPUS["wire"]["messages"]


def test_enum_table_equals_the_descriptor() -> None:
    mine = {name: {str(n): v for n, v in values.items()} for name, values in ENUMS.items()}
    assert mine == _CORPUS["wire"]["enums"]


def test_reason_oneof_is_the_reader_list() -> None:
    # The decoder keeps one member of the oneof; the reader walks the same members.
    assert REASON_ONEOF == REASON_FIELDS


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_value_decodes_to_the_oracle_detail(vector: dict[str, Any]) -> None:
    assert decode_error_detail_value(vector["value"]) == vector["detail"]
    # And through the public reader, which hands the decoded object to the generated
    # model: the model must keep every field the decoder produced.
    detail = error_detail_from({"details": [{"type": ERROR_DETAIL_TYPE, "value": vector["value"]}]})
    assert detail is not None, vector["name"]
    assert to_wire(detail) == vector["detail"]


def test_vector_set_is_nonempty() -> None:
    assert _VECTORS


def test_a_value_that_is_not_base64_is_undecodable() -> None:
    with pytest.raises(WireDecodeError):
        decode_error_detail_value("!!!not base64")


def test_known_field_with_the_wrong_wire_type_is_skipped() -> None:
    # Field 2 (domain, a string) written as a varint 5, then field 1 as a real string.
    raw = bytes([0x10, 0x05, 0x0A, 0x02]) + b"ok"
    assert decode_error_detail(raw) == {"message": "ok"}


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        (bytes([0x0A, 0x05]) + b"ab", "length runs past the end"),
        (bytes([0x0A, 0x02, 0xFF, 0xFE]), "string is not UTF-8"),
        (bytes([0x0B]), "a group wire type"),
        (bytes([0x00, 0x01]), "field number 0"),
        (bytes([0x08] + [0xFF] * 11), "a varint longer than ten bytes"),
        (bytes([0x08]), "a truncated varint"),
    ],
)
def test_undecodable_values(raw: bytes, why: str) -> None:
    with pytest.raises(WireDecodeError):
        decode_error_detail(raw)
    del why


def test_only_the_last_reason_of_the_oneof_is_kept() -> None:
    # dispute_failure (13) then request_auth_failure (17): protobuf keeps the latter.
    raw = bytes([0x6A, 0x02, 0x08, 0x01, 0x8A, 0x01, 0x02, 0x08, 0x03])
    assert decode_error_detail(raw) == {
        "request_auth_failure": {"reason": "REQUEST_AUTH_FAILURE_REASON_SIGNATURE_STALE"}
    }


def test_an_unnamed_enum_number_stays_a_number_and_the_entry_reads_as_none() -> None:
    # dispute_failure.reason = 99: proto-JSON writes the number, the model refuses it,
    # and the reader reports no detail rather than inventing a reason.
    raw = bytes([0x6A, 0x02, 0x08, 99])
    assert decode_error_detail(raw) == {"dispute_failure": {"reason": 99}}
    value = base64.b64encode(raw).decode()
    assert error_detail_from({"details": [{"type": ERROR_DETAIL_TYPE, "value": value}]}) is None


def test_url_alphabet_and_padding_are_accepted() -> None:
    std = _VECTORS[0]["value"]
    padded = std + "=" * (-len(std) % 4)
    url = padded.replace("+", "-").replace("/", "_")
    assert decode_error_detail_value(padded) == decode_error_detail_value(std)
    assert decode_error_detail_value(url) == decode_error_detail_value(std)
