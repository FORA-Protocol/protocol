"""Decode a binary ``fora.v1.ErrorDetail`` into canonical proto-JSON, with no protobuf runtime.

A Connect error carries its typed reason as ``details[].value``: the binary encoding of
the ErrorDetail, base64-encoded. That is the authoritative copy. The ``debug`` projection
beside it is something connect-go adds for JSON readers, and it may be absent. So this
SDK reads ``value`` first, and needs to decode protobuf to do it.

It does not take a protobuf dependency for that. The ErrorDetail subtree is small and
closed: ErrorDetail, its eight reason messages, RegistrationFieldError, and the enums
they use. A table describes it here, and a generic wire-format reader walks the table.
The table is a second statement of the shape, and it is pinned from both sides by the
shared corpus ``error-detail-wire-vectors.json``: the corpus carries the same tables read
from the compiled descriptor, which the suite requires this table to EQUAL, and binary
vectors that between them set every field of every message in the subtree.

The output is the proto-JSON object the generated ``ErrorDetail`` model parses: proto
field names, enums by NAME. An enum number the table does not name stays a number, which
is what proto-JSON writes for it; the model then refuses it and the caller reads that
entry as carrying no detail, rather than one with a reason this SDK invented.

Decoding follows protobuf's own rules: unknown fields are skipped by wire type, a known
field arriving with the wrong wire type is skipped the same way, a repeated enum is
accepted packed or not, the last value of a singular field wins, a singular message field
written twice is merged, and of the reason oneof only the member written last is kept.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any

__all__ = ["ENUMS", "MESSAGES", "WireDecodeError", "decode_error_detail_value"]

#: The fully-qualified name of the root message.
_ROOT = "fora.v1.ErrorDetail"


class WireDecodeError(ValueError):
    """A ``value`` that is not a decodable ErrorDetail."""


@dataclass(frozen=True)
class Field:
    """One field of a message, as the descriptor states it."""

    name: str
    number: int
    #: The protobuf kind ("string", "enum", "message"), or "map".
    kind: str
    #: The fully-qualified enum or message name, for those kinds.
    type: str = ""
    repeated: bool = False
    map_key: str = ""
    map_value: str = ""


def _reason(number: int, name: str, message: str) -> Field:
    return Field(name, number, "message", f"fora.v1.{message}")


#: The ErrorDetail subtree's messages, fields in number order.
MESSAGES: dict[str, tuple[Field, ...]] = {
    "fora.v1.ErrorDetail": (
        Field("message", 1, "string"),
        Field("domain", 2, "string"),
        Field("metadata", 3, "map", map_key="string", map_value="string"),
        _reason(10, "transaction_denial", "TransactionDenial"),
        _reason(11, "catalog_rejection", "CatalogRejection"),
        _reason(12, "registration_failure", "RegistrationFailure"),
        _reason(13, "dispute_failure", "DisputeFailure"),
        _reason(14, "domain_verification_failure", "DomainVerificationFailure"),
        _reason(15, "retrieval_auth_failure", "RetrievalAuthFailure"),
        _reason(16, "usage_report_rejection", "UsageReportRejection"),
        _reason(17, "request_auth_failure", "RequestAuthFailure"),
    ),
    "fora.v1.TransactionDenial": (
        Field("reason", 1, "enum", "fora.v1.DenialReason"),
        Field("restriction_mismatches", 2, "enum", "fora.v1.RestrictionKind", repeated=True),
        Field("offer_id", 3, "string"),
        Field("exchange", 4, "string"),
    ),
    "fora.v1.CatalogRejection": (
        Field("reason", 1, "enum", "fora.v1.CatalogRejectionReason"),
        Field("rejected_paths", 2, "string", repeated=True),
    ),
    "fora.v1.RegistrationFailure": (
        Field("reason", 1, "enum", "fora.v1.RegistrationFailureReason"),
        Field("field_errors", 2, "message", "fora.v1.RegistrationFieldError", repeated=True),
    ),
    "fora.v1.RegistrationFieldError": (
        Field("path", 1, "string"),
        Field("error", 2, "string"),
    ),
    "fora.v1.DisputeFailure": (Field("reason", 1, "enum", "fora.v1.DisputeFailureReason"),),
    "fora.v1.DomainVerificationFailure": (
        Field("reason", 1, "enum", "fora.v1.DomainVerificationFailureReason"),
    ),
    "fora.v1.RetrievalAuthFailure": (
        Field("reason", 1, "enum", "fora.v1.RetrievalAuthFailureReason"),
    ),
    "fora.v1.UsageReportRejection": (
        Field("reason", 1, "enum", "fora.v1.UsageReportRejectionReason"),
    ),
    "fora.v1.RequestAuthFailure": (Field("reason", 1, "enum", "fora.v1.RequestAuthFailureReason"),),
}


def _names(prefix: str, *names: str) -> dict[int, str]:
    """An enum table whose values are numbered 0, 1, 2 ... in declaration order."""
    return {i: f"{prefix}_{n}" for i, n in enumerate(names)}


#: The enums the subtree uses: number -> value name.
ENUMS: dict[str, dict[int, str]] = {
    "fora.v1.DenialReason": _names(
        "DENIAL_REASON",
        "UNSPECIFIED",
        "ACCOUNT_INACTIVE",
        "INSUFFICIENT_BALANCE",
        "RATE_LIMITED",
        "CONTENT_UNAVAILABLE",
        "RESTRICTION_NOT_SATISFIED",
        "REPORTING_OVERDUE",
        "OFFER_EXPIRED",
        "SIGNATURE_INVALID",
        "QUOTA_EXCEEDED",
        "DELEGATION_INVALID",
        "SCOPE_INSUFFICIENT",
        "ENTITLEMENT_MISSING",
        "ENTITLEMENT_MALFORMED",
        "ENTITLEMENT_EXPIRED",
        "ENTITLEMENT_WRONG_BUYER",
        "SUBSCRIPTION_LAPSED",
        "ENTITLEMENT_NOT_GRANTED",
        "ACCOUNT_NOT_REGISTERED",
        "RELAY_NOT_ACCEPTED",
    ),
    "fora.v1.RestrictionKind": _names(
        "RESTRICTION_KIND", "UNSPECIFIED", "FUNCTION", "GEOGRAPHY", "USER_TYPE", "OTHER"
    ),
    "fora.v1.CatalogRejectionReason": _names(
        "CATALOG_REJECTION_REASON",
        "UNSPECIFIED",
        "NOT_CATALOG_CONTRIBUTOR",
        "TENANT_MISMATCH",
        "DOMAIN_NOT_VERIFIED",
        "SIGNATURE_INVALID",
        "MALFORMED_ENTRY",
        "UNKNOWN_VOCAB_TOKEN",
        "QUOTA_EXCEEDED",
        "TERMS_LIMIT_EXCEEDED",
        "URI_UNAVAILABLE",
    ),
    "fora.v1.RegistrationFailureReason": _names(
        "REGISTRATION_FAILURE_REASON",
        "UNSPECIFIED",
        "DOMAIN_NOT_VERIFIED",
        "INVALID_KEY",
        "SIGNATURE_INVALID",
        "ALREADY_REGISTERED",
        "QUOTA_EXCEEDED",
        "INVALID_REGISTRATION_DATA",
        "TERMS_DIGEST_STALE",
    ),
    "fora.v1.DisputeFailureReason": _names(
        "DISPUTE_FAILURE_REASON",
        "UNSPECIFIED",
        "TRANSACTION_NOT_FOUND",
        "REPORT_NOT_FILED",
        "WINDOW_EXPIRED",
        "DUPLICATE",
        "INELIGIBLE",
    ),
    "fora.v1.DomainVerificationFailureReason": _names(
        "DOMAIN_VERIFICATION_FAILURE_REASON",
        "UNSPECIFIED",
        "CHALLENGE_NOT_FOUND",
        "CHALLENGE_MISMATCH",
        "CHALLENGE_EXPIRED",
        "FETCH_FAILED",
        "EXCHANGE_NOT_AUTHORIZED",
        "KEY_REGISTRATION_FAILED",
    ),
    "fora.v1.RetrievalAuthFailureReason": _names(
        "RETRIEVAL_AUTH_FAILURE_REASON",
        "UNSPECIFIED",
        "URL_EXPIRED",
        "URL_SIGNATURE_MISSING",
        "URL_EXPIRY_MISSING",
        "URL_SIGNATURE_MISMATCH",
        "AGENT_KEY_MISSING",
        "PROOF_SIGNATURE_MISSING",
        "KEYID_MISMATCH",
        "THUMBPRINT_MISMATCH",
        "PROOF_CREATED_MISSING",
        "PROOF_EXPIRY_MISSING",
        "PROOF_EXPIRED",
        "PROOF_SIGNATURE_INVALID",
    ),
    "fora.v1.UsageReportRejectionReason": _names(
        "USAGE_REPORT_REJECTION_REASON",
        "UNSPECIFIED",
        "TRANSACTION_NOT_FOUND",
        "DUPLICATE",
        "WINDOW_EXPIRED",
        "MISSING_REQUIRED_FIELDS",
        "MALFORMED",
    ),
    "fora.v1.RequestAuthFailureReason": _names(
        "REQUEST_AUTH_FAILURE_REASON",
        "UNSPECIFIED",
        "SIGNATURE_MISSING",
        "SIGNATURE_INVALID",
        "SIGNATURE_STALE",
    ),
}

# Protobuf wire types.
_VARINT, _FIXED64, _LEN, _GROUP_START, _GROUP_END, _FIXED32 = 0, 1, 2, 3, 4, 5
_MAX_VARINT_BYTES = 10
_VARINT_PAYLOAD = 0x7F
_VARINT_MORE = 0x80
#: How deep a value may nest. The subtree nests three messages deep; the bound only
#: stops a hostile value from recursing.
_MAX_DEPTH = 8
_INT32_SIGN = 1 << 31
_UINT32 = 1 << 32
_UINT64_MASK = (1 << 64) - 1
#: The reason oneof of ErrorDetail: its message-typed fields, in number order. The reader's
#: errordetail.REASON_FIELDS walks the same members, and the suite holds the two equal.
REASON_ONEOF: tuple[str, ...] = tuple(f.name for f in MESSAGES[_ROOT] if f.kind == "message")


def decode_error_detail_value(value: str) -> dict[str, Any]:
    """Decode a ``details[].value`` string into ErrorDetail proto-JSON.

    The string is base64 in the standard or the URL alphabet, padded or not — connect-go
    writes the standard alphabet without padding. Raises :class:`WireDecodeError` for
    anything that is not a decodable ErrorDetail.
    """
    return decode_error_detail(_b64decode(value))


def decode_error_detail(raw: bytes) -> dict[str, Any]:
    """Decode binary ErrorDetail bytes into proto-JSON."""
    out: dict[str, Any] = {}
    order: list[str] = []
    _decode_message(memoryview(raw), _ROOT, out, order, 0)
    # The reason oneof: protobuf keeps the member written last and clears the others.
    written = [name for name in order if name in REASON_ONEOF]
    for name in REASON_ONEOF:
        if written and name != written[-1]:
            out.pop(name, None)
    return out


def _b64decode(value: str) -> bytes:
    text = value.strip().replace("-", "+").replace("_", "/")
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WireDecodeError("value is not base64") from exc


def _decode_message(
    buf: memoryview, message: str, out: dict[str, Any], order: list[str], depth: int
) -> None:
    if depth > _MAX_DEPTH:
        raise WireDecodeError("value nests too deep")
    fields = {f.number: f for f in MESSAGES[message]}
    pos = 0
    while pos < len(buf):
        key, pos = _varint(buf, pos)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise WireDecodeError("field number 0")
        start, pos = _skip(buf, pos, wire)
        field = fields.get(number)
        if field is None or not _wire_matches(field, wire):
            continue
        _apply(field, wire, buf[start:pos], out, depth)
        order.append(field.name)


def _wire_matches(field: Field, wire: int) -> bool:
    if field.kind == "enum":
        return wire == _VARINT or (field.repeated and wire == _LEN)
    return wire == _LEN


def _apply(field: Field, wire: int, payload: memoryview, out: dict[str, Any], depth: int) -> None:
    if field.kind == "enum":
        values = _packed_varints(payload) if wire == _LEN else [_varint(payload, 0)[0]]
        names = [_enum_name(field.type, v) for v in values]
        if field.repeated:
            out.setdefault(field.name, []).extend(names)
        elif names:
            out[field.name] = names[-1]
        return
    if field.kind == "string":
        text = _string(payload, field.name)
        if field.repeated:
            out.setdefault(field.name, []).append(text)
        else:
            out[field.name] = text
        return
    if field.kind == "map":
        key, value = _map_entry(payload, field)
        out.setdefault(field.name, {})[key] = value
        return
    if field.kind == "message":
        if field.repeated:
            item: dict[str, Any] = {}
            _decode_message(payload, field.type, item, [], depth + 1)
            out.setdefault(field.name, []).append(item)
        else:
            # A singular message written twice is merged into the first.
            target = out.setdefault(field.name, {})
            _decode_message(payload, field.type, target, [], depth + 1)
        return
    raise WireDecodeError(f"field kind {field.kind!r} is not in the ErrorDetail subtree")


def _map_entry(payload: memoryview, field: Field) -> tuple[str, str]:
    if field.map_key != "string" or field.map_value != "string":
        raise WireDecodeError("only map<string, string> is in the ErrorDetail subtree")
    key, value = "", ""
    pos = 0
    while pos < len(payload):
        tag, pos = _varint(payload, pos)
        number, wire = tag >> 3, tag & 7
        start, pos = _skip(payload, pos, wire)
        if wire != _LEN or number not in (1, 2):
            continue
        text = _string(payload[start:pos], field.name)
        if number == 1:
            key = text
        else:
            value = text
    return key, value


def _enum_name(enum: str, raw: int) -> str | int:
    number = raw & (_UINT32 - 1)
    if number >= _INT32_SIGN:
        number -= _UINT32
    return ENUMS[enum].get(number, number)


def _string(payload: memoryview, name: str) -> str:
    try:
        return bytes(payload).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WireDecodeError(f"{name} is not valid UTF-8") from exc


def _packed_varints(payload: memoryview) -> list[int]:
    values: list[int] = []
    pos = 0
    while pos < len(payload):
        value, pos = _varint(payload, pos)
        values.append(value)
    return values


def _varint(buf: memoryview, pos: int) -> tuple[int, int]:
    value = 0
    for i in range(_MAX_VARINT_BYTES):
        if pos >= len(buf):
            raise WireDecodeError("truncated varint")
        byte = buf[pos]
        pos += 1
        value |= (byte & _VARINT_PAYLOAD) << (7 * i)
        if not byte & _VARINT_MORE:
            return value & _UINT64_MASK, pos
    raise WireDecodeError("varint longer than ten bytes")


def _skip(buf: memoryview, pos: int, wire: int) -> tuple[int, int]:
    """Where one field's payload starts and ends, by its wire type.

    The start is past a length prefix, so a length-delimited payload is its content.
    """
    if wire == _VARINT:
        return pos, _varint(buf, pos)[1]
    if wire == _FIXED64:
        end = pos + 8
    elif wire == _FIXED32:
        end = pos + 4
    elif wire == _LEN:
        length, pos = _varint(buf, pos)
        end = pos + length
    else:
        # Groups are proto2 only; nothing in this contract encodes one.
        raise WireDecodeError(f"wire type {wire} is not decodable here")
    if end > len(buf):
        raise WireDecodeError("truncated field")
    return pos, end
