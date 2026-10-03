"""Strict decoding of an error answer: the Connect envelope, and every ErrorDetail in it.

A lenient reader takes what it can from a Connect error: it ignores a member it does not
know, and skips a detail that does not decode. Under ``ClientConfig.strict`` both are
findings, so the envelope is checked before it is read. The checks are the ones the Go and
TypeScript clients make, so one envelope gets one verdict in all three:

- a JSON error body is an object whose members are ``code``, ``message`` and ``details``,
  and nothing else. A ``null`` member reads as absent, as proto-JSON reads it;
- ``code`` is present and is one of the sixteen Connect codes; ``message`` is a string;
- ``details`` is an array of objects whose members are ``type``, ``value`` and ``debug``.
  ``type`` is a non-empty string, ``value`` is base64 (standard or URL alphabet, padded or
  not), and an entry carries a ``value``, a ``debug`` projection or both;
- for an entry of type ``fora.v1.ErrorDetail``, the ``value`` decodes as an ErrorDetail
  with no field the contract does not define, and so does the ``debug`` projection when
  present; each then passes the published strict ErrorDetail schema and the cross-field
  rules, and sets at most one member of the reason oneof.

A body that is empty or not JSON is not an envelope: it is a gateway or a proxy answering
for the service, and its status classifies it in either mode. The caller decides that
before it gets here.
"""

from __future__ import annotations

from typing import Any

from fora_sdk._errordetail_wire import WireDecodeError, _b64decode, decode_error_detail_value
from fora_sdk.errordetail import ERROR_DETAIL_TYPE, REASON_FIELDS, _proto_names, _TooDeepError
from fora_sdk.strict import strict_violation

from .errors import CallError, CallErrorKind

#: The members the Connect protocol defines for an error envelope and for a details entry.
_ENVELOPE_MEMBERS = frozenset({"code", "message", "details"})
_ENTRY_MEMBERS = frozenset({"type", "value", "debug"})

#: The codes a Connect error envelope may name.
CONNECT_CODES = frozenset(
    {
        "canceled",
        "unknown",
        "invalid_argument",
        "deadline_exceeded",
        "not_found",
        "already_exists",
        "permission_denied",
        "resource_exhausted",
        "failed_precondition",
        "aborted",
        "out_of_range",
        "unimplemented",
        "internal",
        "unavailable",
        "data_loss",
        "unauthenticated",
    }
)


def check_strict_envelope(op: str, status: int, payload: Any, code: str | None) -> None:
    """Refuse an error answer whose envelope the strict contract does not accept.

    Raises the MALFORMED ``CallError`` naming the first failure. It keeps ``status`` and
    ``code``, the Connect code the lenient read reports, and carries no detail: the detail
    is part of what was refused.
    """
    problem = envelope_violation(payload)
    if problem is not None:
        raise CallError(
            CallErrorKind.MALFORMED,
            op,
            status=status,
            cause=f"strict decoding refused the error answer: {problem}",
            code=code,
        )


def envelope_violation(payload: Any) -> str | None:
    """Why ``payload`` is not a Connect error envelope the contract accepts, or ``None``."""
    if not isinstance(payload, dict):
        return "error body is JSON but not a Connect error envelope object"
    name = _first_unknown(payload, _ENVELOPE_MEMBERS)
    if name is not None:
        return f"error envelope carries {name!r}, a member the Connect protocol does not define"
    return _code_violation(payload) or _message_violation(payload) or _details_violation(payload)


def _code_violation(envelope: dict[str, Any]) -> str | None:
    code = envelope.get("code")
    if code is None:
        return "error envelope names no code"
    if not isinstance(code, str):
        return "error envelope code is not a string"
    if code not in CONNECT_CODES:
        return f"error envelope code {code!r} is not a Connect code"
    return None


def _message_violation(envelope: dict[str, Any]) -> str | None:
    message = envelope.get("message")
    if message is not None and not isinstance(message, str):
        return "error envelope message is not a string"
    return None


def _details_violation(envelope: dict[str, Any]) -> str | None:
    details = envelope.get("details")
    if details is None:
        return None
    if not isinstance(details, list):
        return "error envelope details is not an array"
    for i, entry in enumerate(details):
        problem = _entry_violation(i, entry)
        if problem is not None:
            return problem
    return None


def _entry_violation(i: int, entry: Any) -> str | None:
    if not isinstance(entry, dict):
        return f"details[{i}] is not an object"
    problem = _entry_shape_violation(i, entry)
    if problem is not None or entry["type"] != ERROR_DETAIL_TYPE:
        return problem
    return _value_violation(i, entry.get("value")) or _debug_violation(i, entry.get("debug"))


def _entry_shape_violation(i: int, entry: dict[str, Any]) -> str | None:
    """The entry's own members, whatever type of detail it carries."""
    name = _first_unknown(entry, _ENTRY_MEMBERS)
    if name is not None:
        return f"details[{i}] carries {name!r}, a member the Connect protocol does not define"
    kind = entry.get("type")
    if not isinstance(kind, str) or not kind:
        return f"details[{i}] names no type"
    value, debug = entry.get("value"), entry.get("debug")
    if value is not None and not _is_base64(value):
        return f"details[{i}].value is not base64"
    if value is None and debug is None:
        return f"details[{i}] carries neither a value nor a debug projection"
    return None


def _is_base64(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        _b64decode(value)
    except WireDecodeError:
        return False
    return True


def _value_violation(i: int, value: str | None) -> str | None:
    """The binary ErrorDetail: it decodes, defines every field it carries, and passes."""
    if value is None:
        return None
    unknown: list[str] = []
    try:
        decoded = decode_error_detail_value(value, unknown)
    except WireDecodeError:
        return f"details[{i}].value does not decode as {ERROR_DETAIL_TYPE}"
    if unknown:
        return f"details[{i}].value carries a field the contract does not define ({unknown[0]})"
    problem = _detail_violation(decoded)
    return None if problem is None else f"details[{i}].value{problem}"


def _debug_violation(i: int, debug: Any) -> str | None:
    """The debug projection, read under the proto field names like the lenient reader."""
    if debug is None:
        return None
    if not isinstance(debug, dict):
        return f"details[{i}].debug is not an object"
    try:
        normalized = _proto_names(debug)
    except _TooDeepError:
        return f"details[{i}].debug nests too deep"
    problem = _detail_violation(normalized)
    return None if problem is None else f"details[{i}].debug{problem}"


def _detail_violation(detail: dict[str, Any]) -> str | None:
    """An ErrorDetail as proto-JSON: one reason at most, then the strict schema and rules.

    The schemas do not express oneof exclusivity, so it is checked here; a proto-JSON
    parser refuses the same object.
    """
    reasons = [name for name in REASON_FIELDS if detail.get(name) is not None]
    if len(reasons) > 1:
        return f" sets more than one member of the reason oneof: {', '.join(reasons)}"
    return strict_violation(ERROR_DETAIL_TYPE, detail)


def _first_unknown(obj: dict[str, Any], known: frozenset[str]) -> str | None:
    """The first member, in sorted order, that ``known`` does not name."""
    names = sorted(str(name) for name in obj if name not in known)
    return names[0] if names else None
