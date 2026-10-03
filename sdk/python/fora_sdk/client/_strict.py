"""Strict response decoding: refuse an answer the contract does not describe.

The generated models are forward-compatible on purpose. They ignore a field they do not
know, because a peer on a newer minor version may send one, and they carry only the
field-level rules. A conformance check wants the opposite: an unknown or misspelled field
is a finding, and so is an answer that breaks one of the cross-field rules the proto
states. ``ClientConfig.strict`` turns that on, and this module is the whole of it.

It defines no shape of its own. The unknown-field policy and the field-level rules come
from the published strict JSON Schema of the response message
(``wire.schemas.load(name, strict=True)``, generated from the proto), and the cross-field
rules from :mod:`fora_sdk.crossfield`, the transcription of the proto's message-level CEL
the SDK already ships. The schema also tells the walk below which objects are which
message, so it never guesses.

One thing is normalized first. A FORA server renders proto-JSON with unpopulated fields
emitted, so an unset message field arrives as ``null``, and proto-JSON reads a ``null`` as
the field's default. The schemas describe values, not that rule, so a ``null`` member of a
message object is removed before validation — never one inside a
``google.protobuf.Struct`` or ``Value``, where ``null`` is data.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator
from wire import schemas

from fora_sdk.crossfield import _RULES_BY_MESSAGE, cross_field_rule_ids

from .errors import malformed

if TYPE_CHECKING:
    from pydantic import BaseModel

#: The prefix a schema's ``$ref`` carries before a message's fully-qualified name.
_DEFS_REF = "#/$defs/"
#: The package the cross-field rules are transcribed from.
_RULE_PACKAGE = "fora.v1."


def check_strict(op: str, model: type[BaseModel], payload: Any) -> None:
    """Refuse ``payload`` unless it is a ``model`` message the strict contract accepts.

    Raises the MALFORMED ``CallError`` naming the first failure: the path and the schema's
    complaint for an unknown field or a field-level rule, or the violated rule ids for a
    cross-field rule.
    """
    name = _schema_name(model)
    schema = schemas.load(name, strict=True)
    normalized = _without_nulls(schema, schema, payload)
    errors = sorted(_validator(name).iter_errors(normalized), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        where = "/" + "/".join(str(p) for p in first.path)
        raise malformed(op, f"strict decoding refused the answer at {where}: {first.message}")
    violated: list[str] = []
    _walk(schema, schema, normalized, name, violated)
    if violated:
        raise malformed(
            op, f"strict decoding refused the answer: cross-field rule(s) {', '.join(violated)}"
        )


@cache
def _schema_name(model: type[BaseModel]) -> str:
    """The fully-qualified message name whose published schema decodes ``model``.

    The generated models are one flat module across ``fora.v1`` and ``fora.admin.v1``, so
    the class name is matched against the schema names, walking up from a subclass such
    as ``ExecuteResult`` to the generated model it extends. A class name two packages
    share is refused rather than resolved by accident.
    """
    names = schemas.names()
    for cls in model.__mro__:
        found = [n for n in names if n.rsplit(".", 1)[-1] == cls.__name__]
        if len(found) == 1:
            return found[0]
        if found:
            raise LookupError(f"several published schemas match {cls.__name__}: {found}")
    raise LookupError(f"no published schema for {model.__name__}")


@cache
def _validator(name: str) -> Draft202012Validator:
    return Draft202012Validator(schemas.load(name, strict=True))


def _resolve(root: dict[str, Any], node: Any) -> tuple[dict[str, Any], str | None]:
    """Follow a ``$ref`` into ``$defs``; return the node and the message name it names."""
    if isinstance(node, dict) and isinstance(node.get("$ref"), str):
        ref: str = node["$ref"]
        if ref.startswith(_DEFS_REF):
            name = ref[len(_DEFS_REF) :]
            target = root.get("$defs", {}).get(name)
            if isinstance(target, dict):
                return target, name
    return (node if isinstance(node, dict) else {}), None


def _is_message(node: dict[str, Any]) -> bool:
    """A message object: closed properties. A Struct is an open ``{"type": "object"}``."""
    return isinstance(node.get("properties"), dict)


def _without_nulls(root: dict[str, Any], node: Any, value: Any) -> Any:
    """A copy of ``value`` with the ``null`` members of every message object removed."""
    node, _ = _resolve(root, node)
    if isinstance(value, dict):
        if _is_message(node):
            props: dict[str, Any] = node["properties"]
            return {
                k: _without_nulls(root, props.get(k, {}), v)
                for k, v in value.items()
                if not (v is None and _null_means_absent(root, props.get(k)))
            }
        extra = node.get("additionalProperties")
        if isinstance(extra, dict):
            return {k: _without_nulls(root, extra, v) for k, v in value.items()}
        return value
    if isinstance(value, list):
        items = node.get("items", {})
        return [_without_nulls(root, items, v) for v in value]
    return value


def _null_means_absent(root: dict[str, Any], prop: Any) -> bool:
    """Whether ``null`` is the absence of this field rather than a value of it.

    A field the schema does not declare is left for the validator to refuse, and a
    ``google.protobuf.Value`` (a schema with no ``type``) admits ``null`` as data.
    """
    if prop is None:
        return False
    node, _ = _resolve(root, prop)
    return "type" in node or "anyOf" in node or "$ref" in prop


def _walk(
    root: dict[str, Any], node: Any, value: Any, message: str | None, violated: list[str]
) -> None:
    """Apply the cross-field rules to every message object the schema identifies."""
    node, named = _resolve(root, node)
    message = named or message
    if isinstance(value, dict) and _is_message(node):
        if message is not None and message.startswith(_RULE_PACKAGE):
            short = message[len(_RULE_PACKAGE) :]
            if short in _RULES_BY_MESSAGE:
                violated.extend(cross_field_rule_ids(short, value))
        props: dict[str, Any] = node["properties"]
        for key, child in value.items():
            if key in props:
                _walk(root, props[key], child, None, violated)
    elif isinstance(value, dict) and isinstance(node.get("additionalProperties"), dict):
        for child in value.values():
            _walk(root, node["additionalProperties"], child, None, violated)
    elif isinstance(value, list):
        for child in value:
            _walk(root, node.get("items", {}), child, None, violated)
