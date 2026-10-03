"""The published JSON Schemas for the FORA wire messages, shipped as package data.

One self-contained draft 2020-12 schema per message of the wire contract, named by the
fully-qualified message name, in two variants:

- default (``strict=False``): unknown fields are accepted, as the generated models do;
- strict (``strict=True``): ``additionalProperties: false`` on every message object at
  every depth, so an unknown or misspelled field fails. A conformance check uses this
  variant. ``google.protobuf.Struct`` fields (``ext``) stay open in both.

Both describe canonical proto-JSON as the FORA wire carries it: snake_case proto field
names, 64-bit integers as a decimal string or a JSON integer, and the per-field
``buf.validate`` constraints. Cross-field rules are not in the schemas.

Hand-written: the schemas are generated into ``gen/jsonschema/`` by
``scripts/gen-sdk-types.sh``, and this module only reads them. It needs no validator;
pass the returned schema to one, for example ``jsonschema``::

    from jsonschema import Draft202012Validator
    from wire import schemas

    Draft202012Validator(schemas.load("fora.v1.ResourceResponse", strict=True)).validate(body)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

__all__ = ["load", "names"]

_DIR = Path(__file__).resolve().parent / "jsonschema"
_DEFAULT = ".schema.json"
_STRICT = ".schema.strict.json"


def names() -> List[str]:
    """The fully-qualified names of every message with a published schema, sorted."""
    return sorted(p.name[: -len(_DEFAULT)] for p in _DIR.glob("*" + _DEFAULT))


def load(name: str, *, strict: bool = False) -> Dict[str, Any]:
    """The schema of the message ``name`` (for example ``"fora.v1.ResourceResponse"``).

    ``strict=True`` selects the variant that refuses unknown fields. Each call returns a
    fresh dict, so a caller may modify it. An unknown name raises ``KeyError``.
    """
    if name not in names():
        raise KeyError(f"no published JSON Schema for message {name!r}")
    path = _DIR / (name + (_STRICT if strict else _DEFAULT))
    schema: Dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return schema
