"""Strict decoding, and strict requests: refuse a message the contract does not describe.

``ClientConfig.strict`` turns it on for answers, ``ClientConfig.strict_requests`` for
requests. The check itself is :mod:`fora_sdk.strict`, the one the document readers and the
error-envelope check use too; this module only names the message a verb's generated model
describes and reports a refusal the way every other client failure is reported, as a
MALFORMED ``CallError``.
"""

from __future__ import annotations

from functools import cache
from typing import TYPE_CHECKING, Any

from wire import schemas

from fora_sdk.strict import strict_violation

from .errors import malformed

if TYPE_CHECKING:
    from pydantic import BaseModel


def refuse_unless_strict(op: str, model: type[BaseModel], payload: Any) -> None:
    """Refuse ``payload`` unless it is a ``model`` message the strict contract accepts.

    Raises the MALFORMED ``CallError`` naming the first failure: the path and the schema's
    complaint for an unknown field or a field-level rule, or the violated rule ids for a
    cross-field rule.
    """
    _refuse_unless_strict(op, model, payload, "strict decoding refused the answer")


def refuse_unless_strict_request(op: str, model: type[BaseModel], payload: Any) -> None:
    """Refuse an outgoing ``model`` request the strict contract does not accept, before it
    is signed (``ClientConfig.strict_requests``). The same check as an answer's, naming the
    first failure the same way: an unknown member by its path, so a misspelled key cannot
    reach the wire unnoticed."""
    _refuse_unless_strict(op, model, payload, "strict_requests refused the request")


def _refuse_unless_strict(op: str, model: type[BaseModel], payload: Any, lead: str) -> None:
    problem = strict_violation(_schema_name(model), payload)
    if problem is not None:
        raise malformed(op, f"{lead}{problem}")


@cache
def _schema_name(model: type[BaseModel]) -> str:
    """The fully-qualified message name whose published schema decodes ``model``.

    The generated models are one flat module across ``fora.v1`` and ``fora.admin.v1``, so
    the class name is matched against the schema names. A class name two packages share is
    refused rather than resolved by accident.
    """
    found = [n for n in schemas.names() if n.rsplit(".", 1)[-1] == model.__name__]
    if len(found) == 1:
        return found[0]
    if found:
        raise LookupError(f"several published schemas match {model.__name__}: {found}")
    raise LookupError(f"no published schema for {model.__name__}")
