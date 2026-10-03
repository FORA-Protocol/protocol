"""Strict response decoding: refuse an answer the contract does not describe.

``ClientConfig.strict`` turns this on. The check itself is :mod:`fora_sdk.strict`, the
one the document readers and the error-envelope check use too; this module only names
the message a verb's generated model decodes and reports a refusal the way every other
answer failure is reported, as a MALFORMED ``CallError``.
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
    problem = strict_violation(_schema_name(model), payload)
    if problem is not None:
        raise malformed(op, f"strict decoding refused the answer{problem}")


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
