"""Scope-matching parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/scope-match.parity.test.ts.

``fora_sdk.scopes.scope_covers``/``scopes_cover``/``scopes_subset`` MUST give the
verdicts in sdk/go/helpers/testdata/scope-match-vectors.json, which is written
by hand from the protocol's segment-wise scope-matching rule (Requester.scopes),
not emitted by an implementation:
  - covers:     {granted:str, required:str, expected:bool}
  - cover_sets: {granted:[str], required:[str], expected:bool}; the same row
                also pins scopes_subset(required, granted).
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

from fora_sdk.scopes import scope_covers, scopes_cover, scopes_subset

_VECTORS = load_json(GO_TESTDATA / "scope-match-vectors.json")
_COVERS = _VECTORS["covers"]
_COVER_SETS = _VECTORS["cover_sets"]


@pytest.mark.parametrize("vector", _COVERS, ids=[v["name"] for v in _COVERS])
def test_scope_covers_matches_rule(vector: dict) -> None:
    assert scope_covers(vector["granted"], vector["required"]) is vector["expected"]


@pytest.mark.parametrize("vector", _COVER_SETS, ids=[v["name"] for v in _COVER_SETS])
def test_scopes_cover_matches_rule(vector: dict) -> None:
    granted = list(vector["granted"])
    required = list(vector["required"])
    assert scopes_cover(granted, required) is vector["expected"]
    assert scopes_subset(required, granted) is vector["expected"]
