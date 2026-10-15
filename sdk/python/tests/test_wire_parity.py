"""Wire-constants parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/wire.parity.test.ts.

``fora_sdk.wire`` MUST expose the wire constants with the EXACT values the
sdk/go oracle carries, and ``fora_sdk.wba.accept_signature`` MUST render the two
Accept-Signature values the oracle records (without and with the entitlement
token). The shared vectors at
sdk/go/helpers/testdata/wire-constants-vectors.json carry {name, value},
referenced from the real Go exported constants (never hand-typed). The Go layer
splits RequestIDHeader across helpers/constants.go and core/requestid.go; the
single Python wire module exposes all eight once.

RED now purely because ``fora_sdk.wire`` does not exist yet.
"""

from __future__ import annotations

import pytest

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/fora_sdk/wire.py does not exist yet (TDD red — missing face).
from fora_sdk import wire  # type: ignore[import-not-found]
from fora_sdk.wba import accept_signature

_VECTORS = load_json(GO_TESTDATA / "wire-constants-vectors.json")["vectors"]

# Go identifier → the attribute the Python wire module must expose (same name).
_ATTR_FOR = {
    "ContentTypeProto": "ContentTypeProto",
    "ContentTypeJSON": "ContentTypeJSON",
    "ConnectProtocolVersionHeader": "ConnectProtocolVersionHeader",
    "ConnectProtocolVersion": "ConnectProtocolVersion",
    "ProtocolVersion": "ProtocolVersion",
    "WellKnownManifestVersion": "WellKnownManifestVersion",
    "RequestIDHeader": "RequestIDHeader",
    "SignatureAgentHeader": "SignatureAgentHeader",
    "AgentKeyHeader": "AgentKeyHeader",
    "WellKnownPath": "WellKnownPath",
    "ContentRulesHeader": "ContentRulesHeader",
    "ExchangeHeader": "ExchangeHeader",
    "WBATag": "WBATag",
    "DirectoryResponseTag": "DirectoryResponseTag",
    "AcceptSignatureHeader": "AcceptSignatureHeader",
}

# Go values the Python surface renders through a function rather than a constant.
_RENDERED = {
    "AcceptSignature": lambda: accept_signature(False),
    "AcceptSignatureWithEntitlement": lambda: accept_signature(True),
}


def test_wire_vector_set_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_wire_constant_matches_go_oracle(vector: dict) -> None:
    if vector["name"] in _RENDERED:
        assert _RENDERED[vector["name"]]() == vector["value"]
        return
    attr = _ATTR_FOR[vector["name"]]
    assert getattr(wire, attr) == vector["value"]
