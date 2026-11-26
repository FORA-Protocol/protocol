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

import ast
from pathlib import Path
from typing import Any

import pytest
from conftest import GO_TESTDATA, load_json
from wire import version as generated_version

# RED: sdk/python/fora_sdk/wire.py does not exist yet (TDD red — missing face).
from fora_sdk import wire
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
def test_wire_constant_matches_go_oracle(vector: dict[str, Any]) -> None:
    if vector["name"] in _RENDERED:
        assert _RENDERED[vector["name"]]() == vector["value"]
        return
    attr = _ATTR_FOR[vector["name"]]
    assert getattr(wire, attr) == vector["value"]


# The SDK's two version names and the generated constants they re-export.
_VERSION_EXPORTS = (
    ("ProtocolVersion", "PROTOCOL_VERSION"),
    ("WellKnownManifestVersion", "WELL_KNOWN_MANIFEST_VERSION"),
)


def _binding(source: str, name: str) -> ast.expr | None:
    """Return the expression a module-level assignment in source binds name to."""
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return node.value
        if (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            return node.value
    return None


def _re_exports(value: ast.expr | None, generated: str) -> bool:
    """Return whether value reads the generated constant rather than spelling a literal."""
    return isinstance(value, ast.Attribute) and value.attr == generated


@pytest.mark.parametrize(("name", "generated"), _VERSION_EXPORTS)
def test_version_constants_re_export_the_generated_values(name: str, generated: str) -> None:
    source = Path(wire.__file__).read_text(encoding="utf-8")
    assert _re_exports(_binding(source, name), generated), (
        f"fora_sdk/wire.py must bind {name} to wire.version.{generated}, not a value of its own"
    )
    assert getattr(wire, name) == getattr(generated_version, generated)


def test_version_re_export_check_flags_a_literal() -> None:
    literal = _binding('ProtocolVersion = "1.0"\n', "ProtocolVersion")
    assert not _re_exports(literal, "PROTOCOL_VERSION")
    re_export = _binding("ProtocolVersion = _version.PROTOCOL_VERSION\n", "ProtocolVersion")
    assert _re_exports(re_export, "PROTOCOL_VERSION")
