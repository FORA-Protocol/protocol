"""``fora_sdk.testing``: acceptance signers that admit an empty requester.

They must reproduce byte for byte what the shared corpora record for "a signer without the
check", answer exactly as the signers they twin for every other input, produce nothing the
SDK's verifiers accept, and stay out of the SDK: not re-exported from the root, and imported
by no module of it.
"""

from __future__ import annotations

import ast
import base64
import pathlib
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import fora_sdk
from conftest import GO_TESTDATA, load_json
from fora_sdk import testing
from fora_sdk.core import (
    jcs_acceptance_payload,
    jcs_request_acceptance_payload,
    sign_offer_acceptance_jcs,
    sign_request_acceptance_jcs,
    verify_offer_acceptance_jcs,
    verify_request_acceptance_jcs,
)

_OFFER = load_json(GO_TESTDATA / "acceptance-vectors.json")
_REQUEST = load_json(GO_TESTDATA / "request-acceptance-vectors.json")


def _requester(row: dict[str, Any]) -> dict[str, str]:
    return {
        "requester_id": row["requester_id"],
        "requester_domain": row["requester_domain"],
        "idempotency_key": row["idempotency_key"],
    }


def _offer_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {"offer_sig": row["offer_sig"], **_requester(row)}


def _request_fields(row: dict[str, Any]) -> dict[str, Any]:
    return {"items": [(i["offer_sig"], i["exchange"]) for i in row["items"]], **_requester(row)}


def _assert_the_recorded_signature_verifies(row: dict[str, Any], payload: bytes) -> None:
    """The row's signature verifies over its bytes, so a refusal of them is a refusal of
    the requester alone. Raises InvalidSignature otherwise."""
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(row["pubkey_b64"]))
    public.verify(bytes.fromhex(row["signature_hex"]), payload)


@pytest.mark.parametrize("row", _OFFER["refused"], ids=[r["name"] for r in _OFFER["refused"]])
def test_a_refused_offer_acceptance_is_reproduced(row: dict[str, Any]) -> None:
    fields = _offer_fields(row)
    payload = testing.jcs_acceptance_payload_any_requester(**fields)
    signed = testing.sign_offer_acceptance_any_requester(
        seed=bytes.fromhex(row["seed_hex"]), **fields
    )

    assert payload == row["canonical_jcs"].encode()
    assert signed == (row["signature_hex"], "EdDSA")
    _assert_the_recorded_signature_verifies(row, payload)
    # The protocol's own canonicalizer and verifier refuse the same bytes.
    with pytest.raises(ValueError, match="empty requester"):
        jcs_acceptance_payload(**fields)
    with pytest.raises(ValueError, match="empty requester"):
        verify_offer_acceptance_jcs(
            pubkey_b64=row["pubkey_b64"], signature_hex=row["signature_hex"], **fields
        )


@pytest.mark.parametrize("row", _REQUEST["refused"], ids=[r["name"] for r in _REQUEST["refused"]])
def test_a_refused_request_acceptance_is_reproduced(row: dict[str, Any]) -> None:
    fields = _request_fields(row)
    payload = testing.jcs_request_acceptance_payload_any_requester(**fields)
    signed = testing.sign_request_acceptance_any_requester(
        seed=bytes.fromhex(row["seed_hex"]), **fields
    )

    assert payload == row["canonical_jcs"].encode()
    assert signed == (row["signature_hex"], "EdDSA")
    _assert_the_recorded_signature_verifies(row, payload)
    with pytest.raises(ValueError, match="empty requester"):
        jcs_request_acceptance_payload(**fields)
    assert not verify_request_acceptance_jcs(
        pubkey_b64=row["pubkey_b64"], signature_hex=row["signature_hex"], **fields
    )


def test_the_refused_rows_cover_both_requester_fields() -> None:
    for doc in (_OFFER, _REQUEST):
        assert {row["empty"] for row in doc["refused"]} == {"requester_id", "requester_domain"}


@pytest.mark.parametrize("row", _OFFER["vectors"], ids=[r["name"] for r in _OFFER["vectors"]])
def test_the_offer_twins_are_the_signers_on_a_named_requester(row: dict[str, Any]) -> None:
    fields = _offer_fields(row)
    seed = bytes.fromhex(row["seed_hex"])

    assert testing.jcs_acceptance_payload_any_requester(**fields) == (
        jcs_acceptance_payload(**fields)
    )
    assert testing.sign_offer_acceptance_any_requester(seed=seed, **fields) == (
        sign_offer_acceptance_jcs(seed=seed, **fields)
    )


@pytest.mark.parametrize("row", _REQUEST["vectors"], ids=[r["name"] for r in _REQUEST["vectors"]])
def test_the_request_twins_are_the_signers_on_a_named_requester(row: dict[str, Any]) -> None:
    fields = _request_fields(row)
    seed = bytes.fromhex(row["seed_hex"])

    assert testing.jcs_request_acceptance_payload_any_requester(**fields) == (
        jcs_request_acceptance_payload(**fields)
    )
    assert testing.sign_request_acceptance_any_requester(seed=seed, **fields) == (
        sign_request_acceptance_jcs(seed=seed, **fields)
    )


_NAMED = {"requester_id": "agent-1", "requester_domain": "agent.example", "idempotency_key": "i"}


@pytest.mark.parametrize(
    "fields",
    [
        {**_NAMED, "offer_sig": ""},
        # An unsigned offer is refused before the requester is looked at, by both.
        {**_NAMED, "offer_sig": "", "requester_id": ""},
    ],
)
def test_every_other_offer_refusal_is_the_signers(fields: dict[str, Any]) -> None:
    with pytest.raises(ValueError) as signer:
        jcs_acceptance_payload(**fields)
    with pytest.raises(ValueError) as twin:
        testing.jcs_acceptance_payload_any_requester(**fields)
    assert str(twin.value) == str(signer.value)


@pytest.mark.parametrize(
    ("items", "requester"),
    [
        ([], _NAMED),
        ([("", "one.example")], _NAMED),
        ([("sig", "")], _NAMED),
        ([("sig", "one.example"), ("", "")], _NAMED),
    ],
)
def test_every_other_request_refusal_is_the_signers(
    items: list[tuple[str, str]], requester: dict[str, str]
) -> None:
    with pytest.raises(ValueError) as signer:
        jcs_request_acceptance_payload(items=items, **requester)
    with pytest.raises(ValueError) as twin:
        testing.jcs_request_acceptance_payload_any_requester(items=items, **requester)
    assert str(twin.value) == str(signer.value)


def test_past_an_empty_requester_the_next_refusal_is_the_signers_next() -> None:
    no_id = {**_NAMED, "requester_id": ""}
    with pytest.raises(ValueError, match=r"^request acceptance requires at least one item$"):
        testing.jcs_request_acceptance_payload_any_requester(items=[], **no_id)


def test_the_module_is_not_on_the_root() -> None:
    for name in testing.__all__:
        assert name not in fora_sdk.__all__
        assert not hasattr(fora_sdk, name)


def _imported_modules(path: pathlib.Path, package: str) -> set[str]:
    """Every module ``path`` imports, relative imports resolved against ``package``."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                base = ".".join(parts[: len(parts) - node.level + 1])
                module = f"{base}.{node.module}" if node.module else base
            else:
                module = node.module or ""
            found.add(module)
            found.update(f"{module}.{alias.name}" for alias in node.names)
    return found


def test_no_module_of_the_sdk_imports_it() -> None:
    root = pathlib.Path(fora_sdk.__file__).parent
    for path in root.rglob("*.py"):
        if path.name == "testing.py" and path.parent == root:
            continue
        package = ".".join(("fora_sdk", *path.parent.relative_to(root).parts))
        imported = _imported_modules(path, package)
        assert "fora_sdk.testing" not in imported, f"{path} imports fora_sdk.testing"
