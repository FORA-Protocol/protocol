"""fora_sdk.pop.sign_agent_binding — the delivery proof's sign face — and its refusals.

The sign oracle is the pop-vectors.json 'valid' vector: it carries signer_seed_hex,
agent_directory and nonce, so the sign face re-signs the same inputs and byte-compares
the four header values against the stored ones (Ed25519 is deterministic).
"""

from __future__ import annotations

import re

import pytest

from conftest import GO_TESTDATA, load_json

from fora_sdk.pop import AGENT_KEY_HEADER, sign_agent_binding, verify_agent_binding
from fora_sdk.wba import (
    InvalidNonceError,
    SignatureAgentNotOriginError,
    SignatureAgentRequiredError,
    SignatureLifetimeError,
)

_POP_VECTORS = load_json(GO_TESTDATA / "pop-vectors.json")
_DIRECTORY = "https://agent.example"


def _valid_vector() -> dict[str, object]:
    """Return the 'valid' pop vector (expected_valid=True, with a nonce)."""
    for v in _POP_VECTORS:
        if v["name"] == "valid":
            return v  # type: ignore[no-any-return]
    raise KeyError("no valid pop vector found")


def _seed_of(v: dict[str, object]) -> bytes:
    """The raw Ed25519 seed that produced the vector's signature."""
    return bytes.fromhex(str(v["signer_seed_hex"]))


def _parse_created_expires(signature_input: str) -> tuple[int, int]:
    """Extract the created and expires integers from a Signature-Input string."""
    created_m = re.search(r";created=(\d+)", signature_input)
    expires_m = re.search(r";expires=(\d+)", signature_input)
    assert created_m is not None, "no created in signature_input"
    assert expires_m is not None, "no expires in signature_input"
    return int(created_m.group(1)), int(expires_m.group(1))


def _sign_valid(**overrides: object) -> object:
    v = _valid_vector()
    created, expires = _parse_created_expires(str(v["signature_input"]))
    kwargs: dict[str, object] = {
        "url": str(v["url"]),
        "signer_seed": _seed_of(v),
        "created": created,
        "expires": expires,
        "signature_agent": str(v["agent_directory"]),
        "nonce": str(v["nonce"]),
    }
    kwargs.update(overrides)
    return sign_agent_binding(**kwargs)  # type: ignore[arg-type]


# ---- (a) sign vs oracle ---------------------------------------------------


def test_sign_agent_binding_matches_go_oracle() -> None:
    """The oracle seed, directory and nonce reproduce the four stored values."""
    v = _valid_vector()
    binding = _sign_valid()
    assert binding.agent_key == str(v["presented_key_b64url"])  # type: ignore[attr-defined]
    assert binding.signature_agent == str(v["signature_agent"])  # type: ignore[attr-defined]
    assert binding.signature_input == str(v["signature_input"])  # type: ignore[attr-defined]
    assert binding.signature == str(v["signature"])  # type: ignore[attr-defined]


def test_the_binding_headers_are_the_four_the_edge_reads() -> None:
    binding = _sign_valid()
    assert binding.headers() == {  # type: ignore[attr-defined]
        AGENT_KEY_HEADER: binding.agent_key,  # type: ignore[attr-defined]
        "signature-agent": binding.signature_agent,  # type: ignore[attr-defined]
        "signature-input": binding.signature_input,  # type: ignore[attr-defined]
        "signature": binding.signature,  # type: ignore[attr-defined]
    }


# ---- (b) round-trip through verify_agent_binding -------------------------


def test_sign_then_verify_round_trips() -> None:
    """Signing then verifying within the window succeeds and names the directory."""
    v = _valid_vector()
    created, _ = _parse_created_expires(str(v["signature_input"]))
    binding = _sign_valid()
    result = verify_agent_binding(
        method="GET",
        url=str(v["url"]),
        headers=binding.headers(),  # type: ignore[attr-defined]
        agent_id=str(v["agent_id"]),
        now=created + 1,
    )
    assert result.ok is True, f"verify rejected a freshly-signed proof: {result.reason}"
    assert result.signature_agent == str(v["agent_directory"])


def test_sign_agent_binding_rejects_when_expired() -> None:
    """verify_agent_binding rejects a valid signature once now reaches expires."""
    v = _valid_vector()
    _, expires = _parse_created_expires(str(v["signature_input"]))
    binding = _sign_valid()
    result = verify_agent_binding(
        method="GET",
        url=str(v["url"]),
        headers=binding.headers(),  # type: ignore[attr-defined]
        agent_id=str(v["agent_id"]),
        now=expires + 1,
    )
    assert result.ok is False
    assert result.reason == "pop_expired"


def test_a_proof_whose_member_was_repointed_does_not_verify() -> None:
    """The member is covered: moving it to another directory breaks the signature."""
    v = _valid_vector()
    created, _ = _parse_created_expires(str(v["signature_input"]))
    headers = _sign_valid().headers()  # type: ignore[attr-defined]
    headers["signature-agent"] = 'sig1="https://evil.example"'
    result = verify_agent_binding(
        method="GET",
        url=str(v["url"]),
        headers=headers,
        agent_id=str(v["agent_id"]),
        now=created + 1,
    )
    assert result.ok is False
    assert result.reason == "pop_sig_invalid"


# ---- top-level re-export -------------------------------------------------


def test_sign_agent_binding_in_fora_sdk_all() -> None:
    """fora_sdk.__all__ includes sign_agent_binding."""
    import fora_sdk

    assert "sign_agent_binding" in fora_sdk.__all__


# ---- refusals before anything is signed ----------------------------------


@pytest.mark.parametrize(
    "url",
    [
        'https://cdn.test/a\n"@authority": evil.test',
        "https://cdn.test/a\r",
        "https://cdn.test/a\x00",
        "https://cdn.test/a\x7f",
    ],
    ids=["newline", "carriage_return", "nul", "delete"],
)
def test_sign_agent_binding_refuses_control_bytes_in_the_url(url: str) -> None:
    """A control byte in the URL must be refused, not signed.

    The signature base is line-delimited and the URL is written into it verbatim,
    so a newline would add or split a component line and the signed bytes would
    stop describing the request a verifier reconstructs. Mirrors the Go signer's
    refusal (helpers.SignAgentBinding / ErrInvalidPoPInput).
    """
    seed = bytes(range(32))
    with pytest.raises(ValueError, match="control byte"):
        sign_agent_binding(
            url=url, signer_seed=seed, created=1, expires=2, signature_agent=_DIRECTORY
        )


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"signature_agent": ""}, SignatureAgentRequiredError),
        ({"signature_agent": "https://agent.example/"}, SignatureAgentNotOriginError),
        ({"signature_agent": "http://agent.example"}, SignatureAgentNotOriginError),
        ({"created": 100, "expires": 401}, SignatureLifetimeError),
        ({"created": 100, "expires": 100}, SignatureLifetimeError),
        ({"nonce": "not base64url!"}, InvalidNonceError),
    ],
    ids=["no_directory", "directory_with_path", "plain_http", "too_long", "empty", "bad_nonce"],
)
def test_sign_agent_binding_refuses_what_no_profile_proof_carries(
    overrides: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        _sign_valid(**overrides)


def test_sign_agent_binding_still_signs_an_ordinary_url() -> None:
    """The refusals are narrow: a normal URL, and a percent-encoded one, still sign."""
    seed = bytes(range(32))
    for url in ("https://cdn.test/a?agent_id=x", "https://cdn.test/a%20b%2Fc"):
        binding = sign_agent_binding(
            url=url, signer_seed=seed, created=1, expires=2, signature_agent=_DIRECTORY
        )
        assert binding.agent_key
        assert binding.signature_input.startswith("sig1=")
        assert binding.signature.startswith("sig1=:")
        assert binding.signature_agent == f'sig1="{_DIRECTORY}"'
