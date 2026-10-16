"""Signed-URL + RFC 9421 GET-PoP byte-parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/signedurl-pop.parity.test.ts in pytest.

The Core Invariant for these two helpers is byte-identical verdicts to the
sdk/go oracle. Both shared vector files already exist (emitted by the Go golden
emitter):

  sdk/go/helpers/testdata/signedurl-vectors.json  (SignURLEd25519 output)
  sdk/go/helpers/testdata/pop-vectors.json        (RFC 9421 GET-PoP output)

This suite asserts sdk/python verify reaches the recorded verdict for each
vector. It is RED now purely because sdk/python/fora_sdk/{signedurl,pop}.py do
not exist yet (imports cannot resolve → collection error).

LOAD-BEARING (why vectors come from the Go signer, never hand-authored):
SignURLEd25519 emits the URL with a SORTED query (url.Values.Encode()); the
verifier does NOT re-sort — it only strips `sig` and verifies "GET\n<url>".
They agree ONLY when the verifier is fed the Go signer's canonically-sorted
output. Hand-authored vectors would silently defeat that guard.

PoP portability (per the plan step 5 + the sdk/ts sibling): the PoP verifier
MUST expose the Ed25519 verify primitive as an INJECTABLE dependency, with a
default that uses `cryptography`. This suite drives BOTH a default-primitive
case (byte-identical output observed on the default path, not merely asserted in
prose) AND an injected-primitive case — the verdict MUST match on both paths
because the byte contract is the signature base, not the primitive.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from conftest import GO_TESTDATA, load_json

# RED: sdk/python/fora_sdk/{signedurl,pop}.py do not exist yet (TDD red).
from fora_sdk.pop import verify_agent_binding  # type: ignore[import-not-found]
from fora_sdk.signedurl import verify_ed25519_signed_url  # type: ignore[import-not-found]

_SIGNEDURL_VECTORS = load_json(GO_TESTDATA / "signedurl-vectors.json")
_POP_VECTORS = load_json(GO_TESTDATA / "pop-vectors.json")


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# ---- signed-URL verify -----------------------------------------------------
def test_signedurl_vector_file_is_nonempty() -> None:
    assert len(_SIGNEDURL_VECTORS) > 0


@pytest.mark.parametrize(
    "vector",
    _SIGNEDURL_VECTORS,
    ids=[v["name"] for v in _SIGNEDURL_VECTORS],
)
def test_signedurl_verify_matches_go_oracle(vector: dict[str, object]) -> None:
    pub = _b64url_nopad_decode(str(vector["pub_b64url"]))
    kid = str(vector["kid"])

    # Key resolution is INJECTED (ADR-020 §4): the resolver returns the vector's
    # public key for the matching kid, None otherwise. `now` is injected so the
    # L1 verify reads no wall clock.
    def resolve_key(claimed_kid: str | None) -> bytes | None:
        return pub if claimed_kid == kid else None

    result = verify_ed25519_signed_url(
        str(vector["signed_url"]),
        now=int(vector["now_unix"]),  # type: ignore[arg-type]
        resolve_key=resolve_key,
    )
    assert result.valid is bool(vector["expected_valid"])


# ---- RFC 9421 GET-PoP verify ----------------------------------------------
def test_pop_vector_file_is_nonempty() -> None:
    assert len(_POP_VECTORS) > 0


def _pop_headers(vector: dict[str, object]) -> dict[str, str]:
    """RFC 9421 PoP headers as the verifier receives them off the wire. An empty
    ``signature_agent``, ``signature_input`` or ``signature`` is a header the request
    does not carry at all."""
    headers = {"x-fora-agent-key": str(vector["presented_key_b64url"])}
    for field, name in (
        ("signature_agent", "signature-agent"),
        ("signature_input", "signature-input"),
        ("signature", "signature"),
    ):
        if vector[field]:
            headers[name] = str(vector[field])
    return headers


def _assert_oracle_verdict(result: object, vector: dict[str, object]) -> None:
    """The verdict, the refusal token and the Accept-Signature value the Go
    VerifyAgentBinding reached for this vector."""
    assert result.ok is bool(vector["expected_valid"])  # type: ignore[attr-defined]
    assert (result.reason or "") == vector["expected_reason"]  # type: ignore[attr-defined]
    expected_accept = vector.get("expected_accept_signature") or None
    assert result.accept_signature == expected_accept  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    "vector",
    _POP_VECTORS,
    ids=[v["name"] for v in _POP_VECTORS],
)
def test_pop_verify_default_primitive_matches_go_oracle(vector: dict[str, object]) -> None:
    # DEFAULT-primitive path: verify_agent_binding uses its built-in
    # `cryptography` Ed25519 verify. Observes byte-identical verdict on the
    # default path — no injected primitive.
    result = verify_agent_binding(
        method=str(vector["method"]),
        url=str(vector["url"]),
        headers=_pop_headers(vector),
        agent_id=str(vector["agent_id"]),
        now=int(vector["now_unix"]),  # type: ignore[arg-type]
    )
    _assert_oracle_verdict(result, vector)
    # A proof that verifies names the agent's key directory, as its member carries it.
    if result.ok:
        assert result.signature_agent == str(vector["agent_directory"])


@pytest.mark.parametrize(
    "vector",
    _POP_VECTORS,
    ids=[v["name"] for v in _POP_VECTORS],
)
def test_pop_verify_injected_primitive_matches_go_oracle(vector: dict[str, object]) -> None:
    # INJECTED-primitive path: same vectors verified through a caller-supplied
    # Ed25519 verify primitive (the non-default-crypto path). The verdict MUST
    # match the default path — the byte contract is the signature base, not the
    # primitive.
    def injected_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except Exception:
            return False

    result = verify_agent_binding(
        method=str(vector["method"]),
        url=str(vector["url"]),
        headers=_pop_headers(vector),
        agent_id=str(vector["agent_id"]),
        now=int(vector["now_unix"]),  # type: ignore[arg-type]
        verify_ed25519=injected_verify,
    )
    _assert_oracle_verdict(result, vector)


def test_pop_a_covered_component_the_request_cannot_supply_is_refused_with_accept() -> None:
    # A superset proof covering a header the request does not carry cannot have its base
    # rebuilt. The Go oracle answers bad_covered_components with Accept-Signature, and so
    # does this face: the fetcher fixes it by covering what it sends.
    from fora_sdk.pop import POP_ACCEPT_SIGNATURE

    vector = next(v for v in _POP_VECTORS if v["name"] == "superset_authority_first_and_agent_key")
    headers = _pop_headers(vector)
    headers["signature-input"] = str(vector["signature_input"]).replace(
        '"x-fora-agent-key"', '"x-missing-header"'
    )
    result = verify_agent_binding(
        method=str(vector["method"]),
        url=str(vector["url"]),
        headers=headers,
        agent_id=str(vector["agent_id"]),
        now=int(vector["now_unix"]),  # type: ignore[arg-type]
    )
    assert (result.ok, result.reason, result.accept_signature) == (
        False,
        "bad_covered_components",
        POP_ACCEPT_SIGNATURE,
    )


@pytest.mark.parametrize(
    ("url", "authority"),
    [
        ("https://CDN.Example/doc?x=1", "cdn.example"),
        ("https://cdn.example:8443/a%2Fb", "cdn.example:8443"),
        ("https://user@cdn.example/doc", "cdn.example"),
        ("https://cdn.example?x=1", "cdn.example"),
    ],
)
def test_authority_is_read_off_the_url_text(url: str, authority: str) -> None:
    from fora_sdk._sigbase import authority_of

    assert authority_of(url) == authority
