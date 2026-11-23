"""Thumbprint parity (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/thumbprint.parity.test.ts in pytest.

sdk/python `fora_sdk.thumbprint(pubkey)` MUST reproduce, byte-for-byte, the
RFC 7638 JWK Thumbprint the sdk/go oracle emits. The shared vectors at
sdk/go/helpers/testdata/thumbprint-vectors.json are the cross-language guard:
each entry is a base64url-no-pad raw 32-byte Ed25519 public key and its expected
base64url-no-pad thumbprint (= base64url(SHA-256(canonical JWK))). The canonical
JWK is `{"crv":"Ed25519","kty":"OKP","x":"<b64url-nopad(pubkey)>"}` with members
in lexicographic order, no whitespace. The last vector uses the RFC 8032
Ed25519 test-vector public key.
"""

from __future__ import annotations

import pytest
from conftest import GO_TESTDATA, b64url_nopad_decode, load_json

# RED: sdk/python/fora_sdk/thumbprint.py does not exist yet (TDD red).
from fora_sdk.thumbprint import thumbprint

_VECTORS = load_json(GO_TESTDATA / "thumbprint-vectors.json")["vectors"]


def test_thumbprint_vector_file_is_nonempty() -> None:
    assert len(_VECTORS) > 0


@pytest.mark.parametrize(
    "vector",
    _VECTORS,
    ids=[v["public_key_b64url"] for v in _VECTORS],
)
def test_thumbprint_matches_go_oracle(vector: dict[str, str]) -> None:
    pub = b64url_nopad_decode(vector["public_key_b64url"])
    assert len(pub) == 32
    got = thumbprint(pub)
    assert got == vector["thumbprint"]
