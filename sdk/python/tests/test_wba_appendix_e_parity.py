"""The Web Bot Auth draft's own test vectors — Python replay of the Go oracle's
wba-appendix-e-vectors.json: draft-ietf-webbotauth-httpsig-protocol-01 Appendix E, and
the JSON file its Appendix F.3 points to.

For every request vector the Python face must rebuild ``expected_base`` byte for byte,
through the same parser and base builder its verifiers use. An Ed25519 vector's
signature must verify over that base under the injected key; an RSASSA-PSS vector's alg
must be refused, since the SDK verifies Ed25519 only. ``verify_request``, the verifier
the symbol map pairs with Go ``helpers.VerifyRequest``, must refuse every request vector
with the reason the corpus pins, read from its verdict: ``unsupported_alg``, or
``missing_component`` naming ``@method``, because the vectors cover @authority and at most
Signature-Agent. The signed directory response (E.2.3) is a vector of
directory-response-vectors.json, replayed with its base by
test_directory_response_parity.py.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from harness.corpus import GO_TESTDATA, load_json

from fora_sdk._sigbase import alg_accepted, build_signature_base, parse_all_signatures
from fora_sdk.b64 import b64url_decode_strict
from fora_sdk.httpsig import verify_request

_REQUESTS: list[dict[str, Any]] = load_json(GO_TESTDATA / "wba-appendix-e-vectors.json")[
    "request_vectors"
]
_DIRECTORIES: list[dict[str, Any]] = load_json(GO_TESTDATA / "directory-response-vectors.json")[
    "vectors"
]

#: An RSA vector carries no key: the verifier holds an all-zero Ed25519 key and refuses
#: the alg before it uses any key.
_NO_KEY = bytes(32)


def _headers(v: dict[str, Any]) -> dict[str, str]:
    headers = {"signature-input": v["signature_input"], "signature": v["signature"]}
    if "signature_agent" in v:
        headers["signature-agent"] = v["signature_agent"]
    return headers


def _pubkey(v: dict[str, Any]) -> bytes:
    return b64url_decode_strict(v["pubkey_b64url"]) if "pubkey_b64url" in v else _NO_KEY


def test_the_corpora_carry_every_appendix_e_vector_and_the_f3_file() -> None:
    sections = {v["section"] for v in _REQUESTS} | {
        v["section"] for v in _DIRECTORIES if "section" in v
    }
    assert {"E.1.1", "E.1.2", "E.2.1", "E.2.2", "E.2.3", "F.3"} <= sections


@pytest.mark.parametrize("v", _REQUESTS, ids=[v["name"] for v in _REQUESTS])
def test_request_vector_base_and_signature(v: dict[str, Any]) -> None:
    headers = _headers(v)
    all_params, sig_map = parse_all_signatures(headers)
    p = all_params[0]
    base = build_signature_base(v["method"], v["url"], headers, p)
    assert base == v["expected_base"]
    if v["expected_signature"] == "verified":
        assert alg_accepted(p)
        Ed25519PublicKey.from_public_bytes(_pubkey(v)).verify(sig_map[p.label], base.encode())
    else:
        assert v["expected_signature"] == "unsupported_alg"
        assert not alg_accepted(p)


@pytest.mark.parametrize("v", _REQUESTS, ids=[v["name"] for v in _REQUESTS])
def test_request_vector_is_refused_by_the_fora_request_verifier(v: dict[str, Any]) -> None:
    verdict = verify_request(
        method=v["method"],
        url=v["url"],
        body=b"",
        signature_input=v["signature_input"],
        signature=v["signature"],
        content_digest="",
        authorization="",
        pubkey=_pubkey(v),
        now=v["now"],
        signature_agent=v.get("signature_agent", ""),
    )
    assert not verdict.valid
    assert verdict.reason == v["expected_verify_request_refusal"]
    assert verdict.missing_component == v.get("expected_missing_component")
    # A missing component is answered with Accept-Signature; an unsupported alg is not.
    assert (verdict.accept_signature is not None) == (verdict.reason == "missing_component")
