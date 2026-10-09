"""Key-directory response signatures (WG-00 §5.5, Appendix B.1) — Python replay of the
Go oracle's directory-response-vectors.json.

A key directory's response is signed once per key it lists, covering
``"@authority";req`` and ``content-digest`` with
``tag="http-message-signatures-directory"``. ``verify_directory_response`` must return,
for every vector, exactly the thumbprints the oracle verified — or raise the error the
oracle raised — and ``sign_directory_response`` must re-sign the vectors whose signer
seeds are recorded byte for byte, the authentication page's example among them.
"""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from conftest import GO_TESTDATA, load_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import fora_sdk
from fora_sdk.directory_signature import (
    DirectoryResponseDigestError,
    DirectoryResponseUnsignedError,
    sign_directory_response,
    verify_directory_response,
)
from fora_sdk.wba import SignatureLifetimeError

_VECTORS = load_json(GO_TESTDATA / "directory-response-vectors.json")["vectors"]

#: The vectors signed, as recorded, by the seeds they carry for the authority they
#: name. Every other vector was edited after signing, or — for
#: signed_for_another_authority — signed for an authority it does not record.
_RESIGNABLE = [
    "doc_directory_example",
    "two_keys_both_signed",
    "two_keys_one_signed",
    "expired",
    "created_in_the_future",
    "key_not_listed",
]

_ERRORS: dict[str, type[Exception]] = {
    "digest_mismatch": DirectoryResponseDigestError,
    "unsigned": DirectoryResponseUnsignedError,
}


def _b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _headers(v: dict[str, Any]) -> dict[str, str]:
    headers = {"content-digest": v["content_digest"]}
    if v.get("signature_input"):
        headers["signature-input"] = v["signature_input"]
        headers["signature"] = v["signature"]
    return headers


def test_the_corpus_covers_every_case() -> None:
    names = {v["name"] for v in _VECTORS}
    assert (
        set(_RESIGNABLE)
        | {
            "signed_for_another_authority",
            "body_changed",
            "unsigned",
            "wrong_tag",
            "no_authority_covered",
        }
        <= names
    )


@pytest.mark.parametrize("v", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_verify_directory_response_matches_the_oracle(v: dict[str, Any]) -> None:
    keys = [_b64url(k) for k in v["keys"]]

    def verify() -> set[str]:
        return verify_directory_response(
            v["authority"], _headers(v), v["body"].encode(), keys, v["now"]
        )

    if v["expected_error"]:
        with pytest.raises(_ERRORS[v["expected_error"]]):
            verify()
        return
    assert sorted(verify()) == v["expected_verified"]


@pytest.mark.parametrize("name", _RESIGNABLE)
def test_sign_directory_response_reproduces_the_oracle(name: str) -> None:
    v = next(x for x in _VECTORS if x["name"] == name)
    signed = sign_directory_response(
        v["authority"],
        v["body"].encode(),
        [bytes.fromhex(seed) for seed in v["signer_seeds_hex"]],
        v["created"],
        v["expires"],
    )
    assert signed.content_digest == v["content_digest"]
    assert signed.signature_input == v["signature_input"]
    assert signed.signature == v["signature"]


def test_a_response_signed_for_one_authority_does_not_verify_under_another() -> None:
    v = next(x for x in _VECTORS if x["name"] == "doc_directory_example")
    keys = [_b64url(k) for k in v["keys"]]
    assert verify_directory_response(
        v["authority"], _headers(v), v["body"].encode(), keys, v["now"]
    )
    assert not verify_directory_response(
        "other.example", _headers(v), v["body"].encode(), keys, v["now"]
    )


def test_a_publisher_signs_the_directory_it_builds() -> None:
    # The identity helpers' usage: build the directory with directory_document, sign the
    # exact body with every listed key, serve the three headers with it.
    first, first_id = fora_sdk.generate_key()
    second, second_id = fora_sdk.generate_key()
    body = json.dumps(
        fora_sdk.directory_document([first.public_key(), second.public_key()])
    ).encode()
    seeds = [first.private_bytes_raw(), second.private_bytes_raw()]

    signed = fora_sdk.sign_directory_response("agent.example", body, seeds, 100, 200)

    keys = [k.public_key().public_bytes_raw() for k in (first, second)]
    verified = fora_sdk.verify_directory_response(
        "agent.example", signed.headers(), body, keys, 150
    )
    assert verified == {first_id, second_id}


@pytest.mark.parametrize(
    ("authority", "seeds", "created", "expires", "error"),
    [
        ("", [bytes(32)], 1, 2, ValueError),
        ("agent.example", [], 1, 2, ValueError),
        ("agent.example", [bytes(32)], 0, 2, SignatureLifetimeError),
        ("agent.example", [bytes(32)], 2, 2, SignatureLifetimeError),
    ],
    ids=["no_authority", "no_signer", "no_created", "empty_window"],
)
def test_sign_directory_response_refuses_what_it_cannot_sign(
    authority: str, seeds: list[bytes], created: int, expires: int, error: type[Exception]
) -> None:
    with pytest.raises(error):
        sign_directory_response(authority, b"{}", seeds, created, expires)


def test_a_signature_by_a_key_the_body_does_not_list_verifies_nothing() -> None:
    lister = Ed25519PrivateKey.generate()
    stranger = Ed25519PrivateKey.generate()
    signed = sign_directory_response("agent.example", b"{}", [stranger.private_bytes_raw()], 1, 9)
    listed = [lister.public_key().public_bytes_raw()]
    assert verify_directory_response("agent.example", signed.headers(), b"{}", listed, 5) == set()
