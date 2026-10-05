"""Cross-language revocation-set-membership parity (Python side).

sdk/python ``WBAKeyResolver.revoked()`` MUST reproduce the sdk/go oracle's
verdict for every case in
``sdk/go/helpers/testdata/revocation-membership-vectors.json``. The vector
carries a served WBA directory (keys + windows), a served revocation snapshot
(as_of + revoked thumbprints), a prime thumbprint (a directory-listed key
resolved to populate the snapshot), and labelled cases with the expected verdict.

This test serves those docs against a REAL origin (the shared harness), resolves
the prime thumbprint to prime the snapshot, then asserts ``revoked(tp)`` matches
the oracle for EVERY case — including the load-bearing
directory-absent-but-revoked -> True, which is the whole point of the accessor.

A directory is only read for the keys that signed its response, so the served
directory must be signed by its key. The emitter derives that key from the FIXED seed
``present.v1`` (zero-padded to 32 bytes); the test derives the same key, checks it is
the one the corpus lists, and registers it with the harness signer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resolvers_harness import (
    MutableClock,
    Origin,
    loopback_client,
    register_directory_key,
    revocation_json,
    wba_file_json,
)

from fora_sdk.b64 import b64url_nopad

from fora_sdk.resolvers import WBAKeyResolver

_VECTOR = load_json(GO_RESOLVERS_TESTDATA / "revocation-membership-vectors.json")


def _as_of() -> datetime:
    return datetime.fromisoformat(_VECTOR["as_of"])


def _directory_keys() -> list[dict[str, Any]]:
    return [
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "x": k["x"],
            "not_before": k["not_before"],
            "not_after": k["not_after"],
        }
        for k in _VECTOR["directory_keys"]
    ]


def _register_the_emitters_key() -> None:
    priv = Ed25519PrivateKey.from_private_bytes(b"present.v1".ljust(32, b"\0"))
    x = b64url_nopad(priv.public_key().public_bytes_raw())
    assert [k["x"] for k in _VECTOR["directory_keys"]] == [x]
    register_directory_key(priv)


def test_revocation_membership_corpus_nonempty() -> None:
    assert len(_VECTOR["cases"]) > 0


@pytest.mark.parametrize(
    "case",
    _VECTOR["cases"],
    ids=[c["label"] for c in _VECTOR["cases"]],
)
def test_revoked_matches_go_oracle(case: dict[str, Any]) -> None:
    _register_the_emitters_key()
    origin = Origin(tls=True)
    try:
        origin.set_wba(wba_file_json(_directory_keys(), origin.revocation_url()))
        origin.set_revocation(revocation_json(_as_of(), list(_VECTOR["revoked"])))

        r = WBAKeyResolver(http=loopback_client(), now=MutableClock(_as_of()))
        # Prime the revocation snapshot by resolving the directory-listed key.
        r.resolve(_VECTOR["prime_thumbprint"], origin.origin)

        assert r.revoked(case["thumbprint"]) is case["expected_revoked"]
        # Empty key_id is never revoked (parity with the Go accessor guard).
        assert r.revoked("") is False
    finally:
        origin.close()
