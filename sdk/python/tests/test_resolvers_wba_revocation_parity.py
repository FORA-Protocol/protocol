"""Cross-language revocation-set-membership parity (Python side).

sdk/python ``WBAKeyResolver.revoked(key_id, directory)`` MUST reproduce the
sdk/go oracle's verdict for every case in
``sdk/go/resolvers/testdata/revocation-membership-vectors.json``. The vector
carries two served WBA directories, each with its keys, its own revocation
snapshot (as_of + revoked thumbprints) and a prime thumbprint resolved to load
that snapshot, and labelled (thumbprint, directory) cases with the expected
verdict.

This test serves each directory on its own REAL origin (the shared harness),
resolves every prime thumbprint in the order the vector lists them, then asserts
``revoked(tp, directory)`` matches the oracle for EVERY case. Directory B lists no
key and its list names directory A's key, so the corpus pins the load-bearing
rule: a list answers only for its own directory, and A's key still resolves
against A after B's list has loaded.

A directory is only read for the keys that signed its response, so a served
directory must be signed by every key it lists. The emitter derives A's key from
the FIXED seed ``present.v1`` (zero-padded to 32 bytes); the test derives the same
key, checks it is the one the corpus lists, and registers it with the harness
signer. B lists no key, so it has nothing to sign.
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

from fora_sdk.resolvers import UnknownKeyError, WBAKeyResolver

_VECTOR = load_json(GO_RESOLVERS_TESTDATA / "revocation-membership-vectors.json")


def _as_of() -> datetime:
    return datetime.fromisoformat(_VECTOR["as_of"])


def _directory_keys(directory: dict[str, Any]) -> list[dict[str, Any]]:
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
        for k in directory["directory_keys"]
    ]


def _register_the_emitters_key() -> None:
    priv = Ed25519PrivateKey.from_private_bytes(b"present.v1".ljust(32, b"\0"))
    x = b64url_nopad(priv.public_key().public_bytes_raw())
    listed = [k["x"] for d in _VECTOR["directories"] for k in d["directory_keys"]]
    assert listed == [x]
    register_directory_key(priv)


def _reference(origins: dict[str, Origin], case: dict[str, Any]) -> str:
    """The directory reference a case names, spelled in the case's form."""
    if case["directory"] == "":
        return ""
    origin = origins[case["directory"]]
    return origin.host if case["form"] == "bare" else origin.origin


def test_revocation_membership_corpus_nonempty() -> None:
    assert len(_VECTOR["cases"]) > 0
    assert {d["directory"] for d in _VECTOR["directories"]} == {"A", "B"}


@pytest.mark.parametrize(
    "case",
    _VECTOR["cases"],
    ids=[c["label"] for c in _VECTOR["cases"]],
)
def test_revoked_matches_go_oracle(case: dict[str, Any]) -> None:
    _register_the_emitters_key()
    origins: dict[str, Origin] = {}
    try:
        for d in _VECTOR["directories"]:
            origin = Origin(tls=True)
            origins[d["directory"]] = origin
            origin.set_wba(wba_file_json(_directory_keys(d), origin.revocation_url()))
            origin.set_revocation(revocation_json(_as_of(), list(d["revoked"])))

        r = WBAKeyResolver(http=loopback_client(), now=MutableClock(_as_of()))
        # Load every directory's list, in the vector's order, by resolving its prime
        # thumbprint. A keyless directory resolves nothing, yet its list still loads.
        for d in _VECTOR["directories"]:
            origin = origins[d["directory"]]
            if d["prime_resolves"]:
                r.resolve(d["prime_thumbprint"], origin.origin)
            else:
                with pytest.raises(UnknownKeyError):
                    r.resolve(d["prime_thumbprint"], origin.origin)

        assert r.revoked(case["thumbprint"], _reference(origins, case)) is case["expected_revoked"]
        # Empty key_id is never revoked (parity with the Go accessor guard).
        assert r.revoked("", origins["A"].origin) is False
    finally:
        for origin in origins.values():
            origin.close()
