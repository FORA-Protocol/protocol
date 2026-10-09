"""sdk/python multi-signature append + verify parity under the Web Bot Auth profile.

Core Invariant: a request carrying several signatures — an agent's and a Broker's, or
a forwarder's on top — reconstructs BYTE-FOR-BYTE in Go and Python, so a set signed in
Go verifies in Python and the hop-budget / broken-chain / signature rejections match
the Go taxonomy token for token. The shared Go emitter is the sole oracle
(multisig-chain-vectors.json).

Each signature names its own key directory: it adds a member ``<label>="<origin>"`` to
the Signature-Agent dictionary and covers it as ``"signature-agent";key="<label>"``.
The verifier resolves each keyid in the directory THAT signature's member names. The
resolver in this suite is therefore keyed by (directory, keyid): a port that resolved a
signature through another signature's member would find no key and fail
``wrong_directory_member``'s neighbours, and every positive case asserts the directories
the verdict reports.

A signature covers an earlier one only when its signer forwards the request unchanged
(``cover_previous``); then it must cover it completely — every component it lists, its
Signature member and its Signature-Input member — and the earlier one must come first.
Labels carry no meaning.

Faces under test:
  - ``fora_sdk.httpsig.append_signature`` — adds a signature beside the earlier ones,
    WITHOUT disturbing them; appending to an unsigned request is byte-identical to
    ``sign_request``.
  - ``fora_sdk.server_verify.verify_multisig_request_server`` — enforces the hop budget
    FIRST (hop_budget), coverage completeness next (broken_chain), then verifies each
    signature (signature); returns the keyids and directories in header order.
"""

from __future__ import annotations

import base64

import pytest

from conftest import GO_TESTDATA, load_json

from fora_sdk.httpsig import append_signature, sign_request
from fora_sdk.server_verify import verify_multisig_request_server
from fora_sdk.wba import SignatureAgentFormError, SignatureLabelError

_VECTORS = load_json(GO_TESTDATA / "multisig-chain-vectors.json")["vectors"]

#: The vectors the oracle built only by signing and appending, hop by hop, so a port
#: re-signing the hops in order must reproduce them byte for byte. The others were
#: edited after signing (reordered, stripped, tampered, repointed) and cannot be.
_RESIGNABLE = [
    str(v["name"])
    for v in _VECTORS
    if str(v["name"]).startswith(("positive_", "hop_budget_", "absent_authorization", "duplicate_"))
    or v["name"] == "canonical_case_two"
]


def _by_name(name: str) -> dict[str, object]:
    for v in _VECTORS:
        if v["name"] == name:
            return v
    raise AssertionError(f"missing vector {name}")


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class _DirectoryKeyedResolver:
    """A KeyResolver that answers only for the directory each key is published in."""

    def __init__(self, hops: list[dict[str, object]]) -> None:
        self._keys = {
            (str(h["directory"]), str(h["keyid"])): _b64url_nopad_decode(str(h["pubkey_b64url"]))
            for h in hops
        }
        self.calls: list[tuple[str, str | None]] = []

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        self.calls.append((directory, keyid))
        return self._keys.get((directory, str(keyid)))


def test_vector_set_covers_the_positive_and_every_negative_case() -> None:
    names = {v["name"] for v in _VECTORS}
    assert {
        "positive_independent_two",
        "positive_covering_two",
        "positive_covering_three",
        "positive_covering_two_nonce",
        "hop_budget_three_independent_over_two",
        "hop_budget_three_covering_over_two",
        "broken_coverage_reordered",
        "broken_coverage_stripped",
        "broken_coverage_without_signature_input",
        "broken_coverage_missing_component",
        # A signature that names another signature's member, the legacy String form on
        # two signatures, a tampered first signature, and a member repointed after
        # signing: each resolves the wrong directory or no key, and is refused.
        "wrong_directory_member",
        "legacy_form_on_two_signatures",
        "tampered_first_independent",
        "tampered_first_covered",
        "repointed_second_member",
        # The same sets missing a covered header — which pin WHERE that is noticed
        # relative to the budget and coverage gates, not only that it is.
        "absent_authorization_two",
        "absent_authorization_over_budget",
        "absent_signature_agent_reordered",
        # How a covered header is READ: a second field line beside the signed one, a
        # bag spelled the conventional way, and a set whose covered value IS the join
        # of two lines.
        "duplicate_authorization_two",
        "canonical_case_two",
        "duplicate_bound_two",
    } <= names


def _headers_for(v: dict[str, object]) -> dict[str, str]:
    """The header bag a vector describes: the base five, minus what the request does
    not carry, plus any extra field line spelled in another case.

    ``omit_headers`` drops the key entirely, so the face sees a covered name with no
    field line under it rather than an empty one. ``extra_headers`` is applied AFTER
    the base ones so the join order matches the order the oracle added them.
    """
    headers = {
        "content-digest": str(v["content_digest"]),
        "signature-input": str(v["signature_input"]),
        "signature": str(v["signature"]),
        "authorization": str(v["authorization"]),
        "signature-agent": str(v["signature_agent"]),
    }
    for name in v.get("omit_headers") or []:  # type: ignore[union-attr]
        headers.pop(str(name).lower(), None)
    for name, value in (v.get("extra_headers") or {}).items():  # type: ignore[union-attr]
        headers[str(name)] = str(value)
    return headers


def _verify(v: dict[str, object], **overrides: object) -> object:
    now = (int(v["created"]) + int(v["expires"])) // 2  # type: ignore[call-overload]
    kwargs: dict[str, object] = {
        "method": str(v["method"]),
        "url": str(v["url"]),
        "body": bytes.fromhex(str(v["body_hex"])),
        "headers": _headers_for(v),
        "resolver": _DirectoryKeyedResolver(v["hops"]),  # type: ignore[arg-type]
        "now": now,
        "max_signatures": int(v["max_signatures"]),  # type: ignore[call-overload]
    }
    kwargs.update(overrides)
    return verify_multisig_request_server(**kwargs)  # type: ignore[arg-type]


_NEGATIVE = [str(v["name"]) for v in _VECTORS if not v["expected_verified"]]
_POSITIVE = [str(v["name"]) for v in _VECTORS if v["expected_verified"]]


@pytest.mark.parametrize("name", _NEGATIVE, ids=_NEGATIVE)
def test_negative_case_rejects_with_go_reason(name: str) -> None:
    # NEGATIVE: each Go-emitted reject case rejects with the exact taxonomy token,
    # honoring the hop_budget → broken_chain → signature precedence in the vectors.
    v = _by_name(name)
    verdict = _verify(v)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == str(v["expected_reason"])  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", _POSITIVE, ids=_POSITIVE)
def test_positive_case_verifies_with_go_keyids_and_directories(name: str) -> None:
    # POSITIVE: every Go-emitted set the oracle ACCEPTS verifies here too, returning the
    # same keyids and the same directories in header order. The rejects above cannot
    # stand in for this: a face that refuses everything passes all of them.
    v = _by_name(name)
    verdict = _verify(v)
    assert verdict.valid is True, f"{name}: {verdict.reason}"  # type: ignore[attr-defined]
    assert list(verdict.keyids) == list(v["expected_keyids"])  # type: ignore[attr-defined]
    assert list(verdict.directories) == list(v["expected_directories"])  # type: ignore[attr-defined]


def test_each_key_is_resolved_in_its_own_signers_directory() -> None:
    v = _by_name("positive_covering_two")
    resolver = _DirectoryKeyedResolver(v["hops"])  # type: ignore[arg-type]
    verdict = _verify(v, resolver=resolver)
    assert verdict.valid is True  # type: ignore[attr-defined]
    assert resolver.calls == [
        (str(h["directory"]), str(h["keyid"]))
        for h in v["hops"]  # type: ignore[union-attr]
    ]


def _resign(v: dict[str, object]) -> tuple[str, str, str]:
    """Replay the vector's hops in order through append_signature, with each hop's own
    directory, nonce and cover_previous, under the vector's window and Authorization.

    On a set the oracle ACCEPTS, an extra Authorization line beside the base one was
    there when it signed, so the covered value is the join of both, the way the verifier
    reads them. On a set it refuses, the extra line was slipped in after signing."""
    lines = [str(v["authorization"])]
    extra = (v.get("extra_headers") or {}).get("Authorization")  # type: ignore[union-attr]
    omitted = "Authorization" in (v.get("omit_headers") or [])  # type: ignore[operator]
    if v["expected_verified"] and extra is not None and not omitted:
        lines.append(str(extra))
    authorization = ", ".join(lines)
    signature_input = signature = signature_agent = ""
    for hop in v["hops"]:  # type: ignore[union-attr]
        signed = append_signature(
            method=str(v["method"]),
            url=str(v["url"]),
            body=bytes.fromhex(str(v["body_hex"])),
            authorization=authorization,
            signer_seed=bytes.fromhex(str(hop["seed_hex"])),
            keyid=str(hop["keyid"]),
            created=int(v["created"]),  # type: ignore[call-overload]
            expires=int(v["expires"]),  # type: ignore[call-overload]
            signature_agent=str(hop["directory"]),
            prev_signature_input=signature_input,
            prev_signature=signature,
            prev_signature_agent=signature_agent,
            nonce=str(hop.get("nonce", "")),
            cover_previous=bool(hop.get("cover_previous")),
        )
        signature_input, signature = signed.signature_input, signed.signature
        signature_agent = signed.signature_agent
    return signature_input, signature, signature_agent


@pytest.mark.parametrize("name", _RESIGNABLE, ids=_RESIGNABLE)
def test_append_signature_reproduces_the_go_set_byte_identically(name: str) -> None:
    # BYTE-IDENTITY: re-signing the hops live reproduces the Go-emitted Signature-Input,
    # Signature and Signature-Agent byte for byte — the cross-language contract for the
    # member each hop adds and for a complete coverage of the hop before it.
    v = _by_name(name)
    signature_input, signature, signature_agent = _resign(v)
    assert signature_input == str(v["signature_input"])
    assert signature == str(v["signature"])
    assert signature_agent == str(v["signature_agent"])


def test_append_to_unsigned_request_equals_sign_request_n1() -> None:
    # N=1 INVARIANT: appending to an unsigned request is byte-identical to sign_request,
    # and cover_previous is a no-op when there is no earlier signature.
    v = _by_name("positive_covering_two")
    h1 = v["hops"][0]  # type: ignore[index]
    common = {
        "method": str(v["method"]),
        "url": str(v["url"]),
        "body": bytes.fromhex(str(v["body_hex"])),
        "authorization": str(v["authorization"]),
        "signature_agent": str(h1["directory"]),
        "signer_seed": bytes.fromhex(str(h1["seed_hex"])),
        "keyid": str(h1["keyid"]),
        "created": int(v["created"]),  # type: ignore[call-overload]
        "expires": int(v["expires"]),  # type: ignore[call-overload]
    }
    signed = sign_request(**common)  # type: ignore[arg-type]
    for cover in (False, True):
        appended = append_signature(cover_previous=cover, **common)  # type: ignore[arg-type]
        assert appended.signature_input == signed.signature_input
        assert appended.signature == signed.signature
        assert appended.signature_agent == signed.signature_agent


def _first_hop(v: dict[str, object]) -> dict[str, object]:
    h1 = v["hops"][0]  # type: ignore[index]
    return {
        "method": str(v["method"]),
        "url": str(v["url"]),
        "body": bytes.fromhex(str(v["body_hex"])),
        "authorization": str(v["authorization"]),
        "signer_seed": bytes.fromhex(str(h1["seed_hex"])),
        "keyid": str(h1["keyid"]),
        "created": int(v["created"]),  # type: ignore[call-overload]
        "expires": int(v["expires"]),  # type: ignore[call-overload]
    }


def test_append_takes_the_first_label_no_signature_or_member_uses() -> None:
    # The label is the first sigN not used by Signature-Input, Signature, or a
    # Signature-Agent member: a member "sig2" already present pushes the new one to sig3.
    common = _first_hop(_by_name("positive_covering_two"))
    first = sign_request(signature_agent="https://agent.example", **common)  # type: ignore[arg-type]
    appended = append_signature(
        signature_agent="https://broker.example",
        prev_signature_input=first.signature_input,
        prev_signature=first.signature,
        prev_signature_agent=first.signature_agent + ', sig2="https://other.example"',
        **common,  # type: ignore[arg-type]
    )
    assert appended.signature_input.split(", ")[-1].startswith("sig3=(")
    assert appended.signature_agent.endswith('sig3="https://broker.example"')


def test_append_refuses_a_label_already_in_use() -> None:
    common = _first_hop(_by_name("positive_covering_two"))
    first = sign_request(signature_agent="https://agent.example", **common)  # type: ignore[arg-type]
    with pytest.raises(SignatureLabelError):
        append_signature(
            signature_agent="https://broker.example",
            prev_signature_input=first.signature_input,
            prev_signature=first.signature,
            prev_signature_agent=first.signature_agent,
            label="sig1",
            **common,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("legacy", ['"https://agent.example"', "https://agent.example"])
def test_append_refuses_a_signature_agent_that_is_not_a_dictionary(legacy: str) -> None:
    # The legacy String form and the bare v1.0.8 value cannot take a second member, and
    # rewriting them would break the earlier signature.
    common = _first_hop(_by_name("positive_covering_two"))
    with pytest.raises(SignatureAgentFormError):
        append_signature(
            signature_agent="https://broker.example",
            prev_signature_input='sig1=("@method");keyid="k";alg="ed25519"',
            prev_signature="sig1=:AA==:",
            prev_signature_agent=legacy,
            **common,  # type: ignore[arg-type]
        )


def _positive_two_call(
    *, extra_headers: dict[str, str] | None = None, max_signature_age: int = 0
) -> object:
    v = _by_name("positive_covering_two")
    headers = _headers_for(v)
    headers.update(extra_headers or {})
    return _verify(v, headers=headers, max_signature_age=max_signature_age)


def test_multisig_uncovered_entitlement_header_is_rejected_per_signature() -> None:
    # A request carrying an uncovered X-Entitlement-Token is REJECTED with reason
    # "signature": neither signature covers it, so an unsigned entitlement token
    # cannot be slipped under them. The refusal names what the verifier requires.
    verdict = _positive_two_call(
        extra_headers={"X-Entitlement-Token": "jwt:demo-unsigned-entitlement-token"}
    )
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]
    assert "x-entitlement-token" in (verdict.accept_signature or "")  # type: ignore[attr-defined]


def test_multisig_covered_entitlement_absent_header_still_verifies() -> None:
    # CONTROL: without the entitlement header, the set verifies.
    verdict = _positive_two_call()
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_multisig_signature_within_max_age_bound_verifies() -> None:
    # Lifetime clamp — WITHIN the bound: the declared window is 300s; 400s admits it.
    assert _positive_two_call(max_signature_age=400).valid is True  # type: ignore[attr-defined]


def test_multisig_signature_equal_to_max_age_bound_verifies() -> None:
    # Lifetime clamp — EQUAL to the bound (inclusive), as Go's `> maxAge` reject.
    assert _positive_two_call(max_signature_age=300).valid is True  # type: ignore[attr-defined]


def test_multisig_signature_exceeding_max_age_bound_is_rejected() -> None:
    # Lifetime clamp — EXCEEDING the bound: a 200s clamp rejects the 300s window.
    verdict = _positive_two_call(max_signature_age=200)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]


def test_multisig_unbounded_max_age_default_verifies() -> None:
    assert _positive_two_call(max_signature_age=0).valid is True  # type: ignore[attr-defined]
