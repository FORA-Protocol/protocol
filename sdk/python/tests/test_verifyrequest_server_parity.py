"""sdk/python full-RPC single-signature SERVER-VERIFY parity.

SINGLE-SIG scope only: verifying every signature of a multi-signature request (hop
budget, broken_chain) is OUT OF SCOPE and handled separately. This suite pins the generalized
``httpsig.verify_request`` server
face: today ``verify_request`` is a pure primitive that takes an already-resolved
public key and explicit covered fields; it adds a framework-agnostic SERVER
entry that (a) parses the inbound Signature-Input/Signature off the request
headers, (b) resolves the keyid through an INJECTED KeyResolver (SDK owns no
keys), (c) enforces the covered-set/digest/window, (d) runs the two-phase replay
check over an INJECTED store (SDK owns no replay state), (e) reads time through an
INJECTED clock (SDK owns no wall clock), and (f) returns a VERDICT carrying the
reject reason mirroring the Go connectserver taxonomy (classify.go RejectReason /
ErrReplayed) — NOT thrown exceptions at the SDK boundary.

The semantic oracle is sdk/go/connectserver (verify.go / classify.go / reject.go)
over sdk/go/helpers/verify.go. Reject reason tokens mirror RejectReason.String():
"signature" (bad sig / expiry / future-created / wrong-or-unresolvable key /
tampered covered field / missing component — the default) and "replay". The
multisig tokens broken_chain / hop_budget are out of scope here.

Under the Web Bot Auth profile the vectors also pin WHERE a key is resolved: in the
directory the signature's own covered Signature-Agent member names, which the verdict
reports. A refusal for a missing component, a wrong tag, a Signature-Agent form the
profile refuses or an unsigned request carries the Accept-Signature value the oracle
records (``expected_accept_signature``); every other refusal carries none. The accept
corpus (verify-request-accept-vectors.json) pins the forms other Web Bot Auth signers
send that a FORA verifier accepts although the SDK never emits them.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from conftest import GO_TESTDATA, load_json

# RED: ``verify_request_server`` does not exist yet on httpsig (TDD red). It is
# the framework-agnostic single-sig server-verify entry.
from fora_sdk.httpsig import sign_request, verify_request_server  # type: ignore[attr-defined]
from fora_sdk.keyresolver import StaticKeyResolver

# The positive round-trip consumes the existing sign-request oracle vectors (the
# same the request SIGNER produces); the negatives consume the Go-emitted
# single-sig negative-verify corpus the implement step adds.
_SIGN_VECTORS = load_json(GO_TESTDATA / "sign-request-vectors.json")["vectors"]

# RED (also): this file does not exist yet — load_json raises FileNotFoundError,
# a clean TDD-red signal that the shared negative oracle is missing.
_NEG_VECTORS_PATH = GO_TESTDATA / "verify-request-neg-vectors.json"
_NEG_VECTORS = load_json(_NEG_VECTORS_PATH)["vectors"]
_ACCEPT_VECTORS = load_json(GO_TESTDATA / "verify-request-accept-vectors.json")["vectors"]


def _b64url_nopad_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class _RecordingResolver:
    """A KeyResolver that records every (directory, keyid) it was asked to resolve.

    The injected-boundary probe: the server face MUST resolve keys ONLY through
    this holder, so the recorded calls prove no key was read out-of-band, and the
    recorded directory proves the key was looked up where the signature's member
    points.
    """

    def __init__(self, keys: dict[str, bytes]) -> None:
        self._keys = dict(keys)
        self.calls: list[tuple[str, str | None]] = []

    def resolve(self, keyid: str | None, directory: str) -> bytes | None:
        self.calls.append((directory, keyid))
        if keyid is None:
            return None
        return self._keys.get(keyid)


class _MemoryReplayStore:
    """An in-test replay store the SDK orchestrates over (seen / seen_or_add).

    The SDK ships NO default store, so replay state lives entirely here — the
    state boundary the Core Invariant requires.
    """

    def __init__(self) -> None:
        self.seen: set[str] = set()

    def seen_nonce(self, nonce: str) -> bool:
        return nonce in self.seen

    def seen_or_add(self, nonce: str, ttl_seconds: int) -> bool:  # noqa: ARG002
        if nonce in self.seen:
            return True
        self.seen.add(nonce)
        return False


def test_neg_vector_set_covers_every_single_sig_reject_case() -> None:
    # The Go emitter must produce exactly these named single-sig negatives; the
    # multisig cases (broken_chain / hop_budget) are out of scope.
    names = {v["name"] for v in _NEG_VECTORS}
    assert {
        "neg_bad_sig",
        "neg_replay",
        "neg_expired",
        "neg_wrong_key",
        "neg_tampered_authorization",
        "neg_entitlement_uncovered",
        # How a covered header is READ, which is a separate claim from whether its
        # value was tampered with: a name the request does not carry at all, and a
        # second field line beside the signed one under a different spelling.
        "neg_absent_authorization",
        "neg_absent_signature_agent",
        "neg_duplicate_authorization",
        # The entitlement name carried twice with an empty line first — the coverage
        # rule is skipped entirely by a reader that resolves the name to one line.
        "neg_shadowed_entitlement",
        # The Web Bot Auth profile's own refusals: the tag, the Signature-Agent forms
        # it does not accept, a member that is not an https origin, a required RPC
        # component left uncovered, an unsigned request, and a member repointed at
        # another directory after signing.
        "neg_missing_tag",
        "neg_wrong_tag",
        "neg_bare_signature_agent",
        "neg_signature_agent_member_absent",
        "neg_signature_agent_type_not_directory",
        "neg_signature_agent_not_https_origin",
        "neg_signature_agent_not_an_origin",
        "neg_missing_fora_component",
        "neg_unsigned",
        "neg_repointed_signature_agent",
    } <= names


@pytest.mark.parametrize("vector", _SIGN_VECTORS, ids=[v["name"] for v in _SIGN_VECTORS])
def test_oracle_signed_request_verifies_through_server_face(vector: dict[str, object]) -> None:
    # POSITIVE round-trip: an oracle-signed request verifies (valid=True) when its
    # key is injected via the resolver and its window via the clock. The keyid is
    # resolved ONLY through the injected resolver.
    pub = _b64url_nopad_decode(str(vector["pubkey_b64url"]))
    keyid = str(vector["keyid"])
    resolver = _RecordingResolver({keyid: pub})
    store = _MemoryReplayStore()
    now = (int(vector["created"]) + int(vector["expires"])) // 2  # type: ignore[call-overload]

    verdict = verify_request_server(
        method=str(vector["method"]),
        url=str(vector["url"]),
        body=bytes.fromhex(str(vector["body_hex"])),
        headers={
            "content-digest": str(vector["content_digest"]),
            "signature-input": str(vector["signature_input"]),
            "signature": str(vector["signature"]),
            "authorization": str(vector["authorization"]),
            "signature-agent": str(vector["emitted_headers"]["signature-agent"][0]),  # type: ignore[index]
        },
        resolver=resolver,
        replay_store=store,
        now=now,
    )

    assert verdict.valid is True
    assert verdict.signature_agent == str(vector["signature_agent"])
    # Key resolved ONLY through the injected resolver (no out-of-band read), in the
    # directory the signer's member names.
    assert resolver.calls == [(str(vector["signature_agent"]), keyid)]


def test_live_signed_request_roundtrips_through_server_face() -> None:
    # A request signed live by the request SIGNER verifies through the server face.
    seed = bytes.fromhex("55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374")
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    created, expires = 1_700_000_000, 1_700_000_300
    body = b'{"uri":"https://cdn.example/live"}'

    signed = sign_request(
        method="POST",
        url="https://broker.example/fora.v1.BrokerService/Fetch",
        body=body,
        authorization="Bearer live-token",
        signer_seed=seed,
        keyid="mcp.v1",
        created=created,
        expires=expires,
        signature_agent="https://agent.example",
    )

    resolver = _RecordingResolver({"mcp.v1": pub})
    verdict = verify_request_server(
        method="POST",
        url="https://broker.example/fora.v1.BrokerService/Fetch",
        body=body,
        headers={
            "content-digest": signed.content_digest,
            "signature-input": signed.signature_input,
            "signature": signed.signature,
            "authorization": "Bearer live-token",
            "signature-agent": signed.signature_agent,
        },
        resolver=resolver,
        replay_store=_MemoryReplayStore(),
        now=created + 100,
    )

    assert verdict.valid is True
    assert verdict.signature_agent == "https://agent.example"
    assert resolver.calls == [("https://agent.example", "mcp.v1")]


@pytest.mark.parametrize("vector", _NEG_VECTORS, ids=[v["name"] for v in _NEG_VECTORS])
def test_negative_vector_rejected_with_correct_reason(vector: dict[str, object]) -> None:
    # NEGATIVE: each Go-emitted single-sig negative rejects (valid=False) with the
    # reason token the connectserver taxonomy assigns, and the guarded handler
    # never runs (fail-closed — a verdict, not an exception, at the SDK boundary).
    keys: dict[str, bytes] = {}
    resolver_keyid = str(vector.get("resolver_keyid") or vector["keyid"])
    if vector.get("resolver_pubkey_b64url"):
        keys[resolver_keyid] = _b64url_nopad_decode(str(vector["resolver_pubkey_b64url"]))
    resolver = _RecordingResolver(keys)
    store = _MemoryReplayStore()

    headers = {
        "content-digest": str(vector["content_digest"]),
        "signature-input": str(vector["signature_input"]),
        "signature": str(vector["signature"]),
        "authorization": str(vector["authorization"]),
        "signature-agent": str(vector["signature_agent"]),
    }
    # A vector carrying an "entitlement" value exercises entitlement-coverage
    # enforcement: set the X-Entitlement-Token request header to it. The base
    # request's covered set does not cover the header, so a conformant verifier
    # must reject with reason "signature".
    if vector.get("entitlement"):
        headers["X-Entitlement-Token"] = str(vector["entitlement"])
    # A name the request does NOT carry: the key is dropped, so the face sees a
    # covered name with no field line under it rather than an empty one. Absent is
    # not empty, and the two must not verify alike.
    for name in vector.get("omit_headers") or []:
        headers.pop(str(name).lower(), None)
    # Field lines ADDED beside the base ones, spelled in a different case so the
    # mapping holds both. Applied AFTER, so the join order matches the order the
    # oracle added them; the verbatim spelling is the whole point.
    for name, value in (vector.get("extra_headers") or {}).items():  # type: ignore[union-attr]
        headers[str(name)] = str(value)

    def _verify() -> object:
        return verify_request_server(
            method=str(vector["method"]),
            url=str(vector["url"]),
            body=bytes.fromhex(str(vector["body_hex"])),
            headers=headers,
            resolver=resolver,
            replay_store=store,
            now=int(vector["now"]),  # type: ignore[call-overload]
        )

    if vector.get("replay"):
        # First presentation records the nonce; the SECOND must be rejected.
        first = _verify()
        assert first.valid is True  # type: ignore[attr-defined]

    verdict = _verify()
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == str(vector["expected_reason"])  # type: ignore[attr-defined]
    # The Accept-Signature answer: the oracle's value for the refusals the profile answers
    # that way, none for every other.
    assert verdict.accept_signature == (vector.get("expected_accept_signature") or None)  # type: ignore[attr-defined]


@pytest.mark.parametrize("vector", _ACCEPT_VECTORS, ids=[v["name"] for v in _ACCEPT_VECTORS])
def test_accept_vector_verifies_and_names_the_directory(vector: dict[str, object]) -> None:
    # POSITIVE, the other signers' forms: the legacy String Signature-Agent on one
    # signature, a member key that differs from the label, type=directory as a String
    # and as a Token, no nonce, a nonce of another length, other members beside the
    # signer's. Each verifies, and the key is resolved in the directory the oracle names.
    assert vector["expected_reason"] == ""
    keyid = str(vector.get("resolver_keyid") or vector["keyid"])
    resolver = _RecordingResolver(
        {keyid: _b64url_nopad_decode(str(vector["resolver_pubkey_b64url"]))}
    )
    verdict = verify_request_server(
        method=str(vector["method"]),
        url=str(vector["url"]),
        body=bytes.fromhex(str(vector["body_hex"])),
        headers={
            "content-digest": str(vector["content_digest"]),
            "signature-input": str(vector["signature_input"]),
            "signature": str(vector["signature"]),
            "authorization": str(vector["authorization"]),
            "signature-agent": str(vector["signature_agent"]),
        },
        resolver=resolver,
        replay_store=_MemoryReplayStore(),
        now=int(vector["now"]),  # type: ignore[call-overload]
    )
    assert verdict.valid is True, verdict.reason
    assert verdict.accept_signature is None
    assert verdict.signature_agent == str(vector["expected_signature_agent"])
    assert resolver.calls == [(str(vector["expected_signature_agent"]), keyid)]


def test_replay_uses_the_injected_store_only() -> None:
    # The SDK owns no replay state: the replay decision is made ENTIRELY by the
    # injected store. The neg_replay vector proves this — the first presentation
    # passes and mutates OUR store; the second trips OUR store's `seen`. Assert the
    # store actually recorded the nonce (state lives here, not in the SDK).
    replay = next((v for v in _NEG_VECTORS if v["name"] == "neg_replay"), None)
    assert replay is not None
    assert replay["expected_reason"] == "replay"

    keys = {}
    resolver_keyid = str(replay.get("resolver_keyid") or replay["keyid"])
    if replay.get("resolver_pubkey_b64url"):
        keys[resolver_keyid] = _b64url_nopad_decode(str(replay["resolver_pubkey_b64url"]))
    store = _MemoryReplayStore()

    verify_request_server(
        method=str(replay["method"]),
        url=str(replay["url"]),
        body=bytes.fromhex(str(replay["body_hex"])),
        headers={
            "content-digest": str(replay["content_digest"]),
            "signature-input": str(replay["signature_input"]),
            "signature": str(replay["signature"]),
            "authorization": str(replay["authorization"]),
            "signature-agent": str(replay["signature_agent"]),
        },
        resolver=StaticKeyResolver(keys),
        replay_store=store,
        now=int(replay["now"]),  # type: ignore[call-overload]
    )
    # The nonce landed in OUR store — the SDK held none of it.
    assert len(store.seen) == 1


def _live_signed_call(*, max_signature_age: int, window: int = 300) -> object:
    # Sign a request live over a `window`-second declared lifetime and verify it
    # through the single-sig server face under the given max_signature_age clamp.
    # Returns the verdict. Backs the lifetime-clamp parity tests.
    seed = bytes.fromhex("55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374")
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    created = 1_700_000_000
    expires = created + window
    body = b'{"uri":"https://cdn.example/clamp"}'
    signed = sign_request(
        method="POST",
        url="https://broker.example/fora.v1.BrokerService/Fetch",
        body=body,
        authorization="Bearer clamp-token",
        signer_seed=seed,
        keyid="mcp.v1",
        created=created,
        expires=expires,
        signature_agent="https://agent.example",
    )
    return verify_request_server(
        method="POST",
        url="https://broker.example/fora.v1.BrokerService/Fetch",
        body=body,
        headers={
            "content-digest": signed.content_digest,
            "signature-input": signed.signature_input,
            "signature": signed.signature,
            "authorization": "Bearer clamp-token",
            "signature-agent": signed.signature_agent,
        },
        resolver=_RecordingResolver({"mcp.v1": pub}),
        replay_store=_MemoryReplayStore(),
        now=created + 100,
        max_signature_age=max_signature_age,
    )


def test_single_sig_within_max_age_bound_verifies() -> None:
    # Lifetime clamp — WITHIN the bound: a 300s window under a 400s clamp verifies.
    verdict = _live_signed_call(max_signature_age=400)
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_single_sig_equal_to_max_age_bound_verifies() -> None:
    # Lifetime clamp — EQUAL to the bound (inclusive): 300s window under a 300s clamp
    # verifies (mirrors Go's `> maxAge` reject — equality passes).
    verdict = _live_signed_call(max_signature_age=300)
    assert verdict.valid is True  # type: ignore[attr-defined]


def test_single_sig_exceeding_max_age_bound_is_rejected() -> None:
    # Lifetime clamp — EXCEEDING the bound: 300s window under a 200s clamp rejects with
    # reason "signature" (mirrors Go ErrSignatureLifetimeTooLong).
    verdict = _live_signed_call(max_signature_age=200)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature"  # type: ignore[attr-defined]


def test_single_sig_unbounded_max_age_default_verifies() -> None:
    # Lifetime clamp — UNBOUNDED default (0 / omitted): the 300s window is admitted.
    verdict = _live_signed_call(max_signature_age=0)
    assert verdict.valid is True  # type: ignore[attr-defined]
