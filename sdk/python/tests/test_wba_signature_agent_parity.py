"""sdk/python Web Bot Auth -01 Signature-Agent parity against the shared Go oracle.

The Go SDK reads and sends draft-ietf-webbotauth-httpsig-protocol-01 (WG-01)
Signature-Agent values; wba-signature-agent-vectors.json records, for each wire value,
the key directory URL and identity the Go verifier reads from it or the typed refusal it
answers with, and what a signer configured with a value sends. This suite replays every
row through the Python public faces: ``verify_request_server`` for the verdict, reason
and Accept-Signature, ``verify_request`` for the typed refusal, and ``SigningTransport``
for the signer rows.

The Python reader still implements -00. The rows it does not meet yet are listed in
wba01_pending.PENDING_WBA_01, the one list every replay reads, each with the WG-01 rule it
needs and the outcome the SDK produces today, as STRICT expected failures that fail for
that outcome only. An unlisted row that fails is a regression.
"""

from __future__ import annotations

import importlib
import pathlib
from typing import Any
from urllib.parse import urlsplit

import pytest
import wba01_pending
from conftest import (
    GO_TESTDATA,
    MemoryReplayStore,
    RecordingResolver,
    b64url_nopad_decode,
    load_json,
    verify_vector_headers,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from wba01_pending import (
    PENDING_WBA_01,
    Wba01Observer,
    raised_outcome,
    sign_outcome,
    verify_outcome,
    wba01_param,
)

from fora_sdk import wba
from fora_sdk.httpsig import verify_request, verify_request_server
from fora_sdk.resolvers.documents import wba_directory_url
from fora_sdk.signing_transport import SigningTransport

_CORPUS = "wba-signature-agent-vectors"

_DOC = load_json(GO_TESTDATA / f"{_CORPUS}.json")
_VECTORS: list[dict[str, Any]] = _DOC["vectors"]
_SIGNER: list[dict[str, Any]] = _DOC["signer"]
_ACCEPT = {
    v["name"]: v for v in load_json(GO_TESTDATA / "verify-request-accept-vectors.json")["vectors"]
}


def _error_class(token: str) -> str:
    """The exception a Python signer raises for a refusal token: the token in CamelCase,
    ``signature_agent_required`` as ``SignatureAgentRequiredError``. The corpus records
    the names the SDKs use, so no table maps them."""
    return "".join(word.capitalize() for word in token.split("_")) + "Error"


def _params(kind: str, face: str, rows: list[dict[str, Any]]) -> list[object]:
    return [wba01_param(row, _CORPUS, f"{kind}/{row['name']}", face) for row in rows]


def _joined_signature_agent(row: dict[str, Any]) -> str:
    lines = [str(row["signature_agent"])]
    lines += [str(v) for v in (row.get("extra_headers") or {}).values()]
    return ", ".join(lines)


def test_every_pending_entry_names_a_corpus_row() -> None:
    # An entry for a row no corpus carries marks nothing, so the port could never
    # see it shrink. Each one must name a row of its corpus and a face.
    rows: dict[str, set[str]] = {
        _CORPUS: {f"vectors/{v['name']}" for v in _VECTORS}
        | {f"signer/{v['name']}" for v in _SIGNER},
    }
    for corpus in ("sign-request-vectors", "multisig-chain-vectors"):
        vectors = load_json(GO_TESTDATA / f"{corpus}.json")["vectors"]
        rows[corpus] = {str(v["name"]) for v in vectors}
    rows["pop-vectors"] = {str(v["name"]) for v in load_json(GO_TESTDATA / "pop-vectors.json")}
    for entry in PENDING_WBA_01:
        corpus, rest = entry.split("#", 1)
        row, face = rest.rsplit(":", 1)
        assert face in ("sign", "verify"), entry
        assert row in rows.get(corpus, set()), entry


def test_every_pending_entry_is_registered_by_a_test() -> None:
    # An entry no test registers for its face marks nothing: it never fails, so the
    # rule "delete each entry when its row passes" would never remove it. Every module
    # that reads the list is imported, which registers its keys whichever subset of
    # the suite pytest collected.
    tests = pathlib.Path(__file__).resolve().parent
    for path in sorted(tests.glob("test_*.py")):
        if "wba01_pending" in path.read_text(encoding="utf8"):
            importlib.import_module(path.stem)
    unregistered = sorted(set(PENDING_WBA_01) - wba01_pending.REGISTERED)
    assert not unregistered, f"pending entries no test registers: {unregistered}"


def test_the_corpus_pins_draft_01() -> None:
    assert _DOC["draft"] == "draft-ietf-webbotauth-httpsig-protocol-01"
    used = {str(r["expected_refusal"]) for r in _VECTORS + _SIGNER if r.get("expected_refusal")}
    assert used <= set(_DOC["refusals"])


@pytest.mark.parametrize("row", _params("vectors", "verify", _VECTORS))
def test_verifier_row(row: dict[str, Any], wba01: Wba01Observer) -> None:
    keyid = str(row.get("resolver_keyid") or row["keyid"])
    pub = b64url_nopad_decode(str(row["resolver_pubkey_b64url"]))
    resolver = RecordingResolver({keyid: pub})
    verdict = verify_request_server(
        method=str(row["method"]),
        url=str(row["url"]),
        body=bytes.fromhex(str(row["body_hex"])),
        headers=verify_vector_headers(row),
        resolver=resolver,
        replay_store=MemoryReplayStore(),
        now=int(row["now"]),
    )
    wba01.observe(verify_outcome(verdict.valid, verdict.reason, verdict.accept_signature))
    if row.get("supersedes"):
        # The -00 corpus row carries this exact request with the outcome WG-01 reverses.
        corpus, name = str(row["supersedes"]).split("#", 1)
        assert corpus == "verify-request-accept-vectors"
        old = _ACCEPT[name]
        assert (old["signature_agent"], old["signature_input"], old["signature"]) == (
            row["signature_agent"],
            row["signature_input"],
            row["signature"],
        )
    refusal = str(row.get("expected_refusal") or "")
    if refusal == "":
        assert verdict.valid is True, verdict.reason
        assert verdict.signature_agent == row["expected_signature_agent"]
        assert resolver.calls == [(str(row["expected_signature_agent"]), keyid)]
        identity = urlsplit(str(verdict.signature_agent)).netloc
        assert identity == row["expected_identity"]
        # Computed by this test from the verified origin, not read from the verdict:
        # the Python verdict carries no key directory field until the port adds one.
        assert wba_directory_url("https", identity) == row["expected_key_directory"]
        return
    assert verdict.valid is False
    assert verdict.reason == row["expected_reason"]
    assert verdict.accept_signature == (row.get("expected_accept_signature") or None)
    assert resolver.calls == []
    # The typed refusal, through the primitive face.
    typed = verify_request(
        method=str(row["method"]),
        url=str(row["url"]),
        body=bytes.fromhex(str(row["body_hex"])),
        signature_input=str(row["signature_input"]),
        signature=str(row["signature"]),
        content_digest=str(row["content_digest"]),
        authorization=str(row["authorization"]),
        pubkey=pub,
        now=int(row["now"]),
        signature_agent=_joined_signature_agent(row),
    )
    assert typed.valid is False
    assert typed.reason == refusal


_SIGNER_SEED = bytes(range(1, 33))
_SIGNER_URL = "https://broker.example/fora.v1.BrokerService/Fetch"


@pytest.mark.parametrize("row", _params("signer", "sign", _SIGNER))
def test_signer_row(row: dict[str, Any], wba01: Wba01Observer) -> None:
    transport = SigningTransport(
        signer_seed=_SIGNER_SEED,
        keyid="agent.v1",
        now=lambda: 1_700_000_000.0,
        signature_agent=str(row["configured"]),
    )
    refusal = str(row.get("expected_refusal") or "")
    try:
        signed = transport.sign_outbound(
            method="POST", url=_SIGNER_URL, body=b"{}", authorization=""
        )
    except wba.SignatureProfileError as exc:
        wba01.observe(raised_outcome(exc))
        error = getattr(wba, _error_class(refusal), None) if refusal else None
        assert error is not None, f"refused with {type(exc).__name__}: {exc}"
        assert isinstance(exc, error), f"refused with {type(exc).__name__}: {exc}"
        return
    wba01.observe(sign_outcome(signed.headers["signature-agent"]))
    assert refusal == "", f"signed what the oracle refuses as {refusal}"
    assert signed.headers["signature-agent"] == row["signature_agent"]
    pub = (
        Ed25519PrivateKey.from_private_bytes(_SIGNER_SEED)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    verdict = verify_request(
        method="POST",
        url=_SIGNER_URL,
        body=b"{}",
        signature_input=signed.headers["signature-input"],
        signature=signed.headers["signature"],
        content_digest=signed.headers["content-digest"],
        authorization="",
        pubkey=pub,
        now=1_700_000_010,
        signature_agent=signed.headers["signature-agent"],
    )
    assert verdict.valid is True, verdict.reason
    identity = urlsplit(str(verdict.signature_agent)).netloc
    # Computed by this test from the verified origin, not read from the verdict: the
    # Python verdict carries no key directory field until the port adds one.
    assert wba_directory_url("https", identity) == row["expected_key_directory"]
