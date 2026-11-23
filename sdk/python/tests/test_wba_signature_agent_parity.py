"""sdk/python Web Bot Auth -01 Signature-Agent parity against the shared Go oracle.

The Go SDK reads and sends draft-ietf-webbotauth-httpsig-protocol-01 Signature-Agent
values; wba-signature-agent-vectors.json records, for each wire value, the key
directory URL and identity the Go verifier reads from it or the typed refusal it
answers with, and what a signer configured with a value sends. This suite replays
every row through the Python public faces: ``verify_request_server`` for the verdict,
reason and Accept-Signature, ``verify_request`` for the typed refusal, and
``SigningTransport`` for the signer rows.

The Python reader still implements -00. The rows it does not meet yet are listed in
PENDING_WBA_01, each with the -01 rule it needs, as STRICT expected failures: a listed
row that starts to pass fails the suite, so the port removes its entry in the same
change. An unlisted row that fails is a regression.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import pytest
from conftest import (
    GO_TESTDATA,
    MemoryReplayStore,
    RecordingResolver,
    b64url_nopad_decode,
    load_json,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from fora_sdk import wba
from fora_sdk.httpsig import verify_request, verify_request_server
from fora_sdk.resolvers.documents import wba_directory_url
from fora_sdk.signing_transport import SigningTransport

_DOC = load_json(GO_TESTDATA / "wba-signature-agent-vectors.json")
_VECTORS: list[dict[str, Any]] = _DOC["vectors"]
_SIGNER: list[dict[str, Any]] = _DOC["signer"]
_ACCEPT = {
    v["name"]: v for v in load_json(GO_TESTDATA / "verify-request-accept-vectors.json")["vectors"]
}

_WELL_KNOWN = "a member naming the well-known key directory URL names that directory (-01 §5.5)"
_PARAMETER = (
    "a member with a parameter is ignored (-01 §5.2.1), so the signature names no directory"
)
_OTHER_URL = "another path, a query or a fragment is refused as signature_agent_not_key_directory"
_SIGN_COMPLETES = (
    "a signer completes a configured origin to its well-known key directory URL (-01 §5.2.1)"
)
_SIGN_URL = "a signer accepts the well-known key directory URL as its configured value"
_SIGN_OTHER_URL = (
    "a signer refuses another path, a query or a fragment with SignatureAgentNotKeyDirectoryError"
)

# The rows the -00 Python reader and signer do not meet yet. The port deletes each entry
# as the rule it names lands; a strict marker fails the suite once its row passes.
PENDING_WBA_01: dict[str, str] = {
    "vectors:well_known_url": _WELL_KNOWN,
    "vectors:well_known_url_with_port": _WELL_KNOWN,
    "vectors:legacy_string_well_known_url": _WELL_KNOWN,
    "vectors:member_key_differs_from_label": _WELL_KNOWN,
    "vectors:repeated_field_lines_member_on_first": _WELL_KNOWN,
    "vectors:repeated_field_lines_member_on_second": _WELL_KNOWN,
    "vectors:escaped_quote_in_another_member": _WELL_KNOWN,
    "vectors:ignored_member_beside_the_signers": _WELL_KNOWN,
    "vectors:member_with_parameter": _PARAMETER,
    "vectors:member_type_directory_string": _PARAMETER,
    "vectors:member_type_directory_token": _PARAMETER,
    "vectors:member_with_other_parameter": _PARAMETER,
    "vectors:legacy_string_with_parameter": _PARAMETER,
    "vectors:repeated_field_lines_member_with_parameter": _PARAMETER,
    "vectors:other_path": _OTHER_URL,
    "vectors:origin_with_trailing_slash": _OTHER_URL,
    "vectors:well_known_path_with_trailing_slash": _OTHER_URL,
    "vectors:well_known_path_in_another_case": _OTHER_URL,
    "vectors:query": _OTHER_URL,
    "vectors:bare_origin_with_query": _OTHER_URL,
    "vectors:fragment": _OTHER_URL,
    "vectors:escaped_quote_in_the_covered_value": _OTHER_URL,
    "signer:origin_completed": _SIGN_COMPLETES,
    "signer:well_known_url_as_given": _SIGN_URL,
    "signer:origin_with_port_completed": _SIGN_COMPLETES,
    "signer:other_path": _SIGN_OTHER_URL,
    "signer:query": _SIGN_OTHER_URL,
    "signer:fragment": _SIGN_OTHER_URL,
}


# Each refusal token, as the Python reader names it: the verify_request reason and the
# exception class a signer raises. The -01 tokens are the names the port gives them.
_PY_REASON = {
    "member_ignored": "signature_agent_ignored",
    "not_key_directory": "signature_agent_not_key_directory",
    "not_https_origin": "signature_agent_not_origin",
    "form": "signature_agent_form",
    "missing_component": "missing_component",
}
_PY_ERROR = {
    "required": "SignatureAgentRequiredError",
    "not_https_origin": "SignatureAgentNotOriginError",
    "not_key_directory": "SignatureAgentNotKeyDirectoryError",
}


def _params(kind: str, rows: list[dict[str, Any]]) -> list[object]:
    out: list[object] = []
    for row in rows:
        row_id = f"{kind}:{row['name']}"
        marks = []
        if row_id in PENDING_WBA_01:
            reason = PENDING_WBA_01[row_id]
            marks.append(pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason))
        out.append(pytest.param(row, id=row_id, marks=marks))
    return out


def _headers(row: dict[str, Any]) -> dict[str, str]:
    headers = {
        "content-digest": str(row["content_digest"]),
        "signature-input": str(row["signature_input"]),
        "signature": str(row["signature"]),
        "authorization": str(row["authorization"]),
        "signature-agent": str(row["signature_agent"]),
    }
    # Field lines ADDED beside the base ones, spelled in another case so the mapping
    # holds both; applied after, so the join order matches the oracle's.
    for name, value in (row.get("extra_headers") or {}).items():
        headers[str(name)] = str(value)
    return headers


def _joined_signature_agent(row: dict[str, Any]) -> str:
    lines = [str(row["signature_agent"])]
    lines += [str(v) for v in (row.get("extra_headers") or {}).values()]
    return ", ".join(lines)


def test_the_corpus_pins_draft_01() -> None:
    assert _DOC["draft"] == "draft-ietf-webbotauth-httpsig-protocol-01"
    assert set(_DOC["refusals"]) == set(_PY_REASON) | {"required"}


@pytest.mark.parametrize("row", _params("vectors", _VECTORS))
def test_verifier_row(row: dict[str, Any]) -> None:
    keyid = str(row.get("resolver_keyid") or row["keyid"])
    pub = b64url_nopad_decode(str(row["resolver_pubkey_b64url"]))
    resolver = RecordingResolver({keyid: pub})
    verdict = verify_request_server(
        method=str(row["method"]),
        url=str(row["url"]),
        body=bytes.fromhex(str(row["body_hex"])),
        headers=_headers(row),
        resolver=resolver,
        replay_store=MemoryReplayStore(),
        now=int(row["now"]),
    )
    if row.get("supersedes"):
        # The -00 corpus row carries this exact request with the outcome -01 reverses.
        old = _ACCEPT[str(row["supersedes"]).split("#", 1)[1]]
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
    assert typed.reason == _PY_REASON[refusal]


@pytest.mark.parametrize("row", _params("signer", _SIGNER))
def test_signer_row(row: dict[str, Any]) -> None:
    seed = bytes(range(1, 33))
    transport = SigningTransport(
        signer_seed=seed,
        keyid="agent.v1",
        now=lambda: 1_700_000_000.0,
        signature_agent=str(row["configured"]),
    )
    refusal = str(row.get("expected_refusal") or "")
    try:
        signed = transport.sign_outbound(
            method="POST",
            url="https://broker.example/fora.v1.BrokerService/Fetch",
            body=b"{}",
            authorization="",
        )
    except wba.SignatureProfileError as exc:
        error = getattr(wba, _PY_ERROR.get(refusal, ""), None)
        refused = f"refused with {type(exc).__name__}: {exc}"
        assert error is not None and isinstance(exc, error), refused
        return
    assert refusal == "", f"signed what the oracle refuses as {refusal}"
    assert signed.headers["signature-agent"] == row["signature_agent"]
    key = Ed25519PrivateKey.from_private_bytes(seed).public_key()
    pub = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    verdict = verify_request(
        method="POST",
        url="https://broker.example/fora.v1.BrokerService/Fetch",
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
    assert wba_directory_url("https", identity) == row["expected_key_directory"]
