"""Synthesized-detail parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors ``sdk/ts/tests/synthesized-detail.parity.test.ts`` and the Go leg
``sdk/go/connect/synthesized_detail_corpus_test.go``.

Decoding a peer's ErrorDetail is already pinned elsewhere. These two details are
different: nothing on the wire says what they should contain, so the domain, the sentence
and the typed reason are AUTHORED — three times, in three languages, from three copies of
one decision. That is the shape that drifts silently, and it had: this port derived each
edge reason's enum name by uppercasing the token, which is right for two of the eleven
tokens the protocol records and wrong for the rest, so nine real edge refusals carried a
typed reason in Go and none here.

Field errors are compared by PATH and never by text. The constraint prose comes from a
different validator library in each language and the contract calls it non-authoritative,
so pinning it here would pin an accident.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from harness.client import FACE_IDS, FACES, Face, FixedEndpoint, FixedRequirements
from harness.corpus import GO_CONNECT_TESTDATA, load_json
from harness.replay import assert_recorded_reason
from test_client import _config

from fora_sdk.client.errors import CallError, CallErrorKind
from fora_sdk.regschema import compile_registration_schema
from fora_sdk.resolvers import RegistrationRequirements

_CORPUS = load_json(GO_CONNECT_TESTDATA / "synthesized-detail-vectors.json")
_PRECHECK = _CORPUS["registration_precheck"]
_EDGE = _CORPUS["edge_refusal"]

_ENDPOINT = "https://exchange.test"


def _refuse(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
    raise AssertionError("the pre-check refusal must never reach the wire")


def _assert_recorded_detail(err: CallError, vector: dict[str, Any]) -> None:
    """The detail matches what the oracle recorded for this row."""
    detail = err.detail
    assert detail is not None
    assert (detail.domain or "") == vector["domain"]
    assert (detail.message or "") == vector["message"]
    assert_recorded_reason(detail, vector)
    # Nothing this SDK wrote itself is attributed to a peer. Every detail in this corpus
    # is one the SDK authored, so the recorded peer_message is empty on every row; this
    # port once derived the field from whatever detail was at hand, including these.
    assert (err.peer_message or "") == vector["peer_message"]


@pytest.mark.parametrize("face", FACES, ids=FACE_IDS)
@pytest.mark.parametrize("vector", _PRECHECK, ids=[v["name"] for v in _PRECHECK])
def test_the_registration_pre_check_detail_matches_the_oracle(
    vector: dict[str, Any], face: Face
) -> None:
    schema, verdict = compile_registration_schema(vector["schema"].encode())
    assert verdict == "accepted", "the row's own schema does not compile"
    config = _config(
        endpoint_resolver=FixedEndpoint(_ENDPOINT),
        registration_requirements=FixedRequirements(
            RegistrationRequirements(schema=schema, verdict=verdict)
        ),
    )
    transport = httpx.MockTransport(_refuse)
    client = face.client(config, transport)

    with pytest.raises(CallError) as caught:
        face.run(
            client.register({"exchange": "exchange.test", "registration_data": vector["data"]})
        )

    err = caught.value
    assert err.kind is CallErrorKind.MALFORMED
    _assert_recorded_detail(err, vector)
    failure = err.detail.registration_failure  # type: ignore[union-attr]
    assert [f.path or "" for f in failure.field_errors or []] == vector["field_error_paths"]


@pytest.mark.parametrize("face", FACES, ids=FACE_IDS)
@pytest.mark.parametrize("vector", _EDGE, ids=[v["name"] for v in _EDGE])
def test_the_content_leg_detail_matches_the_oracle(vector: dict[str, Any], face: Face) -> None:
    token = vector["reason_token"]

    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        return httpx.Response(403, json={"error": "denied", "reason": token})

    transport = httpx.MockTransport(respond)
    config = _config()
    client = face.client(config, transport)

    with pytest.raises(CallError) as caught:
        face.run(client.fetch("https://edge.test/doc"))

    err = caught.value
    # The raw token reaches the caller either way; only the typed reason is at stake, so a
    # row that records none must still carry the refusal.
    assert err.reason_of() == token

    if vector["reason_field"] == "":
        # The protocol records no reason for this token, or records two and so cannot say
        # which check ran. Promoting one would attribute a failure the wire never
        # attributed.
        assert err.detail is None
        return
    _assert_recorded_detail(err, vector)
