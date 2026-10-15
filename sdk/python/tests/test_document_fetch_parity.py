"""Document-read parity (Python side) — replay of the shared Go-oracle corpus.

Mirrors the sdk/ts sibling sdk/ts/tests/document-fetch.parity.test.ts and the Go leg
sdk/go/resolvers/document_fetch_corpus_test.go.

Every document read ends in one decision about the status it was answered with, made in
the one GET every read shares: a 200 is read, a 404 is a missing document on every read,
any 3xx is a refused redirect on a key-directory read, and anything else is an
unavailable document. The corpus records that decision for each status; this replays it
through ``fetch_document``, with the read refusing redirects for a key directory and
following them otherwise.

Each failure is also checked for what every vector shares: it is a
``DirectoryUnavailableError`` and never an ``UnknownKeyError``, and it never carries the
Location the server chose.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from conftest import GO_RESOLVERS_TESTDATA, load_json
from fora_sdk.resolvers._http import fetch_document
from fora_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    DocumentNotFoundError,
    RedirectRefusedError,
    UnknownKeyError,
)

_DOC = load_json(GO_RESOLVERS_TESTDATA / "document-fetch-vectors.json")
_VECTORS: list[dict[str, Any]] = _DOC["vectors"]
_URL = "https://publisher.example/.well-known/http-message-signatures-directory"


def _answering(vector: dict[str, Any]) -> httpx.Client:
    def respond(request: httpx.Request) -> httpx.Response:  # noqa: ARG001
        headers = {"location": vector["location"]} if vector["location"] else {}
        return httpx.Response(vector["status"], headers=headers)

    return httpx.Client(transport=httpx.MockTransport(respond))


def _read(vector: dict[str, Any]) -> DirectoryUnavailableError | None:
    assert vector["read"] in {"key_directory", "document"}, vector["read"]
    with _answering(vector) as client:
        try:
            fetch_document(client, _URL, follow_redirects=vector["read"] == "document")
        except DirectoryUnavailableError as exc:
            return exc
    return None


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_document_fetch_vector(vector: dict[str, Any]) -> None:
    failure = _read(vector)
    if vector["verdict"] == "ok":
        assert failure is None, f"the read failed for a vector recorded as ok: {failure!r}"
        return
    assert failure is not None, "the read succeeded for a vector recorded as a failure"
    assert not isinstance(failure, UnknownKeyError)
    # Specific before generic: both subclasses are DirectoryUnavailableError too.
    if isinstance(failure, RedirectRefusedError):
        got = "redirect_refused"
    elif isinstance(failure, DocumentNotFoundError):
        got = "not_found"
    else:
        got = "unavailable"
    assert got == vector["verdict"], f"{failure!r}"
    if vector["location"]:
        assert vector["location"] not in str(failure), "the failure carries the Location"


def test_the_corpus_has_a_control_for_each_read() -> None:
    reads = {v["read"] for v in _VECTORS if v["verdict"] == "ok"}
    assert reads == {"key_directory", "document"}, reads
