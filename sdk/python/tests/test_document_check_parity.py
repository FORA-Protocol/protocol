"""Replay the document-check and license-digest corpora through the Python readers' checks.

Both corpora are emitted by the Go oracle (``sdk/go/resolvers/gen_document_check_vectors_test.go``)
by running the pure decision each document reader ends in. Replaying them here holds
:func:`fora_sdk.resolvers.documents.accept` and
:func:`~fora_sdk.resolvers.documents.verify_digest` to the same verdict for the same bytes
and Content-Type, so a harness reading a party's documents through any of the three SDKs
reports the same finding.
"""

from __future__ import annotations

from typing import Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json

from fora_sdk.resolvers import (
    DigestMismatchError,
    DirectoryUnavailableError,
    ManifestVersionRefusedError,
    MediaTypeRefusedError,
)
from fora_sdk.resolvers._http import Fetched, media_type_essence
from fora_sdk.resolvers.documents import (
    MANIFEST,
    REVOCATION_LIST,
    WBA_DIRECTORY,
    accept,
    verify_digest,
)
from fora_sdk.strict import StrictViolationError

_DOCUMENTS = load_json(GO_RESOLVERS_TESTDATA / "document-check-vectors.json")["vectors"]
_DIGESTS = load_json(GO_RESOLVERS_TESTDATA / "license-digest-vectors.json")["vectors"]

_KINDS = {"manifest": MANIFEST, "wba_directory": WBA_DIRECTORY, "revocation_list": REVOCATION_LIST}

_VERDICTS: list[tuple[type[Exception], str]] = [
    (MediaTypeRefusedError, "media_type"),
    (DirectoryUnavailableError, "undecodable"),
    (ManifestVersionRefusedError, "version"),
    (StrictViolationError, "strict"),
]


def _verdict(vector: dict[str, Any]) -> str:
    content_type = vector["content_type"] or None  # "" means the header was absent
    fetched = Fetched(
        url="https://party.example/doc",
        body=vector["body"].encode("utf-8"),
        media_type=media_type_essence(content_type),
    )
    try:
        accept(_KINDS[vector["document"]], fetched)
    except Exception as exc:
        for kind, name in _VERDICTS:
            if isinstance(exc, kind):
                return name
        raise
    return "ok"


def test_corpora_are_not_empty() -> None:
    assert len(_DOCUMENTS) > 0
    assert len(_DIGESTS) > 0


@pytest.mark.parametrize("vector", _DOCUMENTS, ids=lambda v: v["label"])
def test_document_check_vector(vector: dict[str, Any]) -> None:
    assert _verdict(vector) == vector["verdict"]


@pytest.mark.parametrize("vector", _DIGESTS, ids=lambda v: v["label"])
def test_license_digest_vector(vector: dict[str, Any]) -> None:
    fetched = Fetched(
        url="https://publisher.example/terms", body=vector["body"].encode("utf-8"), media_type=None
    )
    if vector["verdict"] == "mismatch":
        with pytest.raises(DigestMismatchError):
            verify_digest(vector["uri_digest"], fetched)
        return
    assert vector["verdict"] == "ok"
    assert verify_digest(vector["uri_digest"], fetched).digest == vector["digest"]
