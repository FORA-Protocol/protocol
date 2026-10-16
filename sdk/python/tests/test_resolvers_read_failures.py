"""A 404 and a refused redirect are unavailable documents that say which.

``DocumentNotFoundError`` and ``RedirectRefusedError`` subclass
``DirectoryUnavailableError``, so every caller that handles an unavailable document
handles them too, and neither is an ``UnknownKeyError``: a fail-closed composite halts
on them rather than falling through as if the key were merely unknown. Peers of Go
``ErrDocumentNotFound`` / ``ErrRedirectRefused`` and TS ``DocumentNotFound`` /
``RedirectRefused``.
"""

from __future__ import annotations

import fora_sdk
from fora_sdk import resolvers
from fora_sdk.resolvers.errors import (
    DirectoryUnavailableError,
    DocumentNotFoundError,
    RedirectRefusedError,
    UnknownKeyError,
)


def test_each_is_an_unavailable_document_and_never_an_unknown_key() -> None:
    for cls in (DocumentNotFoundError, RedirectRefusedError):
        assert issubclass(cls, DirectoryUnavailableError)
        assert not issubclass(cls, UnknownKeyError)
    assert not issubclass(DocumentNotFoundError, RedirectRefusedError)
    assert not issubclass(RedirectRefusedError, DocumentNotFoundError)


def test_both_are_exported_where_their_siblings_are() -> None:
    for name, cls in (
        ("DocumentNotFoundError", DocumentNotFoundError),
        ("RedirectRefusedError", RedirectRefusedError),
    ):
        assert name in resolvers.__all__
        assert getattr(resolvers, name) is cls
        assert name in fora_sdk.__all__
        assert getattr(fora_sdk, name) is cls
