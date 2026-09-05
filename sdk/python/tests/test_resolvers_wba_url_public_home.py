"""Public-surface home of the WBA directory-path constant (Python side).

The WBA directory path is public only in Go (``WBADirectoryPath``); Python keeps
it as the module-private ``_WBA_DIRECTORY_PATH``. This change promotes it to a public
``WBA_DIRECTORY_PATH`` and re-exports it from the ``fora_sdk`` top-level package so
the app cleanup can import ONE shared constant instead of hand-rolling a
fourth copy of ``/.well-known/http-message-signatures-directory``.

TDD-red: the constant is still private (``_WBA_DIRECTORY_PATH``) and absent from
``fora_sdk.__all__``, so both the top-level import and the ``__all__`` membership
assertion fail until the promotion lands.
"""

from __future__ import annotations

_EXPECTED_PATH = "/.well-known/http-message-signatures-directory"


def test_wba_directory_path_importable_from_fora_sdk_root() -> None:
    """fora_sdk.__init__ re-exports the public WBA_DIRECTORY_PATH at the top level."""
    # RED: WBA_DIRECTORY_PATH is not exported from fora_sdk (only the private
    # _WBA_DIRECTORY_PATH lives inside fora_sdk.resolvers.wba today).
    from fora_sdk import WBA_DIRECTORY_PATH  # type: ignore[attr-defined]

    assert WBA_DIRECTORY_PATH == _EXPECTED_PATH


def test_wba_directory_path_in_fora_sdk_all() -> None:
    """WBA_DIRECTORY_PATH is part of the declared public surface (__all__)."""
    import fora_sdk

    assert "WBA_DIRECTORY_PATH" in fora_sdk.__all__


def test_wba_directory_path_importable_from_resolvers_subpackage() -> None:
    """The constant is also public on the resolvers subpackage surface."""
    # RED: fora_sdk.resolvers does not export WBA_DIRECTORY_PATH yet.
    from fora_sdk.resolvers import WBA_DIRECTORY_PATH  # type: ignore[attr-defined]

    assert WBA_DIRECTORY_PATH == _EXPECTED_PATH
