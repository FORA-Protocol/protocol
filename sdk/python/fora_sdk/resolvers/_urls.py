"""The URLs the resolvers build from a host, and the refusal of a deprecated scheme.

Pure string functions, apart from :func:`refuse_scheme_option`, which raises. They sit
apart from the fetch and decode code that reads the documents these URLs name.
"""

from __future__ import annotations

from fora_sdk.resolvers import _ssrf
from fora_sdk.resolvers.errors import DirectoryUnavailableError
from fora_sdk.wire import WellKnownPath

WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"


def wba_directory_url(scheme: str, host: str) -> str:
    """Build the full WBA identity-directory URL: ``scheme://host`` + the shared
    :data:`WBA_DIRECTORY_PATH`. An empty ``scheme`` defaults to ``https``.

    A PURE string function — the host arrives ALREADY-JOINED (any port-join / IPv6
    bracketing is the caller's concern), there is NO env read and NO scheme-in-host
    detection.
    It mirrors the sdk/go ``WBADirectoryURL`` oracle byte-for-byte, locked by the
    tri-replayed ``wba-url-vectors.json`` corpus.

    Its callers inside the SDK are
    :func:`~fora_sdk.resolvers.offer_key_cache.create_wba_offer_directory_fetch`, which
    joins any port onto the host and hands the result here, and
    :func:`read_wba_directory` when it is given a domain. :class:`WBAKeyResolver` does
    NOT use it: that class's ``_fetch_directory`` seam receives an already-joined
    ``base`` and appends :data:`WBA_DIRECTORY_PATH` directly, so the paths reach the same
    URL by different routes. The tri-language corpus is what holds them to the same
    answer.
    """
    if scheme == "":
        scheme = "https"
    return f"{scheme}://{host}{WBA_DIRECTORY_PATH}"


def manifest_url(scheme: str, host: str) -> str:
    """The URL of ``host``'s well-known manifest. An empty ``scheme`` means https."""
    return f"{scheme or 'https'}://{host}{WellKnownPath}"


def refuse_scheme_option(scheme: str) -> None:
    """Refuse a deprecated ``scheme`` argument that names anything but https.

    The readers, the well-known resolvers and the offer-directory fetch still take a
    ``scheme`` argument, deprecated and removed in 2.0. An empty value means https.
    Any other value raises :class:`DirectoryUnavailableError`, caused by the scheme
    guard's own :class:`_ssrf.SsrfError`, before anything is dialled, whatever client
    was injected, so no value of it reaches a plaintext peer.
    """
    if scheme and scheme.lower() != "https":
        refusal = _ssrf.SsrfError(f"refusing to dial non-https scheme {scheme!r} (SSRF guard)")
        raise DirectoryUnavailableError(f"the scheme argument {scheme!r} is refused") from refusal
