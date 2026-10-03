"""Reading the documents the protocol defines, as a party publishes them.

Four documents are served over plain HTTPS rather than answered over RPC: the
well-known manifest (``/.well-known/fora.json``), the WBA key directory
(``/.well-known/http-message-signatures-directory``), the key revocation list a
directory points to, and the license document a ``License.uri`` names. This module is
the one place each of them is fetched and decoded.

Two faces read them, and they share everything up to the decision of how strict to be.

- **The public readers** (:func:`read_manifest`, :func:`read_wba_directory`,
  :func:`read_revocation_list`, :func:`read_license_document`) check what a party
  publishes. Each refuses a document served under the wrong media type, a body that
  fails the published strict JSON Schema of its message or one of the cross-field
  rules, and, for a license document, bytes that do not hash to ``uri_digest``. Each
  returns the parsed generated model, or raises; none returns ``None``. A conformance
  harness reads through these.
- **The resolvers** (the endpoint resolver, the registration-requirements reader, the
  WBA key resolver and the offer-directory fetch) read the same documents to route and
  to verify. They call the lenient functions below, which skip the media type and the
  strict check: a reader that must accept a newer protocol version cannot refuse a
  field it does not know, and a deployment serving its directory as
  ``application/json`` still has to be reachable.

Every fetch goes through the SDK's guarded client by default, the same one the
resolvers use for an address another party chose: the dial-time SSRF guard refuses
loopback, private and metadata addresses, and the scheme guard refuses anything but
https. ``SKIP_SSRF`` and ``ALLOW_INSECURE`` relax them for a sandbox, exactly as
they do for every other guarded fetch. A body is capped at 1 MiB and refused, never
truncated, past it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from contextlib import nullcontext
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from pydantic import BaseModel, ValidationError
from wire.models import KeyRevocationList, License, WBAFile, WellKnownManifest

from fora_sdk._hostref import _invalid_host
from fora_sdk.hosts import is_bare_host
from fora_sdk.resolvers._http import Fetched, fetch_document, guarded_client
from fora_sdk.resolvers.errors import (
    DigestMismatchError,
    DirectoryUnavailableError,
    ManifestVersionRefusedError,
    MediaTypeRefusedError,
)
from fora_sdk.strict import StrictViolationError, check_strict
from fora_sdk.wire import WellKnownPath, manifest_version_refusal

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    import httpx

__all__ = [
    "MANIFEST_MEDIA_TYPE",
    "WBA_DIRECTORY_MEDIA_TYPE",
    "WBA_DIRECTORY_PATH",
    "Document",
    "LicenseDocument",
    "read_license_document",
    "read_manifest",
    "read_revocation_list",
    "read_wba_directory",
    "wba_directory_url",
]

#: The media type ``/.well-known/fora.json`` is served under.
MANIFEST_MEDIA_TYPE = "application/json"
#: The media type the WBA key directory is served under: a JWK Set (RFC 7517 §8.5.2).
WBA_DIRECTORY_MEDIA_TYPE = "application/jwk-set+json"

WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"

_MANIFEST = "fora.v1.WellKnownManifest"
_WBA_FILE = "fora.v1.WBAFile"
_REVOCATION_LIST = "fora.v1.KeyRevocationList"
_LICENSE = "fora.v1.License"

#: The digest methods ``License.uri_digest`` admits, and the hash each one names.
_DIGEST_METHODS = frozenset({"sha256", "sha384", "sha512"})

M = TypeVar("M", bound=BaseModel)


@dataclass(frozen=True)
class Document(Generic[M]):
    """One document a reader fetched and accepted."""

    #: The parsed generated model.
    message: M
    #: The ``Content-Type`` essence the document was served under, lowercased and
    #: without parameters. For the manifest and the WBA directory it is the media type
    #: the protocol names, since anything else is refused; for a revocation list,
    #: which the protocol names none for, it is whatever was served, or ``None``.
    media_type: str | None
    #: The URL that was fetched.
    url: str
    #: The bytes as served.
    body: bytes


@dataclass(frozen=True)
class LicenseDocument:
    """The document a ``License.uri`` names, verified against ``License.uri_digest``."""

    #: The bytes as served.
    body: bytes
    #: The digest of ``body`` in ``method:hexdigest`` form. Equal to the license's
    #: ``uri_digest``, since anything else is refused.
    digest: str
    #: The ``Content-Type`` essence the document was served under, or ``None``. The
    #: protocol names no media type for a license document, so it is not checked.
    media_type: str | None
    #: The URL that was fetched.
    url: str


def wba_directory_url(scheme: str, host: str) -> str:
    """Build the full WBA identity-directory URL: ``scheme://host`` + the shared
    :data:`WBA_DIRECTORY_PATH`. An empty ``scheme`` defaults to ``https``.

    A PURE string function — the host arrives ALREADY-JOINED (any port-join / IPv6
    bracketing is the caller's concern), there is NO env read (the app keeps its
    consumer-side ``FORA_WELLKNOWN_SCHEME`` read) and NO scheme-in-host detection.
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


# --- the shared reads: one fetch-and-decode per document ------------------------------


def decode_manifest(fetched: Fetched) -> tuple[str, Any]:
    """The manifest's text and its decoded JSON value.

    Decoded as UTF-8 exactly once, because the registration-requirements reader slices
    a member out of this text to compile it from the bytes as served. Invalid UTF-8 and
    a body that is not JSON both read as an undecodable manifest, a transport failure.
    No member is read here: each caller applies the version gate first, under its own
    verdict.
    """
    try:
        text = fetched.body.decode("utf-8")
        return text, json.loads(text)
    except ValueError as exc:
        raise DirectoryUnavailableError(f"manifest decode {fetched.url}") from exc


def fetch_manifest(http: httpx.Client, url: str) -> tuple[Fetched, str, Any]:
    """GET a manifest and decode it, leniently: no media type, no strict check."""
    fetched = fetch_document(http, url)
    text, doc = decode_manifest(fetched)
    return fetched, text, doc


def fetch_wba_directory(http: httpx.Client, url: str) -> WBAFile:
    """GET ``url`` and decode the body as a :class:`WBAFile`, leniently.

    The resolvers' read of a directory: :meth:`WBAKeyResolver._fetch_directory` on the
    signature-verification path and
    :func:`~fora_sdk.resolvers.offer_key_cache.create_wba_offer_directory_fetch` on the
    offer-key path. Go shares a single ``fetchWBAFile`` between the same two call sites
    for the same reason, so the two paths cannot drift apart.

    Every failure leaves as :class:`DirectoryUnavailableError`, which is what lets each
    caller make its own raise-or-contain choice against ONE exception type.
    ``fetch_document`` folds in every transport failure, every non-200, and every way the
    URL itself can be refused — a malformed A-label and an over-long label included.
    This adds the one arm it does not cover: a body that is not a valid directory.
    """
    return _parse(fetch_document(http, url), _WBA_FILE, WBAFile)


def fetch_revocation_list(http: httpx.Client, url: str) -> KeyRevocationList:
    """GET ``url`` and decode the body as a :class:`KeyRevocationList`, leniently.

    Raises :class:`DirectoryUnavailableError` on any failure; the WBA resolver's
    revocation refresh contains it and keeps the snapshot it holds.
    """
    return _parse(fetch_document(http, url), _REVOCATION_LIST, KeyRevocationList)


# --- the checks a public reader applies ----------------------------------------------


@dataclass(frozen=True)
class _Kind:
    """What the contract says about one document: its message, and the media type it is
    served under when the protocol names one."""

    message_name: str
    model: type[BaseModel]
    media_type: str | None
    #: Whether ``ver`` is read before any other member (the manifest's rule).
    version_gate: bool = False


MANIFEST = _Kind(_MANIFEST, WellKnownManifest, MANIFEST_MEDIA_TYPE, version_gate=True)
WBA_DIRECTORY = _Kind(_WBA_FILE, WBAFile, WBA_DIRECTORY_MEDIA_TYPE)
REVOCATION_LIST = _Kind(_REVOCATION_LIST, KeyRevocationList, None)


def accept(kind: _Kind, fetched: Fetched) -> Document[Any]:
    """Check a fetched document as ``kind`` and parse it, or raise.

    The checks run in the order the contract reads a document: the media type, when the
    protocol names one; the body as JSON; for the manifest, ``ver`` before any other
    member; then the strict schema and the cross-field rules. Pure: the document-check
    corpus replays it with the bytes and the label it carries, so the three languages
    answer one document with one verdict.
    """
    if kind.media_type is not None and fetched.media_type != kind.media_type:
        served = "no media type" if fetched.media_type is None else repr(fetched.media_type)
        raise MediaTypeRefusedError(
            f"{fetched.url} was served with {served}, not {kind.media_type!r}"
        )
    try:
        payload = json.loads(fetched.body.decode("utf-8"))
    except ValueError as exc:
        raise DirectoryUnavailableError(f"decode {fetched.url}") from exc
    if kind.version_gate:
        ver = payload.get("ver") if isinstance(payload, dict) else None
        refusal = manifest_version_refusal(ver)
        if refusal is not None:
            raise ManifestVersionRefusedError(refusal)
    check_strict(kind.message_name, payload)
    try:
        message = kind.model.model_validate_json(fetched.body)
    except ValidationError as exc:
        # A value the schema leaves to the parse, such as a timestamp that is not
        # RFC 3339, is the document breaking its message all the same. The model also
        # names an enum by its value name, so an enum written as its number, which the
        # schema admits and the Go reader accepts, is refused here.
        raise StrictViolationError(kind.message_name, f": {_first_error(exc)}") from exc
    return Document(
        message=message, media_type=fetched.media_type, url=fetched.url, body=fetched.body
    )


def verify_digest(uri_digest: str, fetched: Fetched) -> LicenseDocument:
    """Hash the fetched bytes with ``uri_digest``'s method and compare, or raise.

    Pure, and replayed by the license-digest corpus. ``uri_digest`` has passed the
    strict ``License`` check by the time a reader calls this, so its method is one of
    the three the contract admits; a value that is not raises ``ValueError``.
    """
    method, _, expected = uri_digest.partition(":")
    if method not in _DIGEST_METHODS:
        raise ValueError(f"uri_digest names no supported method: {method!r}")
    actual = hashlib.new(method, fetched.body).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise DigestMismatchError(
            f"document at {fetched.url} hashes to {method}:{actual}, the license pins {uri_digest}"
        )
    return LicenseDocument(
        body=fetched.body,
        digest=f"{method}:{actual}",
        media_type=fetched.media_type,
        url=fetched.url,
    )


# --- the public readers ---------------------------------------------------------------


def read_manifest(
    domain: str, *, scheme: str = "https", http: httpx.Client | None = None
) -> Document[WellKnownManifest]:
    """Fetch and check ``domain``'s ``/.well-known/fora.json``.

    The checks run in the order the contract reads the document: the media type must be
    ``application/json``; the body must be JSON; ``ver`` must carry a recognised major
    version before any other member is read; and the whole document must pass the
    strict ``WellKnownManifest`` schema and the cross-field rules.

    Raises ``ValueError`` when ``domain`` is not a bare host (a port is allowed), before
    anything is dialled; :class:`DirectoryUnavailableError` when the fetch fails or the
    body is not JSON; :class:`MediaTypeRefusedError`;
    :class:`ManifestVersionRefusedError`; and
    :class:`~fora_sdk.strict.StrictViolationError`.

    ``http`` defaults to :func:`~fora_sdk.resolvers.guarded_client`, built for this call
    and closed after it. A client passed in is used as it is and left open.
    """
    if not is_bare_host(domain):
        raise _invalid_host(domain, "not a bare host")
    with _client(http) as client:
        fetched = fetch_document(client, manifest_url(scheme, domain))
    return accept(MANIFEST, fetched)


def read_wba_directory(
    url_or_domain: str, *, scheme: str = "https", http: httpx.Client | None = None
) -> Document[WBAFile]:
    """Fetch and check a WBA key directory.

    ``url_or_domain`` is either the directory's full URL or a bare host, in which case
    the directory is read from
    ``scheme://host/.well-known/http-message-signatures-directory``. The media type
    must be ``application/jwk-set+json``, and the body must pass the strict ``WBAFile``
    schema and the cross-field rules. Key validity windows and revocation are not
    evaluated: that is the WBA key resolver's job, and a directory listing an expired
    key is still a well-formed directory.

    Raises ``ValueError`` for a value that is neither a URL nor a bare host;
    :class:`DirectoryUnavailableError`; :class:`MediaTypeRefusedError`; and
    :class:`~fora_sdk.strict.StrictViolationError`. ``http`` is as for
    :func:`read_manifest`.
    """
    if "://" in url_or_domain:
        url = url_or_domain
    elif is_bare_host(url_or_domain):
        url = wba_directory_url(scheme, url_or_domain)
    else:
        raise _invalid_host(url_or_domain, "neither a URL nor a bare host")
    with _client(http) as client:
        fetched = fetch_document(client, url)
    return accept(WBA_DIRECTORY, fetched)


def read_revocation_list(
    url: str, *, http: httpx.Client | None = None
) -> Document[KeyRevocationList]:
    """Fetch and check the key revocation list at ``url``, a directory's ``revocation_url``.

    The protocol names no media type for this document, so the label is reported and
    not checked. The body must pass the strict ``KeyRevocationList`` schema and the
    cross-field rules. Whether ``url`` is anchored to the directory's host is the
    caller's question: the WBA key resolver skips a list that is not.

    Raises :class:`DirectoryUnavailableError` and
    :class:`~fora_sdk.strict.StrictViolationError`. ``http`` is as for
    :func:`read_manifest`.
    """
    with _client(http) as client:
        fetched = fetch_document(client, url)
    return accept(REVOCATION_LIST, fetched)


def read_license_document(
    license: License,  # noqa: A002 - the parameter is the protocol's License message
    *,
    http: httpx.Client | None = None,
) -> LicenseDocument:
    """Fetch the document ``license.uri`` names and verify it against ``uri_digest``.

    The license itself is checked first, against the strict ``License`` schema and its
    cross-field rules, so a ``uri`` without a digest, or a digest whose method is not
    sha256, sha384 or sha512, is refused before anything is dialled. The fetched bytes
    are then hashed with the digest's method and compared with it. The protocol names no
    media type for a license document, so the label is reported and not checked.

    A ``uri`` with a scheme other than https, such as a data-labels identifier that is
    not a URL, is refused by the scheme guard and reported as
    :class:`DirectoryUnavailableError`: it names a document, not a place to fetch one.

    Raises ``ValueError`` when the license carries no ``uri``;
    :class:`~fora_sdk.strict.StrictViolationError`; :class:`DirectoryUnavailableError`;
    and :class:`DigestMismatchError`. ``http`` is as for :func:`read_manifest`.
    """
    if not license.uri:
        raise ValueError("license carries no uri: there is no document to read")
    check_strict(_LICENSE, license.model_dump(mode="json", exclude_none=True))
    with _client(http) as client:
        fetched = fetch_document(client, license.uri)
    return verify_digest(license.uri_digest or "", fetched)


# --- helpers --------------------------------------------------------------------------


def _client(http: httpx.Client | None) -> AbstractContextManager[httpx.Client]:
    """The caller's client, left open, or a guarded one closed after the read."""
    if http is not None:
        return nullcontext(http)
    return guarded_client()


def _first_error(exc: ValidationError) -> str:
    first = exc.errors()[0]
    where = "/" + "/".join(str(p) for p in first["loc"])
    return f"at {where}: {first['msg']}"


def _parse(fetched: Fetched, name: str, model: type[M]) -> M:
    try:
        return model.model_validate_json(fetched.body)
    except ValidationError as exc:
        raise DirectoryUnavailableError(f"{name} decode {fetched.url}") from exc
