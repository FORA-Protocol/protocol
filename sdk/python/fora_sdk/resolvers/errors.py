"""Typed error surface for the fetching resolver faces.

The Go oracle uses errors.Is-DISTINCT sentinels (ErrKeyRevoked / ErrKeyExpired /
ErrDirectoryUnavailable / ErrNoEndpoint / ErrUnknownKey) so a composite resolver
can HALT on a fail-closed verdict rather than fall through as if the key were
merely unknown. The port preserves that distinctness as distinct exception
classes: each fail-closed verdict is its own catchable class, and (critically)
``DirectoryUnavailableError`` is NOT a subclass of ``UnknownKeyError`` — an
outage must stay distinguishable from an unknown key.
"""

from __future__ import annotations

from fora_sdk.directory_signature import (
    DirectoryResponseUnsignedError as _L1DirectoryResponseUnsignedError,
)


class ResolverError(Exception):
    """Base of every resolver verdict."""


class UnknownKeyError(ResolverError):
    """No key is known for the requested keyid/thumbprint (fall-through miss)."""


class KeyRevokedError(ResolverError):
    """The thumbprint is present in the directory host's revocation snapshot."""


class KeyExpiredError(ResolverError):
    """The key exists but ``now`` is outside its [not_before, not_after) window."""


class RevocationUnevaluatedError(ResolverError):
    """The key resolved, but its directory declares a revocation_url whose
    snapshot has never been fetched (unreachable or not host-anchored) — so
    revocation was NEVER EVALUATED, which is DISTINCT from "evaluated and not
    revoked" (:class:`KeyRevokedError` is the revoked verdict).

    Only raised when the resolver is constructed with ``require_revocation=True``;
    the default keeps the prior best-effort behavior (a declared-but-unreachable
    revocation channel does not block resolution). It lets a caller that treats
    revocation as mandatory fail closed instead of trusting an unevaluated key.
    """


class DirectoryUnavailableError(ResolverError):
    """A document could not be fetched or decoded: a well-known manifest, a WBA
    directory or JWKS, a revocation list, or a license document.

    Deliberately NOT a subclass of :class:`UnknownKeyError`: a fail-closed
    composite must be able to halt on a directory outage rather than fall
    through as if the key were merely unknown.
    """


class NoEndpointError(ResolverError):
    """A manifest was fetched and decoded but advertises no endpoint."""


class EndpointRefusedError(ResolverError):
    """A manifest was read and advertises an endpoint this resolver will not hand
    back: one on a host or port unrelated to the domain that served the manifest,
    or one carrying userinfo.

    DISTINCT from :class:`NoEndpointError` and from
    :class:`DirectoryUnavailableError` because it is a VERDICT — the Exchange
    answered, and the answer is not usable. A caller that classifies retryability
    reads this as final rather than as something to try again in a moment.
    """


class ExchangeNotPermittedError(ResolverError):
    """The deployment's allow overlay excluded this Exchange domain, before anything
    was dialled.

    It says nothing about whether the Exchange exists or answers, only that this
    deployment declined to ask, so the remedy is a configuration change rather than a
    retry. Peer of Go ``ErrExchangeNotPermitted`` / TS ``ExchangeNotPermitted``.
    """


class ManifestNotExchangeError(ResolverError):
    """The document served at the domain's well-known path describes some other role.

    Registration requirements are an Exchange's to publish, so a manifest claiming to
    be an agent, a broker or a publisher is refused rather than read for members it
    has no business carrying. A manifest naming no role at all is refused the same
    way: the field is required by the contract, and reading silence as assent would
    make the check advisory. Peer of Go ``ErrManifestNotExchange`` / TS
    ``ManifestNotExchange``.
    """


class ManifestUnusableError(ResolverError):
    """The document arrived and this reader cannot use it.

    A VERDICT and not a failed read: the bytes were served, and the next attempt gets
    the same ones, so a caller told to retry retries forever.

    The SDK's own :class:`~fora_sdk.resolvers.WellKnownRequirementsReader` raises it for
    exactly ONE thing: a document whose version it cannot classify. That is the
    contract's own first question about this document, asked before any other member is
    read, and a layout no reader can classify is not a disappointment about one member —
    it is the whole document being unreadable for what a registration owes.

    The other two ways a manifest can disappoint that reader stay deliberate non-errors:
    a member carrying a type the contract does not admit reads as ABSENT, because the
    projection is shared with the endpoint and key faces, and a document that does not
    decode at all is a transport failure.

    It is ALSO the word for a reader stricter than the SDK's own, which is why the seam
    admits it at all: that seam is injectable, and a reader validating the whole document
    — or applying a version rule narrower than this one — has to be able to say its
    refusal is final.

    Deliberately NOT :class:`ManifestVersionRefusedError`, which belongs to the endpoint
    seam. The two vocabularies are disjoint: that one answers whether an endpoint may be
    dialled, this one whether a document can be read for what a registration owes. Peer
    of Go ``ErrManifestUnusable`` / TS ``ManifestUnusable``.
    """


class ManifestVersionRefusedError(ResolverError):
    """A ``/.well-known/fora.json`` was fetched and parsed but carries a
    ``WellKnownManifest.ver`` this resolver does not accept: an unrecognised major
    version, a value that is not ``MAJOR.MINOR``, or no version at all. The rule is
    :func:`fora_sdk.wire.manifest_version_refusal`.

    Like :class:`EndpointRefusedError` it is a VERDICT — final, not a transport
    failure to retry — and it is never cached. The gate runs before any other
    member of the document is read, for the reason stated once on
    ``WellKnownManifest.ver`` in the proto.
    """


class MediaTypeRefusedError(ResolverError):
    """A document was served under a media type other than the one the protocol names
    for it: ``application/json`` for ``/.well-known/fora.json`` and
    ``application/http-message-signatures-directory+json`` for the WBA directory.

    A VERDICT on what the party publishes, not a failed read, so it is never worth
    retrying. Only the document readers in :mod:`fora_sdk.resolvers.documents` raise
    it. The resolvers that read a key directory for key resolution check its label too
    and report a wrong one as :class:`DirectoryUnavailableError`, like any directory
    they cannot use. Peer of Go ``ErrMediaTypeRefused`` / TS ``MediaTypeRefused``.
    """


class DirectoryResponseUnsignedError(ResolverError, _L1DirectoryResponseUnsignedError):
    """A key directory whose response is not signed by every key it lists: no response
    signature at all, or none by one of the listed keys.

    Raised by :func:`~fora_sdk.resolvers.documents.read_wba_directory`. A VERDICT on what
    the party publishes, never worth retrying. It is also the L1
    :class:`fora_sdk.directory_signature.DirectoryResponseUnsignedError`, so one
    ``except`` catches the verdict from either face. Peer of Go
    ``ErrDirectoryResponseUnsigned``.
    """


class DigestMismatchError(ResolverError):
    """The bytes served at ``License.uri`` do not hash to ``License.uri_digest``.

    The digest is covered by the offer signature, so a mismatch means the document
    changed after the offer was signed, or the server answering is not the one the
    offer named. A VERDICT, never retried. Peer of Go ``ErrDigestMismatch`` / TS
    ``DigestMismatch``.
    """
