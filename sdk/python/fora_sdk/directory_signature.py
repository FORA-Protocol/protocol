"""Key-directory response signatures (WG-00 §5.5 and Appendix B.1) — pure, IO-free L1.

A key directory's response is signed once per key it lists, and FORA requires it. Each
response signature covers ``"@authority";req`` (the authority the directory was fetched
from) and ``content-digest``, carries created, expires, keyid (the key's RFC 7638
thumbprint) and alg, and has ``tag="http-message-signatures-directory"``.
``"@authority";req`` takes its value from the request that fetched the directory, so
the signature cannot be served again under a different host. The Python port of the Go
oracle's helpers/directory.go, pinned to directory-response-vectors.json.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._sigbase import (
    SignatureCheckError,
    SigParams,
    component,
    component_name,
    content_digest,
    covers_component,
    joined_header,
    parse_all_signatures,
    signature_input_inner,
)
from .thumbprint import thumbprint
from .wba import SignatureLifetimeError
from .wire import DirectoryResponseTag

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

#: The covered set of a directory response signature, in the order a FORA signer emits.
_COVERED = (component("@authority", req=True), component("content-digest"))
#: How far a response signature's created may lead the verifier's clock.
_MAX_FUTURE_SKEW_SEC = 300


class DirectoryResponseUnsignedError(ValueError):
    """A key directory response carrying no response signature at all: no
    Content-Digest, or no Signature-Input / Signature (Go
    ``ErrDirectoryResponseUnsigned``)."""


class DirectoryResponseDigestError(ValueError):
    """A key directory response whose Content-Digest does not match its body, so no
    signature over it can be checked (Go ``ErrDigestMismatch``)."""


@dataclass(frozen=True)
class DirectoryResponseSignature:
    """The three header values a key directory's response carries for its response
    signatures, ready to set on the response."""

    content_digest: str
    signature_input: str
    signature: str

    def headers(self) -> dict[str, str]:
        """The three headers, lowercase-keyed."""
        return {
            "content-digest": self.content_digest,
            "signature-input": self.signature_input,
            "signature": self.signature,
        }


def _base(authority: str, digest: str, names: Sequence[str], inner: str) -> str:
    """The base: one line per covered component (lowercase ``names``) in the signature's
    own order, then the parameters."""
    lines = []
    for name in names:
        if name == "@authority":
            lines.append(f'"@authority";req: {authority.lower()}')
        else:
            lines.append(f'"content-digest": {digest}')
    lines.append(f'"@signature-params": {inner}')
    return "\n".join(lines)


def sign_directory_response(
    authority: str,
    body: bytes,
    signer_seeds: Sequence[bytes],
    created: int,
    expires: int,
) -> DirectoryResponseSignature:
    """Sign a key directory response once per signer, labels ``sig1..sigN`` in order.

    ``authority`` is the host[:port] the directory is served under, exactly as a
    client's request names it: lowercase, and without a port when it is the scheme's
    default. ``body`` is the exact response body. Each signer is a 32-byte Ed25519 seed;
    its keyid is the RFC 7638 thumbprint of its public key, which must be a key the body
    lists. The window is the caller's and is not capped at the request-signature limit:
    a directory response is cached and may be signed for longer than a request.

    Raises ``ValueError`` for an empty authority or no signer, and
    :class:`~fora_sdk.wba.SignatureLifetimeError` for a window that is not positive.
    """
    if authority == "":
        raise ValueError("directory response needs the authority it is served under")
    if not signer_seeds:
        raise ValueError("directory response needs at least one signer")
    if created <= 0 or expires <= created:
        raise SignatureLifetimeError(
            f"directory response window must be positive: created={created} expires={expires}"
        )
    digest = content_digest(body)
    inputs: list[str] = []
    sigs: list[str] = []
    for i, seed in enumerate(signer_seeds, start=1):
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        params = SigParams(
            label=f"sig{i}",
            covered=_COVERED,
            keyid=thumbprint(priv.public_key().public_bytes_raw()),
            alg="ed25519",
            created=created,
            expires=expires,
            tag=DirectoryResponseTag,
        )
        inner = signature_input_inner(params)
        raw = priv.sign(_base(authority, digest, ["@authority", "content-digest"], inner).encode())
        inputs.append(f"{params.label}={inner}")
        sigs.append(f"{params.label}=:{base64.b64encode(raw).decode()}:")
    return DirectoryResponseSignature(
        content_digest=digest, signature_input=", ".join(inputs), signature=", ".join(sigs)
    )


def verify_directory_response(
    authority: str,
    headers: Mapping[str, str],
    body: bytes,
    keys: Sequence[bytes],
    now: int,
) -> set[str]:
    """The RFC 7638 thumbprints of the listed ``keys`` whose response signature verifies.

    ``authority`` is the host[:port] the directory was fetched from, ``headers`` the
    response headers (matched case-insensitively), ``body`` the exact response body and
    ``keys`` the raw 32-byte Ed25519 keys the body lists; ``now`` is unix seconds.

    Raises :class:`DirectoryResponseUnsignedError` when the response carries no
    Content-Digest or no signature, and :class:`DirectoryResponseDigestError` when the
    Content-Digest does not match the body. Otherwise each signature is judged on its
    own, and one that fails is skipped rather than fatal: it must carry
    ``tag="http-message-signatures-directory"`` and alg ed25519, cover exactly
    ``"@authority";req`` and ``content-digest``, carry created no later than now plus
    300 seconds and expires no earlier than now, and verify under the listed key whose
    thumbprint its keyid names.
    """
    digest = joined_header(headers, "content-digest") or ""
    if digest == "":
        raise DirectoryResponseUnsignedError("key directory response carries no Content-Digest")
    if digest != content_digest(body):
        raise DirectoryResponseDigestError("key directory response: content-digest mismatch")
    try:
        all_params, sig_map = parse_all_signatures(headers)
    except SignatureCheckError as exc:
        raise DirectoryResponseUnsignedError(f"key directory response: {exc}") from exc
    by_thumb: dict[str, bytes] = {}
    for key in keys:
        try:
            by_thumb[thumbprint(key)] = key
        except ValueError:
            continue
    verified: set[str] = set()
    for p in all_params:
        pub = by_thumb.get(p.keyid)
        if pub is None or not _params_valid(p, now):
            continue
        names = [component_name(c).lower() for c in p.covered]
        base = _base(authority, digest, names, p.raw_inner)
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig_map[p.label], base.encode())
        except (InvalidSignature, ValueError):
            continue
        verified.add(p.keyid)
    return verified


def _params_valid(p: SigParams, now: int) -> bool:
    """The per-signature rules other than the Ed25519 check: tag, alg, covered set and
    window."""
    if p.tag != DirectoryResponseTag or p.alg.lower() != "ed25519":
        return False
    if len(p.covered) != len(_COVERED) or not all(covers_component(p.covered, c) for c in _COVERED):
        return False
    if not p.created or not p.expires:
        return False
    return p.created <= now + _MAX_FUTURE_SKEW_SEC and p.expires >= now
