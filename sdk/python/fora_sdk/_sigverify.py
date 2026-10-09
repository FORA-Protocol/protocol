"""The request-verification core every verify face shares: the pure primitive
(:func:`fora_sdk.httpsig.verify_request`) and the two server faces
(:mod:`fora_sdk.server_verify`).

The Python port of Go ``verifySingleSignature``, ``VerifyMultisigRequest`` and
``enforceEarlierCoverage``. Each signature is judged on its own, in header order, by
the same chain: alg, the Web Bot Auth tag, the FORA RPC components, the key directory
its own covered Signature-Agent member names, entitlement coverage, the created/expires
window, the content digest, then the key that directory publishes and Ed25519 over the
rebuilt base. A request carrying several signatures first has its hop budget checked,
counting every signature, then every coverage of an earlier signature checked for
completeness (WG-00 §5.2.2). Labels carry no meaning beyond naming.

A failure raises: a :class:`~fora_sdk.wba.SignatureProfileError` for the profile's
form, or a :class:`~fora_sdk._sigbase.SignatureCheckError` carrying a fine-grained
reason. The faces turn either into a verdict and never let it reach their caller.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._sigbase import (
    SignatureCheckError,
    SigParams,
    build_signature_base,
    component,
    component_name,
    component_param,
    content_digest,
    covers_component,
    joined_header,
    parse_all_signatures,
    render_component,
)
from .wba import (
    MissingComponentError,
    SignatureAgentFormError,
    SignatureAgentNotOriginError,
    SignatureTagError,
    signature_directory,
)
from .wire import WBATag

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Resolve the raw Ed25519 public key a keyid names in the key directory at an https
#: origin: ``(directory, keyid) -> key``, or None when unknown.
Resolve = Callable[[str, str], bytes | None]

#: How far a created timestamp may lead the verifier's clock (Go defaultMaxFutureSkew).
MAX_FUTURE_SKEW_SEC = 300

#: The components a FORA RPC signature must cover beyond the Web Bot Auth base. The
#: signature's own Signature-Agent member is checked by signature_directory, and the
#: entitlement-token header is required only when the request carries it.
REQUIRED_COVERED: tuple[str, ...] = ("@method", "@target-uri", "content-digest", "authorization")

_ENTITLEMENT = "x-entitlement-token"
_ED25519_PUBLIC_KEY_BYTES = 32


@dataclass(frozen=True)
class Request:
    """The request being verified: the request line, the exact body, the headers."""

    method: str
    url: str
    body: bytes
    headers: Mapping[str, str]


@dataclass(frozen=True)
class Checks:
    """How a signature is checked: where its key comes from, the verifier's clock (unix
    seconds), and the longest declared lifetime accepted (0 means unbounded)."""

    resolve: Resolve
    now: int
    max_signature_age: int = 0


@dataclass(frozen=True)
class VerifiedSignature:
    """One signature that verified. ``signature_agent`` is the https origin of the key
    directory its keyid was resolved in, the value of the member it covers."""

    label: str
    keyid: str
    alg: str
    created: int
    expires: int
    signature: bytes
    public_key: bytes
    signature_agent: str


def verify_first(
    req: Request, resolve: Resolve, *, now: int, max_signature_age: int = 0
) -> VerifiedSignature:
    """Verify the FIRST signature in header order: the whole request for one signer.
    The others still count toward the legacy-form rule."""
    all_params, sig_map = parse_all_signatures(req.headers)
    checks = Checks(resolve, now, max_signature_age)
    return verify_signature(req, all_params[0], sig_map, len(all_params), checks)


def verify_all(
    req: Request,
    resolve: Resolve,
    *,
    now: int,
    max_signatures: int = 0,
    max_signature_age: int = 0,
) -> list[VerifiedSignature]:
    """Verify EVERY signature, in header order. The hop budget is checked before any
    crypto, then the completeness of every coverage of an earlier signature, then each
    signature on its own; any one failing refuses the request."""
    all_params, sig_map = parse_all_signatures(req.headers)
    if max_signatures > 0 and len(all_params) > max_signatures:
        raise SignatureCheckError("hop_budget", f"got {len(all_params)} max {max_signatures}")
    enforce_earlier_coverage(all_params)
    checks = Checks(resolve, now, max_signature_age)
    return [verify_signature(req, p, sig_map, len(all_params), checks) for p in all_params]


def verify_signature(
    req: Request, p: SigParams, sig_map: dict[str, bytes], sig_count: int, checks: Checks
) -> VerifiedSignature:
    """The full per-signature chain. ``sig_count`` is the number of signatures on the
    request: the legacy String form of Signature-Agent is accepted only when it is one."""
    if p.alg.lower() != "ed25519":
        raise SignatureCheckError("unsupported_alg", f"alg={p.alg!r}")
    if p.tag != WBATag:
        raise SignatureTagError(f"signature tag is not {WBATag!r}: {p.tag!r}")
    _enforce_required_components(p)
    directory = signature_directory(req.headers, p, sig_count)
    _enforce_entitlement_coverage(req.headers, p)
    _enforce_window(p, checks.now, checks.max_signature_age)
    _verify_content_digest(req, p)
    pub = _resolve(checks.resolve, directory, p.keyid)
    base = build_signature_base(req.method, req.url, req.headers, p)
    sig = sig_map[p.label]
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, base.encode())
    except (InvalidSignature, ValueError) as exc:
        raise SignatureCheckError("signature_verify") from exc
    return VerifiedSignature(
        label=p.label,
        keyid=p.keyid,
        alg=p.alg,
        created=p.created,
        expires=p.expires,
        signature=sig,
        public_key=pub,
        signature_agent=directory,
    )


def _resolve(resolve: Resolve, directory: str, keyid: str) -> bytes:
    try:
        pub = resolve(directory, keyid)
    except Exception as exc:  # any resolver failure leaves the key unproven, fail closed
        raise SignatureCheckError("unknown_key", f"keyid={keyid!r}") from exc
    if pub is None:
        raise SignatureCheckError("unknown_key", f"keyid={keyid!r}")
    if len(pub) != _ED25519_PUBLIC_KEY_BYTES:
        raise SignatureCheckError("unknown_key", f"public key length {len(pub)}")
    return pub


def _enforce_required_components(p: SigParams) -> None:
    seen = {component_name(c).lower() for c in p.covered}
    for need in REQUIRED_COVERED:
        if need not in seen:
            raise MissingComponentError(need)


def _enforce_entitlement_coverage(headers: Mapping[str, str], p: SigParams) -> None:
    """When the request carries the entitlement-token header, the signature must commit
    to it, or an unsigned token could be slipped under a valid signature. Every field
    line counts: an empty line placed first must not shadow a real token behind it."""
    if (joined_header(headers, _ENTITLEMENT) or "") == "":
        return
    if not any(component_name(c).lower() == _ENTITLEMENT for c in p.covered):
        raise MissingComponentError(_ENTITLEMENT)


def _enforce_window(p: SigParams, now: int, max_age: int) -> None:
    if p.created == 0:
        raise SignatureCheckError("missing_created")
    if p.expires == 0:
        raise SignatureCheckError("missing_expires")
    if p.expires < now:
        raise SignatureCheckError("expired", f"expires={p.expires} now={now}")
    if p.created > now + MAX_FUTURE_SKEW_SEC:
        raise SignatureCheckError("future_created", f"created={p.created} now={now}")
    # A signer-chosen far-future expires is a wide replay window; 0 means unbounded,
    # and a window equal to the bound passes.
    if max_age > 0 and p.expires - p.created > max_age:
        raise SignatureCheckError("lifetime_too_long", f"window={p.expires - p.created}s")


def _verify_content_digest(req: Request, p: SigParams) -> None:
    if not any(component_name(c).lower() == "content-digest" for c in p.covered):
        return
    raw = joined_header(req.headers, "content-digest")
    if not raw:
        raise SignatureCheckError("missing_content_digest")
    if raw != content_digest(req.body):
        raise SignatureCheckError("digest_mismatch")


def enforce_earlier_coverage(all_params: list[SigParams]) -> None:
    """WG-00 §5.2.2 for every signature that covers another: each covered
    ``"signature";key=X`` or ``"signature-input";key=X`` must name a signature appearing
    EARLIER in Signature-Input, and one covering ``"signature";key=X`` must also cover
    ``"signature-input";key=X`` and every component X lists. Covering an earlier
    signature is optional; covering one partially is refused."""
    position = {p.label: i for i, p in enumerate(all_params)}
    for i, p in enumerate(all_params):
        for c in p.covered:
            name = component_name(c).lower()
            if name not in ("signature", "signature-input"):
                continue
            key = component_param(c, "key")
            at = position.get(key)
            if not key or at is None or at >= i:
                raise SignatureCheckError(
                    "broken_chain", f"{p.label} covers {name};key={key!r}, not an earlier signature"
                )
            if name == "signature":
                _covers_earlier_fully(p, all_params[at])


def _covers_earlier_fully(p: SigParams, prev: SigParams) -> None:
    if not covers_component(p.covered, component("signature-input", key=prev.label)):
        raise SignatureCheckError(
            "broken_chain", f"{p.label} covers signature;key={prev.label!r} without its input"
        )
    for c in prev.covered:
        if not covers_component(p.covered, c):
            raise SignatureCheckError(
                "broken_chain", f"{p.label} covers {prev.label} without {render_component(c)}"
            )


def failure_reason(exc: Exception) -> str:
    """The fine-grained reason token for a verification failure."""
    if isinstance(exc, SignatureCheckError):
        return exc.reason
    for kind, reason in _PROFILE_REASONS:
        if isinstance(exc, kind):
            return reason
    return "signature_verify"


_PROFILE_REASONS: tuple[tuple[type[Exception], str], ...] = (
    (MissingComponentError, "missing_component"),
    (SignatureTagError, "signature_tag"),
    (SignatureAgentFormError, "signature_agent_form"),
    (SignatureAgentNotOriginError, "signature_agent_not_origin"),
)
