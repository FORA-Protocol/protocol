"""Delivery-URL proof of possession (ADR-013) under the Web Bot Auth profile — pure L1
helper, both faces.

When a signed URL carries an ``agent_id`` (the agent's RFC 7638 thumbprint), a
code-capable edge requires the fetcher to prove possession of the bound key, fully
offline. The proof is a full Web Bot Auth signature over the GET: the WG-00 base (a
dictionary Signature-Agent member naming the agent's key directory, covered as
``"signature-agent";key="sig1"``, and the created, expires, keyid, alg, nonce and tag
parameters) plus ``@method`` and ``@target-uri``, with the raw public key in
``X-FORA-Agent-Key``::

    X-FORA-Agent-Key: <base64url raw public key>
    Signature-Agent: sig1="https://agent.example"
    Signature-Input: sig1=("@method" "@target-uri" "signature-agent";key="sig1");
                     created=C;expires=E;keyid="K";alg="ed25519";nonce="N";
                     tag="web-bot-auth"
    Signature: sig1=:<standard base64>:

The edge verifies against the presented key and enforces the three-way identity

  agent_id (URL) == keyid (Signature-Input) == thumbprint(presented key)

The last equality is the one that cannot be dropped: verifying against the presented
key alone proves nothing. A generic WBA verifier ignores ``X-FORA-Agent-Key``, resolves
the same key from the directory the member names, and accepts the same signature.

``@target-uri`` is the URL VERBATIM, never a parsed and re-encoded one. The Ed25519
verify primitive is INJECTABLE (``verify_ed25519``) so a runtime without a preferred
backend can supply its own; the byte contract is the signature base. ``now`` and
``created``/``expires`` are injected: neither face reads a clock. Byte-parity guard:
the sdk/go signer ``SignAgentBinding`` through pop-vectors.json.
"""

from __future__ import annotations

import base64
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._sigbase import (
    MissingSignatureError,
    MissingSignatureInputError,
    SignatureCheckError,
    SigParams,
    build_signature_base,
    component_name,
    parse_all_signatures,
    plain,
    signature_input_inner,
)
from .b64 import b64url_decode, b64url_nopad
from .thumbprint import thumbprint
from .wba import (
    MAX_SIGNATURE_LIFETIME,
    InvalidNonceError,
    MissingComponentError,
    SignatureAgentRequiredError,
    SignatureLifetimeError,
    SignatureProfileError,
    check_https_origin,
    signature_agent_component,
    signature_agent_member,
    signature_directory,
    valid_nonce,
)
from .wire import AgentKeyHeader, WBATag

#: Lookup form of :data:`fora_sdk.wire.AgentKeyHeader`. HTTP field names are
#: case-insensitive and the mappings this module reads are lowercase-keyed, so
#: the canonical constant is folded here rather than re-typed — one edit renames
#: the header everywhere, and the wire-constants vectors pin the canonical form
#: across all three SDKs.
AGENT_KEY_HEADER = AgentKeyHeader.lower()

_ED25519_PUBLIC_KEY_BYTES = 32
#: The only label this profile emits, and the key of the agent's member. A delivery
#: fetch is a single hop to the edge, so the label is fixed rather than computed.
_POP_LABEL = "sig1"
#: A proof covers AT LEAST these: the Web Bot Auth base's Signature-Agent member plus
#: the @method and @target-uri the profile adds. Anything else it covers is allowed.
_POP_REQUIRED = ("@method", "@target-uri")
#: The Accept-Signature value a refused delivery proof is answered with: the components
#: a proof must cover at least, the dictionary form of Signature-Agent, and the created,
#: expires and tag parameters. The same bytes as Go ``helpers.PoPAcceptSignature``.
POP_ACCEPT_SIGNATURE = (
    'sig1=("@method" "@target-uri" "signature-agent";key="sig1");created;expires;tag="'
    + WBATag
    + '"'
)
#: A proof's created timestamp may not lead the verifier clock by more than this.
_MAX_FUTURE_SKEW_SEC = 300
_C0_END = 0x20
_DEL = 0x7F

#: Injected Ed25519 verify primitive: ``(pubkey, signature, message) -> valid?``.
Ed25519Verify = Callable[[bytes, bytes, bytes], bool]


@dataclass(frozen=True)
class PopResult:
    """Verdict of a proof-of-possession verification. On success ``signature_agent``
    is the origin of the agent's key directory, as its covered member names it. On a
    refusal the fetcher can fix by signing again as the profile requires — no
    signature, a wrong tag, a missing required component, or a Signature-Agent the
    profile refuses — ``accept_signature`` is :data:`POP_ACCEPT_SIGNATURE`."""

    ok: bool
    reason: str | None = None
    signature_agent: str | None = None
    accept_signature: str | None = None


@dataclass(frozen=True)
class AgentBinding:
    """The proof a fetcher attaches to a bound delivery request: four header values.

    Returned as values rather than written onto a request so a caller can sign before
    it builds one and so the bytes can be asserted against the shared vectors. The byte
    string in ``signature`` is STANDARD base64 while ``agent_key`` is base64url — RFC
    8941's byte sequence meeting a header this profile defines itself.
    """

    #: The ``X-FORA-Agent-Key`` value: base64url, no padding.
    agent_key: str
    #: The ``Signature-Agent`` value: the one-member dictionary ``sig1="<origin>"``.
    signature_agent: str
    #: The full ``Signature-Input`` value, label included.
    signature_input: str
    #: The full ``Signature`` value, label included.
    signature: str

    def headers(self) -> dict[str, str]:
        """The four headers, lowercase-keyed, ready to set on the GET."""
        return {
            AGENT_KEY_HEADER: self.agent_key,
            "signature-agent": self.signature_agent,
            "signature-input": self.signature_input,
            "signature": self.signature,
        }


def _default_verify_ed25519(pubkey: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _read_presented_key(headers: Mapping[str, str]) -> bytes | PopResult:
    """The presented key, or the refusal: ``missing_agent_key`` when the header is
    absent, ``bad_agent_key`` when it is not 32 bytes of base64url."""
    raw = headers.get(AGENT_KEY_HEADER)
    if not raw:
        return _refuse("missing_agent_key")
    try:
        key = b64url_decode(raw)
    except (ValueError, TypeError):
        return _refuse("bad_agent_key")
    if len(key) != _ED25519_PUBLIC_KEY_BYTES:
        return _refuse("bad_agent_key")
    return key


def _control_byte_at(value: str) -> int | None:
    """The BYTE offset of the first C0 control or DEL in ``value``'s UTF-8, or None.

    Scanned over the bytes, not the code points, so the reported offset is the number
    Go's strings.IndexFunc reports for the same input."""
    return next((i for i, b in enumerate(value.encode("utf-8")) if b < _C0_END or b == _DEL), None)


def _validate_binding(
    *, url: str, method: str, created: int, expires: int, signature_agent: str, nonce: str
) -> None:
    """Every precondition of a bound fetch, checked before anything is signed — the
    Python port of Go ``validateAgentBinding``."""
    if url == "":
        raise ValueError("missing target URI (required by the agent-binding profile)")
    # The base is line-delimited and both values are written into it verbatim, so a
    # control byte would add or split a line and the bytes signed here would stop
    # describing the request a verifier reconstructs. Refused rather than escaped.
    bad = _control_byte_at(url)
    if bad is not None:
        raise ValueError(f"target URI carries a control byte at byte {bad}")
    bad = _control_byte_at(method)
    if bad is not None:
        raise ValueError(f"method carries a control byte at byte {bad}")
    # A proof carrying no created would claim 1970: the edge bounds how far created may
    # lead its clock, not how far it may lag, so freshness would be silently absent.
    if created <= 0:
        raise ValueError("missing created param")
    if expires <= 0:
        raise ValueError("missing expires param")
    life = expires - created
    if life <= 0 or life > MAX_SIGNATURE_LIFETIME:
        raise SignatureLifetimeError(
            f"signature lifetime must be positive and at most {MAX_SIGNATURE_LIFETIME}s: "
            f"created={created} expires={expires}"
        )
    if signature_agent == "":
        raise SignatureAgentRequiredError("a proof needs the agent's Signature-Agent origin")
    check_https_origin(signature_agent)
    if not valid_nonce(nonce):
        raise InvalidNonceError("nonce must use only base64url characters")


def sign_agent_binding(
    *,
    url: str,
    signer_seed: bytes,
    created: int,
    expires: int,
    signature_agent: str = "",
    nonce: str = "",
    method: str = "GET",
) -> AgentBinding:
    """Produce the proof of possession a fetcher presents for a bound delivery URL.

    ``signature_agent`` is the https origin of the agent's key directory, the one that
    publishes the key; it is required, written as the member ``sig1="<origin>"`` and
    covered. ``nonce`` is the RFC 9421 nonce, base64url; the helper reads no RNG, and
    the signing transport passes 64 fresh random bytes. ``created``/``expires`` are
    injected unix seconds and the window is at most
    :data:`~fora_sdk.wba.MAX_SIGNATURE_LIFETIME`. The keyid is the RFC 7638 thumbprint
    of the signer's public key, the anchor of the three-way identity.

    Raises ``ValueError`` for a missing URL, a control byte in the URL or the method, or
    a missing created or expires; :class:`~fora_sdk.wba.SignatureLifetimeError`,
    :class:`~fora_sdk.wba.SignatureAgentRequiredError`,
    :class:`~fora_sdk.wba.SignatureAgentNotOriginError` and
    :class:`~fora_sdk.wba.InvalidNonceError` for the rest.
    """
    method = method or "GET"
    _validate_binding(
        url=url,
        method=method,
        created=created,
        expires=expires,
        signature_agent=signature_agent,
        nonce=nonce,
    )
    priv = Ed25519PrivateKey.from_private_bytes(signer_seed)
    pub = priv.public_key().public_bytes_raw()
    params = SigParams(
        label=_POP_LABEL,
        covered=(*plain("@method", "@target-uri"), signature_agent_component(_POP_LABEL)),
        keyid=thumbprint(pub),
        alg="ed25519",
        created=created,
        expires=expires,
        nonce=nonce,
        tag=WBATag,
    )
    agent = signature_agent_member(_POP_LABEL, signature_agent)
    base = build_signature_base(method, url, {"signature-agent": agent}, params)
    raw = priv.sign(base.encode())
    return AgentBinding(
        agent_key=b64url_nopad(pub),
        signature_agent=agent,
        signature_input=f"{_POP_LABEL}={signature_input_inner(params)}",
        signature=f"{_POP_LABEL}=:{base64.b64encode(raw).decode()}:",
    )


def _freshness_failure(p: SigParams, now: int) -> str | None:
    if not p.created:
        return "pop_missing_created"
    if p.created > now + _MAX_FUTURE_SKEW_SEC:
        return "pop_future_created"
    if not p.expires:
        return "pop_missing_exp"
    if now >= p.expires:
        return "pop_expired"
    return None


def _covers_the_profile(p: SigParams) -> bool:
    """Whether the proof covers at least @method, @target-uri (plain) and a
    Signature-Agent reference; which member that is, is signature_directory's call."""
    plain_names = {component_name(c).lower() for c in p.covered if not c.params}
    names = {component_name(c).lower() for c in p.covered}
    return all(n in plain_names for n in _POP_REQUIRED) and "signature-agent" in names


def _refuse(reason: str, *, accept: bool = False) -> PopResult:
    accept_signature = POP_ACCEPT_SIGNATURE if accept else None
    return PopResult(ok=False, reason=reason, accept_signature=accept_signature)


def _parse(headers: Mapping[str, str]) -> tuple[SigParams, bytes, int] | PopResult:
    """The proof's first signature, its bytes and the signature count, or a refusal."""
    try:
        all_params, sig_map = parse_all_signatures(headers)
    except (MissingSignatureInputError, MissingSignatureError):
        return _refuse("missing_sig", accept=True)
    except SignatureCheckError:
        return _refuse("malformed_sig_input")
    p = all_params[0]
    return p, sig_map[p.label], len(all_params)


def verify_agent_binding(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    agent_id: str,
    now: int,
    verify_ed25519: Ed25519Verify | None = None,
) -> PopResult:
    """Verify the agent's proof of possession of the key bound to ``agent_id``.

    Returns ``ok=True`` only when every rule holds: the tag is ``web-bot-auth``; the
    signature covers AT LEAST @method, @target-uri and its Signature-Agent member, so a
    Web Bot Auth library's proof that also covers @authority verifies; the member
    names an https origin, in the dictionary form or the legacy
    String form; agent_id, keyid and the presented key's thumbprint agree; the window
    holds at ``now`` (unix seconds); and the Ed25519 signature over the base rebuilt
    with the verbatim URL verifies against the presented key. ``headers`` is
    lowercase-keyed.
    """
    presented = _read_presented_key(headers)
    if isinstance(presented, PopResult):
        return presented
    parsed = _parse(headers)
    if isinstance(parsed, PopResult):
        return parsed
    p, sig_bytes, sig_count = parsed
    if p.alg.lower() != "ed25519":
        return _refuse("unsupported_alg")
    if p.tag != WBATag:
        return _refuse("bad_tag", accept=True)
    if not _covers_the_profile(p):
        return _refuse("bad_covered_components", accept=True)
    try:
        directory = signature_directory(headers, p, sig_count)
    except MissingComponentError:
        return _refuse("bad_covered_components", accept=True)
    except SignatureProfileError:
        return _refuse("bad_signature_agent", accept=True)

    # 3-way identity: keyid and the presented-key thumbprint must both equal the
    # URL-bound agent_id before any signature work is trusted.
    if p.keyid != agent_id:
        return PopResult(ok=False, reason="keyid_mismatch")
    if thumbprint(presented) != agent_id:
        return PopResult(ok=False, reason="thumbprint_mismatch")

    stale = _freshness_failure(p, now)
    if stale is not None:
        return PopResult(ok=False, reason=stale)

    try:
        base = build_signature_base(method, url, headers, p).encode()
    except SignatureCheckError:
        # A covered component this request cannot supply: a header it does not carry,
        # or a derived component the verifier does not support.
        return _refuse("bad_covered_components", accept=True)
    verify = verify_ed25519 if verify_ed25519 is not None else _default_verify_ed25519
    if not verify(presented, sig_bytes, base):
        return PopResult(ok=False, reason="pop_sig_invalid")
    return PopResult(ok=True, signature_agent=directory)
