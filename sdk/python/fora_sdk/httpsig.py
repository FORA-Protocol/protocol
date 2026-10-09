"""RFC 9421 Ed25519 request signing + verification under the Web Bot Auth profile —
pure, IO-free L1 helper.

The byte oracle is the Go ``SignRequest`` / ``AppendSignature`` (sdk/go/helpers/sign.go)
over ``buildSignatureBase`` (sigbase.go), and ``VerifyRequest`` (verify.go). The port
produces, byte for byte, the signature base, Signature-Input, Signature and
Signature-Agent the Go oracle emits, pinned to the shared
sdk/go/helpers/testdata/sign-request-vectors.json and multisig-chain-vectors.json.

One signature labelled L, by an agent whose key directory is the https origin O::

    Signature-Agent: L="O"
    Signature-Input: L=("@method" "@target-uri" "content-digest" "authorization"
                        "signature-agent";key="L");created=C;expires=E;keyid="K";
                        alg="ed25519";nonce="N";tag="web-bot-auth"
    Signature: L=:<standard base64>:

The covered set is the FORA RPC set (@method and @target-uri bind the verb and the
destination, content-digest the body, authorization the bearer) plus the signature's
own Signature-Agent member, which names the directory a verifier resolves the keyid
in. ``created``/``expires`` are INJECTED — sign reads no wall clock — and the window is
at most :data:`~fora_sdk.wba.MAX_SIGNATURE_LIFETIME`. ``@target-uri`` is the supplied
absolute URL verbatim.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ._sigbase import (
    SignatureCheckError,
    SigParams,
    build_signature_base,
    content_digest,
    cover_earlier,
    parse_all_signatures,
    plain,
    signature_input_inner,
)
from ._sigverify import Request, failure_reason, verify_first
from .wba import (
    MAX_SIGNATURE_LIFETIME,
    InvalidNonceError,
    SignatureAgentRequiredError,
    SignatureLabelError,
    SignatureLifetimeError,
    SignatureProfileError,
    accept_signature_for,
    check_https_origin,
    next_free_label,
    signature_agent_component,
    signature_agent_dictionary,
    signature_agent_member,
    used_labels,
    valid_label,
    valid_nonce,
)
from .wire import WBATag

#: The FORA RPC components every request signature covers, before its own
#: Signature-Agent member.
_RPC_COMPONENTS: tuple[str, ...] = ("@method", "@target-uri", "content-digest", "authorization")


@dataclass(frozen=True)
class SignedRequest:
    """The RFC 9421 headers + the signature base produced for a request.

    EVERY covered header is here, at the value that entered the base, so a caller
    attaching what this returns sends what was signed. The oracle reaches the same place
    by mutating the request it was handed (``helpers.SignRequest``), which is why it has
    no such field to omit. See docs/design-history.md, "A covered header the peer never
    receives is not bound".
    """

    content_digest: str
    signature_input: str
    signature: str
    signature_base: str
    #: Echoed from the input. Empty is a value, not an absence, and REQUIRED, no
    #: default: a field that can be left out re-creates the "empty is a safe default"
    #: assumption the transport relies on this echo to remove.
    authorization: str
    #: The Signature-Agent header value to send: the request's dictionary with this
    #: signature's member ``<label>="<origin>"`` in it.
    signature_agent: str


@dataclass(frozen=True)
class VerifiedRequest:
    """Verdict of an RFC 9421 request verification.

    ``signature_agent`` is, on success, the https origin of the key directory the
    signature's own covered Signature-Agent member names. ``accept_signature`` is, on a
    refusal for a missing component, a wrong tag, a Signature-Agent form the profile
    refuses or a request carrying no signature, the Accept-Signature value to answer
    with (:func:`fora_sdk.wba.accept_signature`); None otherwise.
    """

    valid: bool
    reason: str | None = None
    signature_agent: str | None = None
    accept_signature: str | None = None


def _check_sign_options(signature_agent: str, label: str, created: int, expires: int) -> None:
    """Refuse what no conformant signature can carry: a missing or non-origin
    Signature-Agent, an unusable label, or a window that is not positive or longer than
    MAX_SIGNATURE_LIFETIME."""
    if signature_agent == "":
        raise SignatureAgentRequiredError("a signature needs the signer's Signature-Agent origin")
    check_https_origin(signature_agent)
    if not valid_label(label):
        raise SignatureLabelError(f"signature label is not a structured-field key: {label!r}")
    life = expires - created
    if created <= 0 or life <= 0 or life > MAX_SIGNATURE_LIFETIME:
        raise SignatureLifetimeError(
            f"signature lifetime must be positive and at most {MAX_SIGNATURE_LIFETIME}s: "
            f"created={created} expires={expires}"
        )


def _sign(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    params: SigParams,
    signer_seed: bytes,
) -> tuple[str, str, str]:
    """Build the base for ``params``, sign it; return (base, input member, sig member)."""
    if not valid_nonce(params.nonce):
        raise InvalidNonceError("nonce must use only base64url characters")
    base = build_signature_base(method, url, headers, params)
    sig = Ed25519PrivateKey.from_private_bytes(signer_seed).sign(base.encode())
    member_input = f"{params.label}={signature_input_inner(params)}"
    member_sig = f"{params.label}=:{base64.b64encode(sig).decode()}:"
    return base, member_input, member_sig


def sign_request(
    *,
    method: str,
    url: str,
    body: bytes,
    authorization: str,
    signer_seed: bytes,
    keyid: str,
    created: int,
    expires: int,
    signature_agent: str = "",
    nonce: str = "",
    label: str = "",
) -> SignedRequest:
    """Sign a request as a FORA RPC under the Web Bot Auth profile; return the headers.

    ``signature_agent`` is the signer's key-directory origin, such as
    ``"https://agent.example"``. It is required: the emitted Signature-Agent is the
    one-member dictionary ``<label>="<origin>"``, and the signature covers that member.
    ``label`` defaults to ``sig1``. ``created``/``expires`` are injected unix seconds.

    Authorization is always bound — pass an empty string when the caller holds no token,
    which BINDS that emptiness. The header is still emitted and still sent; an absent
    header is a different thing entirely and a verifier refuses it.

    ``nonce``, when non-empty, is emitted as the RFC 9421 ``nonce`` parameter. Ed25519
    is deterministic and the timestamps have one-second resolution, so identical
    requests signed in the same second produce the same signature and a replay store
    refuses the second. The helper reads no RNG: a caller that needs unique signatures
    supplies a fresh nonce (``SigningTransport`` does).

    Raises :class:`~fora_sdk.wba.SignatureAgentRequiredError`,
    :class:`~fora_sdk.wba.SignatureAgentNotOriginError`,
    :class:`~fora_sdk.wba.SignatureLabelError`,
    :class:`~fora_sdk.wba.SignatureLifetimeError` or
    :class:`~fora_sdk.wba.InvalidNonceError`, before anything is signed.
    """
    label = label or "sig1"
    _check_sign_options(signature_agent, label, created, expires)
    digest_header = content_digest(body)
    agent = signature_agent_member(label, signature_agent)
    params = _request_params(label, keyid, created, expires, nonce)
    headers = {
        "content-digest": digest_header,
        "authorization": authorization,
        "signature-agent": agent,
    }
    base, member_input, member_sig = _sign(
        method=method, url=url, headers=headers, params=params, signer_seed=signer_seed
    )
    return SignedRequest(
        content_digest=digest_header,
        signature_input=member_input,
        signature=member_sig,
        signature_base=base,
        authorization=authorization,
        signature_agent=agent,
    )


def _request_params(label: str, keyid: str, created: int, expires: int, nonce: str) -> SigParams:
    """The parameters of a FORA RPC signature labelled ``label``."""
    return SigParams(
        label=label,
        covered=(*plain(*_RPC_COMPONENTS), signature_agent_component(label)),
        keyid=keyid,
        alg="ed25519",
        created=created,
        expires=expires,
        nonce=nonce,
        tag=WBATag,
    )


def append_signature(
    *,
    method: str,
    url: str,
    body: bytes,
    authorization: str,
    signer_seed: bytes,
    keyid: str,
    created: int,
    expires: int,
    signature_agent: str = "",
    prev_signature_input: str = "",
    prev_signature: str = "",
    prev_signature_agent: str = "",
    nonce: str = "",
    label: str = "",
    cover_previous: bool = False,
) -> SignedRequest:
    """Add a signature to a request WITHOUT disturbing any signature already on it, the
    Python port of Go ``helpers.AppendSignature``.

    ``prev_signature_input``, ``prev_signature`` and ``prev_signature_agent`` are the
    request's current Signature-Input, Signature and Signature-Agent values (empty for
    an unsigned request). The new signature's member ``<label>="<signature_agent>"`` is
    appended to the Signature-Agent dictionary, and its Signature-Input and Signature
    members to theirs; the returned values are the whole new headers. ``label`` defaults
    to the first ``sigN`` no signature or member on the request uses; an explicit one
    must be a free structured-field key.

    The new signature covers its own request components and its own member only, unless
    ``cover_previous`` is set: then it also covers the LAST signature already on the
    request completely, as WG-00 §5.2.2 permits a party that forwards a request
    unchanged — every component that signature lists, its Signature member and its
    Signature-Input member. With no earlier signature it is a no-op, and appending to an
    unsigned request produces the same headers as :func:`sign_request`.

    A Signature-Agent that is not a dictionary, such as an agent's legacy String form,
    raises :class:`~fora_sdk.wba.SignatureAgentFormError`: a String cannot take a second
    member, and rewriting it would break the earlier signature. The other refusals are
    those of :func:`sign_request`, plus :class:`~fora_sdk.wba.SignatureLabelError` for a
    label already in use.
    """
    prev = {
        "signature-input": prev_signature_input,
        "signature": prev_signature,
        "signature-agent": prev_signature_agent,
    }
    prev = {name: value for name, value in prev.items() if value.strip() != ""}
    label = label or next_free_label(prev)
    _check_sign_options(signature_agent, label, created, expires)
    if label in used_labels(prev):
        raise SignatureLabelError(f"signature label {label!r} is already in use on the request")
    signature_agent_dictionary(prev)
    earlier = _last_signature(prev) if cover_previous else None
    digest_header = content_digest(body)
    agent = signature_agent_member(label, signature_agent)
    if "signature-agent" in prev:
        agent = prev["signature-agent"].strip() + ", " + agent
    params = _request_params(label, keyid, created, expires, nonce)
    if earlier is not None:
        params = SigParams(
            label=params.label,
            covered=tuple(cover_earlier(list(params.covered), earlier)),
            keyid=params.keyid,
            alg=params.alg,
            created=params.created,
            expires=params.expires,
            nonce=params.nonce,
            tag=params.tag,
        )
    headers = {
        **prev,
        "content-digest": digest_header,
        "authorization": authorization,
        "signature-agent": agent,
    }
    base, member_input, member_sig = _sign(
        method=method, url=url, headers=headers, params=params, signer_seed=signer_seed
    )
    return SignedRequest(
        content_digest=digest_header,
        signature_input=_append_member(prev.get("signature-input"), member_input),
        signature=_append_member(prev.get("signature"), member_sig),
        signature_base=base,
        authorization=authorization,
        signature_agent=agent,
    )


def _last_signature(prev: dict[str, str]) -> SigParams | None:
    """The last signature on the request in header order, or None when it has none."""
    if "signature-input" not in prev:
        return None
    try:
        all_params, _ = parse_all_signatures(prev)
    except SignatureCheckError as exc:
        raise ValueError(f"cover previous signature: {exc}") from exc
    return all_params[-1]


def _append_member(existing: str | None, member: str) -> str:
    return f"{existing.strip()}, {member}" if existing else member


def verify_request(
    *,
    method: str,
    url: str,
    body: bytes,
    signature_input: str,
    signature: str,
    content_digest: str,
    authorization: str,
    pubkey: bytes,
    now: int,
    signature_agent: str = "",
) -> VerifiedRequest:
    """Verify the request's first RFC 9421 signature against ``pubkey`` at ``now``.

    ``signature_agent`` is the request's Signature-Agent header value ("" when the
    request carries none); ``content_digest`` its Content-Digest. Every rule of the
    profile applies, as in Go ``helpers.VerifyRequest``: alg ed25519, tag web-bot-auth,
    the FORA RPC components and the signature's own Signature-Agent member covered, the
    member an https origin, the digest, the created/expires window, and the Ed25519
    signature over the rebuilt base. Pure: the key and ``now`` are injected. The verdict
    reports the directory the member names, and, for the refusals the profile answers
    that way, the Accept-Signature value.
    """
    headers = {
        "signature-input": signature_input,
        "signature": signature,
        "content-digest": content_digest,
        "authorization": authorization,
    }
    if signature_agent != "":
        headers["signature-agent"] = signature_agent
    request = Request(method=method, url=url, body=body, headers=headers)
    try:
        verified = verify_first(request, lambda _directory, _keyid: pubkey, now=now)
    except (SignatureCheckError, SignatureProfileError) as exc:
        return VerifiedRequest(
            valid=False, reason=failure_reason(exc), accept_signature=accept_signature_for(exc)
        )
    return VerifiedRequest(valid=True, signature_agent=verified.signature_agent)


# The framework-agnostic SERVER-verify faces live in server_verify.py (they compose the
# shared verification core with the injected resolver / replay store / clock).
# Re-export them here so a Broker/Exchange imports the whole request-verify surface —
# primitive + server entry — from fora_sdk.httpsig.
from .server_verify import (  # noqa: E402
    MultisigVerdict,
    RejectReason,
    ReplayStore,
    verify_multisig_request_server,
    verify_request_server,
)

__all__ = [
    "MultisigVerdict",
    "RejectReason",
    "ReplayStore",
    "SignedRequest",
    "VerifiedRequest",
    "append_signature",
    "content_digest",
    "sign_request",
    "verify_multisig_request_server",
    "verify_request",
    "verify_request_server",
]
