"""RFC 9421 signature-base construction and Signature-Input parsing, shared by the
request signer (:mod:`fora_sdk.httpsig`), the request verifier
(:mod:`fora_sdk._sigverify`), the delivery proof (:mod:`fora_sdk.pop`) and the key
directory's response signatures (:mod:`fora_sdk.directory_signature`).

The Python port of the Go oracle's sigbase.go and the parsing half of verify.go. The
base is the exact byte string both sides feed to Ed25519, so it is built in one place:
one line per covered component, in the signature's covered order, then the
``@signature-params`` line. On signing, that line carries the parameters as rendered
here; on verifying, it carries the signer's inner list VERBATIM from the wire, because
RFC 9421 §2.5 makes the parameter order the signer's choice.

A covered component is an :class:`~fora_sdk.sfv.Item` whose value is the component name
and whose parameters are the RFC 9421 component parameters: ``key`` selects a
Dictionary member (``"signature-agent";key="sig1"``), and ``req`` is a Boolean flag
(``"@authority";req``). Header values are read the RFC 9421 §2.1 way: every field line
under the name, matched case-insensitively and joined with ", ".
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from . import sfv
from .multisig_parse import raw_inner_by_label

if TYPE_CHECKING:
    from collections.abc import Mapping


class SignatureCheckError(Exception):
    """A request signature refused for a reason other than the profile's form.

    ``reason`` is a stable, fine-grained token (``"expired"``, ``"digest_mismatch"`` and
    so on) that the pure verifier reports and the server faces collapse to their own
    reject vocabulary. Never raised to an SDK caller: each verify face returns a verdict.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def component(name: str, **params: str | bool) -> sfv.Item:
    """A covered-component identifier named ``name`` carrying ``params``."""
    return sfv.Item(name, dict(params))


def plain(*names: str) -> list[sfv.Item]:
    """Covered components with no parameters."""
    return [sfv.Item(n) for n in names]


def component_name(c: sfv.Item) -> str:
    """The component name, as the signer wrote it."""
    return c.value if isinstance(c.value, str) else ""


def component_param(c: sfv.Item, key: str) -> str:
    """The String value of parameter ``key`` on ``c``, or "" when absent or a flag."""
    v = c.params.get(key)
    return v if isinstance(v, str) else ""


def render_component(c: sfv.Item) -> str:
    """The identifier as it appears in Signature-Input and on its base line:
    ``"name"`` then ``;k="v"`` per String parameter and ``;k`` per flag. The name is
    written verbatim, so the header and the base agree byte for byte."""
    out = ['"', component_name(c), '"']
    for key, value in c.params.items():
        out.append(";" + key)
        if value is not True:
            out.append("=" + sfv.serialize_bare_item(value))
    return "".join(out)


def same_component(a: sfv.Item, b: sfv.Item) -> bool:
    """The same name, compared case-insensitively, and the same parameters in order."""
    return component_name(a).lower() == component_name(b).lower() and list(
        a.params.items()
    ) == list(b.params.items())


def covers_component(covered: tuple[sfv.Item, ...] | list[sfv.Item], c: sfv.Item) -> bool:
    """Whether ``covered`` holds ``c`` by :func:`same_component`."""
    return any(same_component(s, c) for s in covered)


@dataclass(frozen=True)
class SigParams:
    """One signature's Signature-Input member: its label, covered set and parameters.

    ``raw_inner`` is the member value exactly as it arrived (everything after
    ``label=``), which the verifier terminates the base with. It is empty on the
    signing side, where the rendered inner is both what is signed and what is sent.
    """

    label: str
    covered: tuple[sfv.Item, ...]
    keyid: str = ""
    alg: str = ""
    created: int = 0
    expires: int = 0
    nonce: str = ""
    tag: str = ""
    raw_inner: str = ""


def render_params_tail(p: SigParams) -> str:
    """The signature parameters in the order the profile's examples use: created,
    expires, keyid, alg, nonce, tag. The order is the signer's choice; the three SDKs
    make the same one so their signatures agree byte for byte. An unset parameter is
    left out."""
    out: list[str] = []
    if p.created:
        out.append(f";created={p.created}")
    if p.expires:
        out.append(f";expires={p.expires}")
    if p.keyid:
        out.append(";keyid=" + sfv.serialize_bare_item(p.keyid))
    if p.alg:
        out.append(";alg=" + sfv.serialize_bare_item(p.alg))
    if p.nonce:
        out.append(f';nonce="{p.nonce}"')
    if p.tag:
        out.append(";tag=" + sfv.serialize_bare_item(p.tag))
    return "".join(out)


def signature_input_inner(p: SigParams) -> str:
    """The inner list and parameters: the Signature-Input member value and the
    ``@signature-params`` value of a signature being made."""
    return "(" + " ".join(render_component(c) for c in p.covered) + ")" + render_params_tail(p)


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest header value: ``sha-256=:<std-base64(SHA-256)>:``."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


# --- reading a request's headers -------------------------------------------------------


def header_lines(headers: Mapping[str, str], name: str) -> list[str]:
    """Every field line under ``name``, matched case-insensitively, in mapping order.

    Empty when the request carries no such field. A mapping cannot hold one name twice
    under one spelling, so two spellings of one name are two field lines of one field.
    """
    lower = name.lower()
    return [value for key, value in headers.items() if key.lower() == lower]


def joined_header(headers: Mapping[str, str], name: str) -> str | None:
    """The RFC 9421 §2.1 value of ``name``: every field line joined with ", " and
    trimmed, or None when the request carries none. Absent and empty differ: an empty
    covered header reconstructs to the empty value the signer bound."""
    lines = header_lines(headers, name)
    if not lines:
        return None
    return ", ".join(lines).strip()


# --- building the base -----------------------------------------------------------------


def component_value(method: str, url: str, headers: Mapping[str, str], c: sfv.Item) -> str:
    """The canonical value of one covered component on this request.

    ``@method`` is the method uppercased and ``@target-uri`` the absolute URL exactly as
    given; no other derived component is supported. A component carrying a ``key``
    parameter is a Dictionary member (:func:`member_value`); any other name is a header.
    A covered header the request does not carry cannot be reconstructed and is refused.
    """
    if c.params:
        return member_value(headers, c)
    name = component_name(c).lower()
    if name == "@method":
        return method.upper()
    if name == "@target-uri":
        return url
    value = joined_header(headers, name)
    if value is None:
        raise SignatureCheckError("missing_header", f"header {name!r} missing from request")
    return value


def member_value(headers: Mapping[str, str], c: sfv.Item) -> str:
    """The canonical serialization of the Dictionary member a ``key`` parameter names
    (RFC 9421 §2.1.2): a Signature-Agent member's String with its parameters, a
    Signature member's byte sequence, a Signature-Input member's inner list.

    Serializing the parsed member rather than splicing the wire text makes signer and
    verifier agree however the member was spaced. No other parameter is supported.
    """
    name = component_name(c)
    key = c.params.get("key")
    if name.startswith("@") or len(c.params) != 1 or not isinstance(key, str):
        raise SignatureCheckError("malformed_sig_input", f"unsupported parameters on {name!r}")
    lines = header_lines(headers, name)
    if not lines:
        raise SignatureCheckError("missing_header", f"header {name!r} missing from request")
    try:
        dictionary = sfv.parse_dictionary(lines)
    except sfv.StructuredFieldError as exc:
        raise SignatureCheckError("malformed_sig_input", f"{name} is not a dictionary") from exc
    member = dictionary.get(key)
    if member is None:
        raise SignatureCheckError("malformed_sig_input", f"{name} has no member {key!r}")
    try:
        return sfv.serialize_member(member)
    except sfv.StructuredFieldError as exc:  # pragma: no cover - a parsed member serializes
        raise SignatureCheckError("malformed_sig_input", f"serialize {name} member") from exc


def build_signature_base(method: str, url: str, headers: Mapping[str, str], p: SigParams) -> str:
    """The RFC 9421 §2.5 signature base over ``p``'s covered set, ending with the
    ``@signature-params`` line: the verbatim wire inner when ``p`` was parsed, the
    rendered one when it is being signed."""
    lines = [
        f"{render_component(c)}: {component_value(method, url, headers, c)}" for c in p.covered
    ]
    inner = p.raw_inner or signature_input_inner(p)
    lines.append(f'"@signature-params": {inner}')
    return "\n".join(lines)


def cover_earlier(own: list[sfv.Item], prev: SigParams) -> list[sfv.Item]:
    """Extend a new signature's covered set to cover ``prev`` as WG-00 §5.2.2 asks:
    every component ``prev`` lists that ``own`` lacks, then ``prev``'s Signature and
    Signature-Input members."""
    out = list(own)
    for c in prev.covered:
        if not covers_component(out, c):
            out.append(c)
    out.append(component("signature", key=prev.label))
    out.append(component("signature-input", key=prev.label))
    return out


# --- parsing Signature-Input and Signature ---------------------------------------------


class MissingSignatureInputError(SignatureCheckError):
    """The request carries no Signature-Input header."""

    def __init__(self) -> None:
        super().__init__("missing_sig_input")


class MissingSignatureError(SignatureCheckError):
    """The request carries no Signature header."""

    def __init__(self) -> None:
        super().__init__("missing_sig")


def parse_all_signatures(
    headers: Mapping[str, str],
) -> tuple[list[SigParams], dict[str, bytes]]:
    """Every signature on the request, in Signature-Input order, and each label's
    signature bytes. One signature is the N=1 case of the same parse.

    Raises :class:`MissingSignatureInputError` / :class:`MissingSignatureError` for an
    absent header, and ``SignatureCheckError("malformed_sig_input")`` for a header that
    is not a structured-field Dictionary, a member that is not an inner list, a
    parameter of the wrong type, a signature with no keyid, or a label Signature lacks.
    """
    input_lines = header_lines(headers, "signature-input")
    if not input_lines:
        raise MissingSignatureInputError
    sig_lines = header_lines(headers, "signature")
    if not sig_lines:
        raise MissingSignatureError
    try:
        inputs = sfv.parse_dictionary(input_lines)
        sigs = sfv.parse_dictionary(sig_lines)
    except sfv.StructuredFieldError as exc:
        raise SignatureCheckError("malformed_sig_input", str(exc)) from exc
    if not inputs:
        raise SignatureCheckError("malformed_sig_input", "no labels found")
    raw = raw_inner_by_label(input_lines)
    params: list[SigParams] = []
    sig_map: dict[str, bytes] = {}
    for label, member in inputs.items():
        params.append(_parse_input_member(label, member, raw.get(label, "")))
        sig_map[label] = _signature_bytes(sigs, label)
    return params, sig_map


def _parse_input_member(label: str, member: sfv.Member, raw_inner: str) -> SigParams:
    if not isinstance(member, sfv.InnerList):
        raise SignatureCheckError("malformed_sig_input", f"label {label!r} is not an inner list")
    covered = tuple(_covered_from_item(i) for i in member.items)
    keyid = _str_param(member.params, "keyid")
    if not keyid:
        raise SignatureCheckError("malformed_sig_input", "keyid required")
    return SigParams(
        label=label,
        covered=covered,
        keyid=keyid,
        alg=_str_param(member.params, "alg"),
        created=_int_param(member.params, "created"),
        expires=_int_param(member.params, "expires"),
        nonce=_str_param(member.params, "nonce"),
        tag=_str_param(member.params, "tag"),
        raw_inner=raw_inner,
    )


def _covered_from_item(item: sfv.Item) -> sfv.Item:
    """A covered-component identifier: a String name whose parameters are Strings or
    Boolean flags. ``key`` is the one a request signature uses and ``req`` the one a
    directory response signature uses."""
    if not isinstance(item.value, str):
        raise SignatureCheckError("malformed_sig_input", "component identifier not a string")
    for key, value in item.params.items():
        if value is not True and not isinstance(value, str):
            raise SignatureCheckError(
                "malformed_sig_input", f"component param {key!r} not a string"
            )
    return item


def _str_param(params: sfv.Params, name: str) -> str:
    if name not in params:
        return ""
    v = params[name]
    if not isinstance(v, str):
        raise SignatureCheckError("malformed_sig_input", f"{name} not a string")
    return v


def _int_param(params: sfv.Params, name: str) -> int:
    if name not in params:
        return 0
    v = params[name]
    if isinstance(v, bool) or not isinstance(v, int):
        raise SignatureCheckError("malformed_sig_input", f"{name} not an integer")
    return v


def _signature_bytes(sigs: dict[str, sfv.Member], label: str) -> bytes:
    member = sigs.get(label)
    if member is None:
        raise SignatureCheckError("malformed_sig_input", f"Signature label {label!r} not present")
    if not isinstance(member, sfv.Item) or not isinstance(member.value, bytes):
        raise SignatureCheckError("malformed_sig_input", "Signature value not a byte sequence")
    return member.value
