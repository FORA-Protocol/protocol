"""The Web Bot Auth profile of RFC 9421 request signatures, as FORA pins it:
draft-ietf-webbotauth-httpsig-protocol-00 ("WG-00"). The Python port of the Go
oracle's helpers/wba.go: the pieces of the profile the signer and the verifier share.

- Signature-Agent is a structured-field Dictionary. The member for a signature is
  ``<label>="https://<origin>"``, and the signature covers it as
  ``"signature-agent";key="<label>"``. Each signature's keyid is resolved in the key
  directory its own covered member names.
- Every signature carries created, expires, keyid, alg="ed25519" and
  tag="web-bot-auth"; a FORA signer adds a fresh nonce, and the window is at most
  :data:`MAX_SIGNATURE_LIFETIME`.
- A verifier also accepts the legacy sf-string form of Signature-Agent, covered as
  plain ``"signature-agent"``, on a request carrying one signature, a member key that
  differs from the label, no nonce, and a ``type=directory`` member parameter. It
  refuses the bare unquoted value the v1.0.8 SDKs sent.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from . import sfv
from ._sigbase import (
    MissingSignatureError,
    MissingSignatureInputError,
    component,
    component_name,
    component_param,
    header_lines,
    plain,
    render_component,
)
from .wire import WBATag

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ._sigbase import SigParams

#: The longest window (``expires - created``, in seconds) a FORA signer gives a request
#: signature. A signature is never a long-lived credential.
MAX_SIGNATURE_LIFETIME = 300

#: The only value of a Signature-Agent member's ``type`` parameter that names a key
#: directory (WG-00 §5.2.1).
_DIRECTORY_TYPE = "directory"
_SIGNATURE_AGENT = "signature-agent"
_ENTITLEMENT = "x-entitlement-token"
_MAX_PORT = 65535
_DEFAULT_PORT = 443
_ASCII_LOW = 0x21
_ASCII_HIGH = 0x80


class SignatureProfileError(ValueError):
    """Base of the refusals of a signature's form under the Web Bot Auth profile.

    The signing helpers raise the sign-side ones before anything is signed, and the
    client reports each of them as a malformed call, never as a peer that did not
    answer.
    """


class SignatureAgentRequiredError(SignatureProfileError):
    """A signing call given no Signature-Agent origin. Every Web Bot Auth signature
    names its signer's key directory (Go ``ErrSignatureAgentRequired``)."""


class SignatureAgentNotOriginError(SignatureProfileError):
    """A Signature-Agent value that is not the ASCII serialization of an https origin:
    ``https://host[:port]``, lowercase, with no path, query, fragment or credentials and
    no default port (Go ``ErrSignatureAgentNotOrigin``)."""


class SignatureAgentFormError(SignatureProfileError):
    """A Signature-Agent the profile does not accept: the bare unquoted value, a member
    the signature names but the dictionary does not carry, a member that is not a String
    or whose type is not directory, the legacy String form on a request carrying more
    than one signature, a signature covering several members none of which is keyed to
    its label, or, when appending, a Signature-Agent that is not a dictionary (Go
    ``ErrSignatureAgentForm``)."""


class SignatureLabelError(SignatureProfileError):
    """A signature label that is not a structured-field key, or one already used by a
    signature or a Signature-Agent member on the request (Go ``ErrSignatureLabel``)."""


class SignatureLifetimeError(SignatureProfileError):
    """A signing window that is not positive or is longer than
    :data:`MAX_SIGNATURE_LIFETIME` (Go ``ErrSignatureLifetime``)."""


class InvalidNonceError(SignatureProfileError):
    """A nonce with a character outside the base64url alphabet (Go ``ErrInvalidNonce``).
    The three SDKs apply the same rule, so a nonce one accepts is written as the same
    bytes by all three, and a quote cannot end the quoted parameter early."""


class SignatureTagError(SignatureProfileError):
    """A signature with no tag, or a tag other than ``web-bot-auth`` (Go
    ``ErrSignatureTag``)."""


class MissingComponentError(SignatureProfileError):
    """A signature that does not cover a component the route requires."""

    def __init__(self, component_name: str) -> None:
        super().__init__(f"required covered component missing: {component_name}")
        #: The lowercase name of the component the signature omits.
        self.component = component_name


def check_https_origin(s: str) -> None:
    """Refuse ``s`` unless it is the ASCII serialization of an https origin, the only
    value a Signature-Agent member carries in this profile.

    Accepted: ``https://`` then a lowercase host (an IP literal allowed, an IPv6 one in
    brackets) and, only when it is not 443, ``:port``. Anything else raises
    :class:`SignatureAgentNotOriginError`: another scheme, uppercase, a path (even
    ``/``), a query, a fragment, credentials, or a non-ASCII host, which an origin
    carries punycoded. The Python port of Go ``CheckHTTPSOrigin``.
    """
    if not s.startswith("https://"):
        raise SignatureAgentNotOriginError(f"{s!r} does not start with https://")
    rest = s[len("https://") :]
    if rest == "" or any(c in rest for c in "/?#@\\%"):
        raise SignatureAgentNotOriginError(f"{s!r} carries more than a host and port")
    if any(ord(c) >= _ASCII_HIGH or ord(c) < _ASCII_LOW or "A" <= c <= "Z" for c in rest):
        raise SignatureAgentNotOriginError(f"{s!r} is not a lowercase ASCII origin")
    host, port, has_port = _split_host_port(rest)
    if host is None:
        raise SignatureAgentNotOriginError(f"{s!r} is not a host[:port]")
    if ":" in host:
        if not _is_ip(host):
            raise SignatureAgentNotOriginError(f"{s!r} is not a host[:port]")
    elif not _is_origin_host_name(host):
        raise SignatureAgentNotOriginError(f"{s!r} is not a host[:port]")
    if has_port:
        if not port.isdigit() or port[0] == "0" or not 0 < int(port) <= _MAX_PORT:
            raise SignatureAgentNotOriginError(f"{s!r} carries an invalid port")
        if int(port) == _DEFAULT_PORT:
            raise SignatureAgentNotOriginError(f"{s!r} spells out the default port")


def _split_host_port(rest: str) -> tuple[str | None, str, bool]:
    """Split ``host[:port]`` the way Go's URL parser does: a bracketed IPv6 literal, or a
    host with at most one colon. Returns ``(None, "", False)`` for a value that is not
    one."""
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return None, "", False
        host, after = rest[1:close], rest[close + 1 :]
        if after == "":
            return (host or None), "", False
        if not after.startswith(":"):
            return None, "", False
        return (host or None), after[1:], True
    host, colon, port = rest.partition(":")
    if ":" in port:
        return None, "", False
    return (host or None), port, colon == ":"


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_origin_host_name(name: str) -> bool:
    """A lowercase registered name or IPv4 literal: letters, digits, '-', '.' and '_'
    only, with no empty label."""
    if name == "" or name.startswith(".") or ".." in name:
        return False
    return all(c.isascii() and (c.islower() or c.isdigit() or c in "-._") for c in name)


def valid_label(label: str) -> bool:
    """Whether ``label`` is a structured-field key (RFC 8941 §3.1.2)."""
    try:
        sfv.serialize_key(label)
    except sfv.StructuredFieldError:
        return False
    return True


def valid_nonce(nonce: str) -> bool:
    """Whether ``nonce`` is empty or uses only base64url characters (A-Z a-z 0-9 - _)."""
    return all(c.isascii() and (c.isalnum() or c in "-_") for c in nonce)


def signature_agent_member(label: str, origin: str) -> str:
    """One Signature-Agent dictionary member for ``label``. ``origin`` has passed
    :func:`check_https_origin`, so it carries no character a String would escape."""
    return f'{label}="{origin}"'


def signature_agent_component(label: str) -> sfv.Item:
    """The covered-component identifier binding a signature to its own member."""
    return component(_SIGNATURE_AGENT, key=label)


def used_labels(headers: Mapping[str, str]) -> set[str]:
    """Every label already on the request: the members of Signature-Input and Signature
    and the keys of a Signature-Agent dictionary. A new signature takes a label none of
    them uses, so its member cannot collide with another signature's."""
    used: set[str] = set()
    for name in ("signature-input", "signature", _SIGNATURE_AGENT):
        lines = header_lines(headers, name)
        if not lines:
            continue
        try:
            used.update(sfv.parse_dictionary(lines))
        except sfv.StructuredFieldError:
            continue
    return used


def next_free_label(headers: Mapping[str, str]) -> str:
    """``sigN`` for the smallest N >= 1 no label on the request uses."""
    used = used_labels(headers)
    n = 1
    while f"sig{n}" in used:
        n += 1
    return f"sig{n}"


def signature_agent_dictionary(headers: Mapping[str, str]) -> dict[str, sfv.Member]:
    """The request's Signature-Agent as a Dictionary, its field lines joined. An absent
    or empty header is an empty dictionary; one that does not parse as a Dictionary,
    such as the legacy String form, raises :class:`SignatureAgentFormError`."""
    lines = header_lines(headers, _SIGNATURE_AGENT)
    if ", ".join(lines).strip() == "":
        return {}
    try:
        return sfv.parse_dictionary(lines)
    except sfv.StructuredFieldError as exc:
        raise SignatureAgentFormError(f"Signature-Agent is not a dictionary: {exc}") from exc


def _directory_from_member(member: sfv.Member, key: str) -> str:
    """A Signature-Agent member read as a key directory's origin. The member must be a
    String; a ``type`` parameter, when present, must be ``directory``, since WG-00
    §5.2.1 has a verifier ignore a member of any other type."""
    if isinstance(member, sfv.InnerList):
        raise SignatureAgentFormError(f"member {key!r} is an inner list")
    if not isinstance(member.value, str):
        raise SignatureAgentFormError(f"member {key!r} is not a String")
    if "type" in member.params and not _is_directory_type(member.params["type"]):
        raise SignatureAgentFormError(f"member {key!r} has a type other than directory")
    check_https_origin(member.value)
    return member.value


def _is_directory_type(v: sfv.BareItem) -> bool:
    if isinstance(v, sfv.Token):
        return v.value == _DIRECTORY_TYPE
    return isinstance(v, str) and v == _DIRECTORY_TYPE


def _legacy_directory(headers: Mapping[str, str]) -> str:
    """A Signature-Agent in the legacy form: one String, covered as plain
    ``"signature-agent"``. The bare unquoted value parses as a Token and is refused."""
    lines = header_lines(headers, _SIGNATURE_AGENT)
    if not lines:
        raise MissingComponentError(_SIGNATURE_AGENT)
    try:
        item = sfv.parse_item(", ".join(lines))
    except sfv.StructuredFieldError as exc:
        raise SignatureAgentFormError(f"Signature-Agent is not a String: {exc}") from exc
    if not isinstance(item.value, str):
        raise SignatureAgentFormError("the legacy form must be a quoted String")
    check_https_origin(item.value)
    return item.value


def _covered_members(p: SigParams) -> tuple[list[str], int]:
    """The keys of the Signature-Agent members ``p`` covers, and how many times it
    covers the field plainly. Any other parameter is a form the profile refuses."""
    keyed: list[str] = []
    plain_count = 0
    for c in p.covered:
        if component_name(c).lower() != _SIGNATURE_AGENT:
            continue
        key = component_param(c, "key")
        if key and len(c.params) == 1:
            keyed.append(key)
        elif not c.params:
            plain_count += 1
        else:
            raise SignatureAgentFormError("unsupported parameter on the signature-agent component")
    return keyed, plain_count


def signature_directory(headers: Mapping[str, str], p: SigParams, sig_count: int) -> str:
    """The key-directory origin a signature names: the Signature-Agent member it covers.

    A signature covering exactly one member follows it, whatever its key, because the
    profile accepts a member key that differs from the label. A signature that covers an
    earlier one also covers that one's member (WG-00 §5.2.2), so among several the one
    keyed to its own label is followed; none keyed to it is a form error. The legacy
    String form, covered as plain ``"signature-agent"``, is accepted only on a request
    carrying one signature (``sig_count``). The Python port of Go ``signatureDirectory``.
    """
    keyed, plain_count = _covered_members(p)
    if plain_count == 0 and not keyed:
        raise MissingComponentError(_SIGNATURE_AGENT)
    if plain_count > 1 or (plain_count == 1 and keyed):
        raise SignatureAgentFormError("the signature covers Signature-Agent in more than one form")
    if plain_count == 1:
        if sig_count > 1:
            raise SignatureAgentFormError(
                "the legacy String form is accepted only on a request carrying one signature"
            )
        return _legacy_directory(headers)
    key = keyed[0]
    if len(keyed) > 1:
        if p.label not in keyed:
            raise SignatureAgentFormError(
                f"{p.label} covers several Signature-Agent members and none keyed to its label"
            )
        key = p.label
    if not header_lines(headers, _SIGNATURE_AGENT):
        raise MissingComponentError(_SIGNATURE_AGENT)
    member = signature_agent_dictionary(headers).get(key)
    if member is None:
        raise SignatureAgentFormError(f"no member {key!r}")
    return _directory_from_member(member, key)


def accept_signature(entitlement: bool = False) -> str:
    """The Accept-Signature value a FORA verifier answers a refused RPC signature with:
    the components a FORA RPC signature must cover, the dictionary form of
    Signature-Agent, and the created, expires and tag parameters (RFC 9421 §5.1,
    WG-00 §5.3). ``entitlement`` adds ``x-entitlement-token``, for a request carrying
    that header."""
    covered = [
        *plain("@method", "@target-uri", "content-digest", "authorization"),
        signature_agent_component("sig1"),
    ]
    if entitlement:
        covered.append(component(_ENTITLEMENT))
    listed = " ".join(render_component(c) for c in covered)
    return f'sig1=({listed});created;expires;tag="{WBATag}"'


def accept_signature_for(exc: BaseException) -> str | None:
    """The Accept-Signature value a verifier answers ``exc`` with, or None when it
    answers with none.

    It does for every refusal the client can fix by signing again as the profile
    requires: a request carrying no signature, a signature that omits a required
    component, a signature with the wrong tag, a Signature-Agent in a form the profile
    refuses, and a member that is not an https origin. It does not for a signature that
    is well formed and fails for any other reason: a malformed Signature-Input, a bad
    signature, an unknown key, a stale window, a replay, a hop budget or a broken chain.
    """
    if isinstance(exc, MissingComponentError):
        return accept_signature(exc.component == _ENTITLEMENT)
    refused_form = (
        MissingSignatureInputError,
        MissingSignatureError,
        SignatureTagError,
        SignatureAgentFormError,
        SignatureAgentNotOriginError,
    )
    if isinstance(exc, refused_form):
        return accept_signature(False)
    return None
