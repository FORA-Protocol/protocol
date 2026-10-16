"""RFC 8941 structured field values: the parser and serializer the signature code reads
Signature-Input, Signature and Signature-Agent with.

The Go oracle delegates this to dunglas/httpsfv; Python ships no structured-field
library in its dependency set, so the subset the Web Bot Auth profile meets is written
out here once, against the RFC's own parsing algorithms (§4.2) and serialization
algorithms (§4.1): Dictionaries, Items, Inner Lists and Parameters, over Integers,
Decimals, Strings, Tokens, Byte Sequences and Booleans. Lists are not parsed: no field
this SDK reads is a List.

A field the RFC says to fail on raises :class:`StructuredFieldError` — never a partial
result. Repeated keys follow the RFC's last-wins rule, keeping the first position,
which a Python ``dict`` does by itself. A Token is its own type rather than a ``str``,
because the profile treats the two differently: the legacy Signature-Agent value is a
String, and the bare v1.0.8 value, which parses as a Token, is refused.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Decimal
from typing import TypeAlias


class StructuredFieldError(ValueError):
    """A field value that is not a valid RFC 8941 structured field, or a value that
    cannot be serialized as one."""


@dataclass(frozen=True)
class Token:
    """An RFC 8941 Token (§3.3.4): an unquoted identifier such as ``directory``."""

    value: str


#: A bare item (RFC 8941 §3.3). ``bool`` is listed first on purpose: it is a subclass
#: of ``int`` in Python, so every type test checks it before ``int``.
BareItem: TypeAlias = bool | int | Decimal | str | Token | bytes
#: Parameters (§3.1.2), in the order they appeared.
Params: TypeAlias = dict[str, BareItem]


@dataclass(frozen=True)
class Item:
    """An Item (§3.3): a bare item and its parameters."""

    value: BareItem
    params: Params = field(default_factory=dict)


@dataclass(frozen=True)
class InnerList:
    """An Inner List (§3.1.1): items in order, and the list's own parameters."""

    items: tuple[Item, ...]
    params: Params = field(default_factory=dict)


#: A Dictionary member value (§3.2).
Member: TypeAlias = Item | InnerList

_MAX_INTEGER = 999_999_999_999_999
_MAX_INTEGER_DIGITS = 15
_MAX_DECIMAL_INT_DIGITS = 12
_MAX_DECIMAL_FRACTION_DIGITS = 3
_MAX_DECIMAL_DIGITS = 16
_PRINTABLE_LOW = 0x20
_PRINTABLE_HIGH = 0x7E
_LCALPHA = frozenset("abcdefghijklmnopqrstuvwxyz")
_DIGIT = frozenset("0123456789")
_ALPHA = _LCALPHA | frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_KEY_REST = _LCALPHA | _DIGIT | frozenset("_-.*")
_TCHAR = _ALPHA | _DIGIT | frozenset("!#$%&'*+-.^_`|~")
_TOKEN_REST = _TCHAR | frozenset(":/")
_BASE64 = _ALPHA | _DIGIT | frozenset("+/=")


class _Reader:
    """The input string and the position parsing has reached in it."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def take(self) -> str:
        c = self.peek()
        self.pos += 1
        return c

    def done(self) -> bool:
        return self.pos >= len(self.text)

    def skip(self, chars: str) -> None:
        while not self.done() and self.text[self.pos] in chars:
            self.pos += 1

    def fail(self, what: str) -> StructuredFieldError:
        return StructuredFieldError(f"{what} at offset {self.pos} of {self.text!r}")


def join_field_lines(lines: list[str]) -> str:
    """Every field line of one field joined the way RFC 8941 §4.2 combines them."""
    return ", ".join(lines)


def parse_dictionary(value: str | list[str]) -> dict[str, Member]:
    """Parse a Dictionary field (§4.2.2). A list is the field's lines, joined first."""
    r = _Reader(join_field_lines(value) if isinstance(value, list) else value)
    r.skip(" ")
    out: dict[str, Member] = {}
    while not r.done():
        key = _parse_key(r)
        if r.peek() == "=":
            r.take()
            out[key] = _parse_item_or_inner_list(r)
        else:
            out[key] = Item(True, _parse_parameters(r))
        r.skip(" \t")
        if r.done():
            break
        if r.take() != ",":
            raise r.fail("expected ',' between dictionary members")
        r.skip(" \t")
        if r.done():
            raise r.fail("trailing ',' after the last dictionary member")
    return out


def parse_item(value: str | list[str]) -> Item:
    """Parse an Item field (§4.2.3). A list is the field's lines, joined first."""
    r = _Reader(join_field_lines(value) if isinstance(value, list) else value)
    r.skip(" ")
    item = _parse_item(r)
    r.skip(" ")
    if not r.done():
        raise r.fail("unexpected characters after the item")
    return item


def _parse_item_or_inner_list(r: _Reader) -> Member:
    if r.peek() == "(":
        return _parse_inner_list(r)
    return _parse_item(r)


def _parse_inner_list(r: _Reader) -> InnerList:
    r.take()  # the opening "("
    items: list[Item] = []
    while not r.done():
        r.skip(" ")
        if r.peek() == ")":
            r.take()
            return InnerList(tuple(items), _parse_parameters(r))
        items.append(_parse_item(r))
        if r.peek() not in (" ", ")"):
            raise r.fail("expected ' ' or ')' in an inner list")
    raise r.fail("unterminated inner list")


def _parse_item(r: _Reader) -> Item:
    value = _parse_bare_item(r)
    return Item(value, _parse_parameters(r))


def _parse_bare_item(r: _Reader) -> BareItem:
    c = r.peek()
    if c == "-" or c in _DIGIT:
        return _parse_number(r)
    if c == '"':
        return _parse_string(r)
    if c == "*" or c in _ALPHA:
        return _parse_token(r)
    if c == ":":
        return _parse_byte_sequence(r)
    if c == "?":
        return _parse_boolean(r)
    raise r.fail("no bare item")


def _parse_parameters(r: _Reader) -> Params:
    params: Params = {}
    while r.peek() == ";":
        r.take()
        r.skip(" ")
        key = _parse_key(r)
        value: BareItem = True
        if r.peek() == "=":
            r.take()
            value = _parse_bare_item(r)
        params[key] = value
    return params


def _parse_key(r: _Reader) -> str:
    start = r.pos
    c = r.peek()
    if c != "*" and c not in _LCALPHA:
        raise r.fail("a key must start with a lowercase letter or '*'")
    r.take()
    while r.peek() != "" and r.peek() in _KEY_REST:
        r.take()
    return r.text[start : r.pos]


def _parse_number(r: _Reader) -> int | Decimal:
    start = r.pos
    sign = 1
    if r.peek() == "-":
        r.take()
        sign = -1
    if r.peek() == "" or r.peek() not in _DIGIT:
        raise r.fail("a number needs a digit")
    digits_start = r.pos
    is_decimal = False
    while r.peek() != "":
        c = r.peek()
        if c in _DIGIT:
            r.take()
        elif c == "." and not is_decimal:
            if r.pos - digits_start > _MAX_DECIMAL_INT_DIGITS:
                raise r.fail("a decimal's integer part is too long")
            is_decimal = True
            r.take()
        else:
            break
        if not is_decimal and r.pos - digits_start > _MAX_INTEGER_DIGITS:
            raise r.fail("an integer is too long")
        if is_decimal and r.pos - digits_start > _MAX_DECIMAL_DIGITS:
            raise r.fail("a decimal is too long")
    text = r.text[digits_start : r.pos]
    if not is_decimal:
        return sign * int(text)
    fraction = text.split(".", 1)[1]
    if not fraction or len(fraction) > _MAX_DECIMAL_FRACTION_DIGITS:
        spelled = r.text[start : r.pos]
        raise StructuredFieldError(f"a decimal needs one to three fraction digits: {spelled!r}")
    return sign * Decimal(text)


def _parse_string(r: _Reader) -> str:
    r.take()  # the opening quote
    out: list[str] = []
    while not r.done():
        c = r.take()
        if c == "\\":
            nxt = r.take()
            if nxt not in ('"', "\\"):
                raise r.fail("a string escapes only '\"' and '\\'")
            out.append(nxt)
        elif c == '"':
            return "".join(out)
        elif not _PRINTABLE_LOW <= ord(c) <= _PRINTABLE_HIGH:
            raise r.fail("a string carries a character outside printable ASCII")
        else:
            out.append(c)
    raise r.fail("unterminated string")


def _parse_token(r: _Reader) -> Token:
    start = r.pos
    r.take()
    while r.peek() != "" and r.peek() in _TOKEN_REST:
        r.take()
    return Token(r.text[start : r.pos])


def _parse_byte_sequence(r: _Reader) -> bytes:
    r.take()  # the opening colon
    start = r.pos
    while r.peek() != "" and r.peek() != ":":
        if r.peek() not in _BASE64:
            raise r.fail("a byte sequence carries a character outside base64")
        r.take()
    if r.done():
        raise r.fail("unterminated byte sequence")
    encoded = r.text[start : r.pos]
    r.take()  # the closing colon
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StructuredFieldError(f"a byte sequence is not base64: {encoded!r}") from exc


def _parse_boolean(r: _Reader) -> bool:
    r.take()  # the "?"
    c = r.take()
    if c == "1":
        return True
    if c == "0":
        return False
    raise r.fail("a boolean is ?0 or ?1")


# --- serialization (§4.1) ----------------------------------------------------------


def serialize_member(member: Member) -> str:
    """Serialize a Dictionary member value: an Item or an Inner List."""
    if isinstance(member, InnerList):
        return serialize_inner_list(member)
    return serialize_item(member)


def serialize_item(item: Item) -> str:
    """Serialize an Item (§4.1.3)."""
    return serialize_bare_item(item.value) + serialize_params(item.params)


def serialize_inner_list(inner: InnerList) -> str:
    """Serialize an Inner List (§4.1.1.1)."""
    items = " ".join(serialize_item(i) for i in inner.items)
    return f"({items}){serialize_params(inner.params)}"


def serialize_params(params: Params) -> str:
    """Serialize Parameters (§4.1.1.2). A Boolean true is written as the bare key."""
    out: list[str] = []
    for key, value in params.items():
        out.append(";" + serialize_key(key))
        if value is not True:
            out.append("=" + serialize_bare_item(value))
    return "".join(out)


def serialize_key(key: str) -> str:
    """Serialize a key (§4.1.1.3), refusing one that is not a valid key."""
    if not key or (key[0] != "*" and key[0] not in _LCALPHA) or not set(key) <= _KEY_REST:
        raise StructuredFieldError(f"not a structured-field key: {key!r}")
    return key


def serialize_bare_item(value: BareItem) -> str:
    """Serialize a bare item (§4.1.3.1)."""
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        if not -_MAX_INTEGER <= value <= _MAX_INTEGER:
            raise StructuredFieldError(f"integer out of range: {value}")
        return str(value)
    if isinstance(value, Decimal):
        return _serialize_decimal(value)
    if isinstance(value, Token):
        return _serialize_token(value)
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    return _serialize_string(value)


def _serialize_decimal(value: Decimal) -> str:
    rounded = value.quantize(Decimal("0.001"), rounding=ROUND_HALF_EVEN)
    if abs(rounded) >= Decimal(10) ** _MAX_DECIMAL_INT_DIGITS:
        raise StructuredFieldError(f"decimal out of range: {value}")
    text = f"{rounded:f}".rstrip("0")
    return text + "0" if text.endswith(".") else text


def _serialize_string(value: str) -> str:
    out = ['"']
    for c in value:
        if not _PRINTABLE_LOW <= ord(c) <= _PRINTABLE_HIGH:
            raise StructuredFieldError(f"a string cannot carry {c!r}")
        if c in ('"', "\\"):
            out.append("\\")
        out.append(c)
    out.append('"')
    return "".join(out)


def _serialize_token(token: Token) -> str:
    v = token.value
    if not v or (v[0] != "*" and v[0] not in _ALPHA) or any(c not in _TOKEN_REST for c in v):
        raise StructuredFieldError(f"not a token: {v!r}")
    return v
