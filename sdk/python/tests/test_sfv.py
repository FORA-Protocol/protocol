"""RFC 8941 structured field values — the parser and serializer the signature code
reads Signature-Input, Signature and Signature-Agent with.

A parser, so unit-tested directly. The cases are the RFC's own: what each type parses
to, the inputs §4.2 says to fail on, and the serialization round trip the signature
base depends on (a member is serialized from its parsed form, never spliced from the
wire, so signer and verifier agree however the wire spaced it).
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from fora_sdk import sfv


def test_a_dictionary_of_every_member_shape() -> None:
    parsed = sfv.parse_dictionary(
        'a=1, b="x\\"y", c=tok/en:1, d=:AQID:, e=?0, f, g=(1 "two");p=3, h=-1.5;q'
    )
    assert parsed == {
        "a": sfv.Item(1),
        "b": sfv.Item('x"y'),
        "c": sfv.Item(sfv.Token("tok/en:1")),
        "d": sfv.Item(b"\x01\x02\x03"),
        "e": sfv.Item(False),
        "f": sfv.Item(True),
        "g": sfv.InnerList((sfv.Item(1), sfv.Item("two")), {"p": 3}),
        "h": sfv.Item(Decimal("-1.5"), {"q": True}),
    }


def test_field_lines_are_joined_and_a_repeated_key_keeps_its_place_with_the_last_value() -> None:
    parsed = sfv.parse_dictionary(["a=1, b=2", "a=3"])
    assert list(parsed) == ["a", "b"]
    assert parsed["a"] == sfv.Item(3)


def test_a_token_and_a_string_are_different_types() -> None:
    # The bare v1.0.8 Signature-Agent value parses as a Token and the legacy form as a
    # String; the profile refuses the first and accepts the second.
    assert sfv.parse_item("https://agent.example").value == sfv.Token("https://agent.example")
    assert sfv.parse_item('"https://agent.example"').value == "https://agent.example"


def test_a_signature_input_member_parses_to_its_components_and_parameters() -> None:
    member = sfv.parse_dictionary(
        'sig1=("@method" "signature-agent";key="sig1" "@authority";req);created=1;keyid="k"'
    )["sig1"]
    assert member == sfv.InnerList(
        (
            sfv.Item("@method"),
            sfv.Item("signature-agent", {"key": "sig1"}),
            sfv.Item("@authority", {"req": True}),
        ),
        {"created": 1, "keyid": "k"},
    )


@pytest.mark.parametrize(
    "value",
    [
        "a=1,",  # trailing comma
        "a=1,,b=2",  # empty member
        "A=1",  # a key starts with a lowercase letter or '*'
        "a=(1 2",  # unterminated inner list
        "a=(1,2)",  # an inner list separates items with spaces
        'a="unterminated',
        'a="bad \\n escape"',
        "a=:not base64!:",
        "a=:AQID",  # unterminated byte sequence
        "a=?2",
        "a=1234567890123456",  # sixteen-digit integer
        "a=1.2345",  # four fraction digits
        "a=1 b=2",  # members are separated by commas
        "a=@",
    ],
)
def test_the_inputs_the_rfc_fails_on_are_refused(value: str) -> None:
    with pytest.raises(sfv.StructuredFieldError):
        sfv.parse_dictionary(value)


def test_an_item_with_trailing_characters_is_refused() -> None:
    with pytest.raises(sfv.StructuredFieldError):
        sfv.parse_item('"https://agent.example", sig2="x"')


@pytest.mark.parametrize(
    "member",
    [
        '"https://agent.example";type=directory',
        ":AQIDBA==:",
        '("@method" "signature-agent";key="sig1");created=1700000000;keyid="k";tag="t"',
        "?1;flag",
        "-12.5",
    ],
)
def test_a_parsed_member_serializes_to_its_canonical_form(member: str) -> None:
    parsed = sfv.parse_dictionary(f"m={member}")["m"]
    assert sfv.serialize_member(parsed) == member


def test_serialization_normalizes_what_the_wire_spaced_differently() -> None:
    parsed = sfv.parse_dictionary('m=(  "a"   "b";key="x"  );p=1')["m"]
    assert sfv.serialize_member(parsed) == '("a" "b";key="x");p=1'


@pytest.mark.parametrize(
    "value",
    ["bad\nstring", "é", 10**15, sfv.Token("1abc")],
)
def test_a_value_that_is_not_a_structured_field_is_not_serialized(value: object) -> None:
    with pytest.raises(sfv.StructuredFieldError):
        sfv.serialize_bare_item(value)  # type: ignore[arg-type]


def test_an_invalid_key_is_not_serialized() -> None:
    with pytest.raises(sfv.StructuredFieldError):
        sfv.serialize_params({"Key": True})
