"""Signature-Input parse-edge units: the verbatim-inner split and the clean refusal.

The canonical Go golden vectors are well-behaved (no comma or paren inside a quoted
keyid, no backslash escapes, canonical whitespace), so passing every vector does NOT
gate correctness on an ADVERSARIAL Signature-Input. Go delegates the dictionary parse
to dunglas/httpsfv and hand-rolls only the verbatim-inner split
(rawInnerByLabel / splitTopLevelMembers); Python parses with fora_sdk.sfv and keeps the
same split. These parser units pin the quoted-string / backslash-escape / top-level
comma behavior the RFC 8941 dictionary grammar requires.

Faces under test:
  fora_sdk.multisig_parse.split_top_level_members — split one SFV dictionary header
    value on TOP-LEVEL commas, honoring quoted strings and backslash escapes.
  fora_sdk.multisig_parse.raw_inner_by_label — the VERBATIM member value after
    ``label=`` for each label, so each signature's base terminates with the signer's
    exact @signature-params bytes.
  fora_sdk._sigbase.parse_all_signatures — the full multi-label parse; refuses a
    malformed header outright, never a mis-slice.
"""

from __future__ import annotations

import pytest

from fora_sdk._sigbase import SignatureCheckError, parse_all_signatures
from fora_sdk.multisig_parse import raw_inner_by_label, split_top_level_members


def test_splits_on_top_level_commas_into_one_member_per_label() -> None:
    raw = 'sig1=("@method" "@target-uri"), sig2=("@method" "signature";key="sig1")'
    assert split_top_level_members(raw) == [
        'sig1=("@method" "@target-uri")',
        ' sig2=("@method" "signature";key="sig1")',
    ]


def test_does_not_split_on_a_comma_inside_a_quoted_string() -> None:
    # A keyid may legally contain a comma inside its quotes; a naive comma split
    # would tear the member in two and mis-slice both labels.
    raw = 'sig1=("@method");keyid="agent,demo.v1", sig2=("@method");keyid="broker.relay.a"'
    parts = split_top_level_members(raw)
    assert len(parts) == 2
    assert 'keyid="agent,demo.v1"' in parts[0]
    assert 'keyid="broker.relay.a"' in parts[1]


def test_honors_backslash_escapes_inside_a_quoted_string() -> None:
    # The escaped quote (\") must NOT close the string, so the following comma
    # stays inside quotes and does not split the member.
    raw = 'sig1=("@method");keyid="a\\",b", sig2=("@method");keyid="c"'
    parts = split_top_level_members(raw)
    assert len(parts) == 2
    assert 'keyid="a\\",b"' in parts[0]
    assert 'keyid="c"' in parts[1]


def test_preserves_the_verbatim_inner_value_per_label() -> None:
    # raw_inner_by_label returns everything after ``label=`` byte-for-byte — the
    # signer's exact @signature-params tail the verify base must terminate with.
    raw = (
        'sig1=("@method" "@target-uri");keyid="agent.v1";created=1700000000, '
        'sig2=("@method" "signature";key="sig1");keyid="broker.relay.a"'
    )
    inner = raw_inner_by_label([raw])
    assert inner["sig1"] == '("@method" "@target-uri");keyid="agent.v1";created=1700000000'
    assert inner["sig2"] == '("@method" "signature";key="sig1");keyid="broker.relay.a"'


def test_cleanly_rejects_a_malformed_header_rather_than_mis_slicing() -> None:
    # An unterminated inner list must be REFUSED, not partially sliced into a bogus
    # covered set.
    malformed = 'sig1=("@method" "@target-uri";keyid="agent.v1"'
    with pytest.raises(SignatureCheckError) as caught:
        parse_all_signatures({"signature-input": malformed, "signature": "sig1=:AA==:"})
    assert caught.value.reason == "malformed_sig_input"


def test_a_comma_inside_a_quoted_keyid_parses_to_two_signatures() -> None:
    headers = {
        "signature-input": 'a=("@method");keyid="x,y", b=("@method");keyid="z"',
        "signature": "a=:AA==:, b=:AQ==:",
    }
    params, sig_map = parse_all_signatures(headers)
    assert [(p.label, p.keyid) for p in params] == [("a", "x,y"), ("b", "z")]
    assert sig_map == {"a": b"\x00", "b": b"\x01"}
