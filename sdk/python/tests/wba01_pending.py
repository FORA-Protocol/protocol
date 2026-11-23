"""The Web Bot Auth -01 rows the Python SDK does not meet yet: one list, read by every replay.

The Go oracle reads and writes draft-ietf-webbotauth-httpsig-protocol-01 Signature-Agent
values. Every signer writes the well-known key directory URL, a bare origin completed to
it, and the verifier ignores a member that carries parameters and refuses any URL but the
well-known one. The Python SDK still implements -00.

Each entry names a corpus row and the face a test exercises on it,
``"<corpus>#<row>:<face>"``. The face ``sign`` re-signs the row and compares the bytes,
and ``verify`` verifies it; a test applies the entry for the face it exercises. Each entry
carries the -01 rule the row needs. A test over a listed row is a STRICT expected failure:
it must fail on an assertion, and the suite fails the moment it passes. The port deletes
each entry in the change that makes its row pass, so this list shrinks to nothing.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

import pytest

_F = TypeVar("_F", bound=Callable[..., Any])

_SIGNS_URL = (
    "a signer writes the well-known key directory URL, a bare origin completed to it (-01 §5.2.1)"
)
_READS_URL = "a member naming the well-known key directory URL names that directory (-01 §5.5)"
_PARAMETER = (
    "a member with a parameter is ignored (-01 §5.2.1), so the signature names no directory"
)
_OTHER_URL = "another path, a query or a fragment is refused as signature_agent_not_key_directory"
_SIGN_ACCEPTS_URL = "a signer accepts the well-known key directory URL as its configured value"
_SIGN_OTHER_URL = (
    "a signer refuses another path, a query or a fragment with SignatureAgentNotKeyDirectoryError"
)

_WBA = "wba-signature-agent-vectors"
_SIGN_REQUEST = "sign-request-vectors"
_POP = "pop-vectors"
_MULTISIG = "multisig-chain-vectors"

PENDING_WBA_01: dict[str, str] = {
    # wba-signature-agent-vectors.json, verifier rows.
    f"{_WBA}#vectors/well_known_url:verify": _READS_URL,
    f"{_WBA}#vectors/well_known_url_with_port:verify": _READS_URL,
    f"{_WBA}#vectors/legacy_string_well_known_url:verify": _READS_URL,
    f"{_WBA}#vectors/member_key_differs_from_label:verify": _READS_URL,
    f"{_WBA}#vectors/repeated_field_lines_member_on_first:verify": _READS_URL,
    f"{_WBA}#vectors/repeated_field_lines_member_on_second:verify": _READS_URL,
    f"{_WBA}#vectors/escaped_quote_in_another_member:verify": _READS_URL,
    f"{_WBA}#vectors/ignored_member_beside_the_signers:verify": _READS_URL,
    f"{_WBA}#vectors/member_with_parameter:verify": _PARAMETER,
    f"{_WBA}#vectors/member_type_directory_string:verify": _PARAMETER,
    f"{_WBA}#vectors/member_type_directory_token:verify": _PARAMETER,
    f"{_WBA}#vectors/member_with_other_parameter:verify": _PARAMETER,
    f"{_WBA}#vectors/member_type_other:verify": _PARAMETER,
    f"{_WBA}#vectors/member_not_a_string_with_parameter:verify": _PARAMETER,
    f"{_WBA}#vectors/legacy_string_with_parameter:verify": _PARAMETER,
    f"{_WBA}#vectors/repeated_field_lines_member_with_parameter:verify": _PARAMETER,
    f"{_WBA}#vectors/other_path:verify": _OTHER_URL,
    f"{_WBA}#vectors/origin_with_trailing_slash:verify": _OTHER_URL,
    f"{_WBA}#vectors/well_known_path_with_trailing_slash:verify": _OTHER_URL,
    f"{_WBA}#vectors/well_known_path_in_another_case:verify": _OTHER_URL,
    f"{_WBA}#vectors/query:verify": _OTHER_URL,
    f"{_WBA}#vectors/bare_origin_with_query:verify": _OTHER_URL,
    f"{_WBA}#vectors/fragment:verify": _OTHER_URL,
    f"{_WBA}#vectors/escaped_quote_in_the_covered_value:verify": _OTHER_URL,
    # wba-signature-agent-vectors.json, signer rows.
    f"{_WBA}#signer/origin_completed:sign": _SIGNS_URL,
    f"{_WBA}#signer/well_known_url_as_given:sign": _SIGN_ACCEPTS_URL,
    f"{_WBA}#signer/origin_with_port_completed:sign": _SIGNS_URL,
    f"{_WBA}#signer/other_path:sign": _SIGN_OTHER_URL,
    f"{_WBA}#signer/query:sign": _SIGN_OTHER_URL,
    f"{_WBA}#signer/fragment:sign": _SIGN_OTHER_URL,
    # sign-request-vectors.json: every row now carries the well-known URL member.
    **{
        f"{_SIGN_REQUEST}#{row}:{face}": _SIGNS_URL if face == "sign" else _READS_URL
        for row in (
            "post_with_authorization",
            "post_empty_authorization_bound",
            "append_relay_leg",
            "post_with_nonce",
            "post_empty_authorization_bound_with_nonce",
            "append_relay_leg_with_nonce",
            "doc_single_hop_example",
            "doc_broker_example",
        )
        for face in ("sign", "verify")
    },
    # pop-vectors.json: the proofs the Go signer made.
    f"{_POP}#valid:sign": _SIGNS_URL,
    f"{_POP}#valid:verify": _READS_URL,
    f"{_POP}#valid_no_nonce:verify": _READS_URL,
    f"{_POP}#expired:verify": _READS_URL,
    # multisig-chain-vectors.json: every hop's member now names the well-known URL.
    **{
        f"{_MULTISIG}#{row}:verify": _READS_URL
        for row in (
            "positive_independent_two",
            "positive_covering_two",
            "positive_covering_three",
            "positive_covering_two_nonce",
            "canonical_case_two",
            "duplicate_bound_two",
        )
    },
    **{
        f"{_MULTISIG}#{row}:sign": _SIGNS_URL
        for row in (
            "positive_independent_two",
            "positive_covering_two",
            "positive_covering_three",
            "positive_covering_two_nonce",
            "hop_budget_three_independent_over_two",
            "hop_budget_three_covering_over_two",
            "absent_authorization_two",
            "absent_authorization_over_budget",
            "duplicate_authorization_two",
            "canonical_case_two",
            "duplicate_bound_two",
        )
    },
}


def wba01_marks(corpus: str, row: str, face: str) -> list[pytest.MarkDecorator]:
    """The strict expected-failure mark for a pending row, or none."""
    reason = PENDING_WBA_01.get(f"{corpus}#{row}:{face}")
    if reason is None:
        return []
    return [pytest.mark.xfail(strict=True, raises=AssertionError, reason=reason)]


def wba01_param(value: object, corpus: str, row: str, face: str) -> Any:
    """A pytest.param for ``value``, identified by ``row`` and marked when it is pending."""
    return pytest.param(value, id=row, marks=wba01_marks(corpus, row, face))


def wba01_pending(corpus: str, row: str, face: str) -> Callable[[_F], _F]:
    """Mark a test pinned to one row when that row is pending."""

    def apply(fn: _F) -> _F:
        for mark in wba01_marks(corpus, row, face):
            fn = mark(fn)
        return fn

    return apply
