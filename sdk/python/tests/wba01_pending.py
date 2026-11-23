"""The Web Bot Auth -01 rows the Python SDK does not meet yet: one list, read by every replay.

The Go oracle reads and writes draft-ietf-webbotauth-httpsig-protocol-01 (WG-01)
Signature-Agent values. Every signer writes the well-known key directory URL, a bare
origin completed to it, and the verifier ignores a member that carries parameters and
refuses any URL but the well-known one. The Python SDK still implements -00.

Each entry names a corpus row and the face a test exercises on it,
``"<corpus>#<row>:<face>"``: ``sign`` signs the row's inputs and compares the bytes,
``verify`` verifies the row. It records the WG-01 rule the row needs and the outcome the
Python SDK produces on that face today.

A test over a listed row is a STRICT expected failure, and it fails for one reason only.
The test reports the SDK's outcome through the ``wba01`` fixture before it asserts the
oracle row: an outcome other than the recorded one raises PendingOutcomeChangedError, which is
not an AssertionError, so ``xfail(strict=True, raises=AssertionError)`` reports a failure;
a listed test that never reports its outcome fails at teardown; and a listed test that
passes fails as a strict XPASS. An entry therefore fails when its row starts to pass and
when the SDK starts to fail it differently. The port deletes each entry in the change
that makes its row pass, so this list shrinks to nothing.

Every key a test registers is recorded, and test_wba_signature_agent_parity holds the
list to them: an entry no test registers marks nothing and could never be deleted.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

import pytest

_F = TypeVar("_F", bound=Callable[..., Any])


@dataclass(frozen=True)
class Pending:
    """One pending row: the WG-01 rule it needs, and the SDK's outcome on it today.

    ``today`` is one outcome when every test over the row reaches the same one. Where
    the tests over a row exercise different faces (the server face and the primitive
    verify, which report different reasons), it maps each test's name to its outcome.
    """

    rule: str
    today: str | Mapping[str, str]

    def today_for(self, test: str) -> str | None:
        """The outcome the list records for ``test``, None when it records none."""
        if isinstance(self.today, str):
            return self.today
        return self.today.get(test)


class PendingOutcomeChangedError(Exception):
    """A pending row's outcome is not the one the list records. Deliberately not an
    AssertionError, so a strict expected failure reports it as a failure."""


def verify_outcome(
    valid: bool, reason: str | None = None, accept_signature: str | None = None
) -> str:
    """A verify face's outcome: ``valid``, or the refusal reason and its Accept-Signature."""
    if valid:
        return "valid"
    if accept_signature:
        return f"refused {reason}; Accept-Signature: {accept_signature}"
    return f"refused {reason}"


def sign_outcome(signature_agent: str) -> str:
    """A sign face's outcome: the Signature-Agent the SDK writes."""
    return f"writes Signature-Agent: {signature_agent}"


def raised_outcome(exc: BaseException) -> str:
    """The outcome of a face that raised instead of answering."""
    return f"raises {type(exc).__name__}"


# The rules a pending row needs.
_SIGNS_URL = (
    "a signer writes the well-known key directory URL, a bare origin completed to it (WG-01 §5.2.1)"
)
_READS_URL = "a member naming the well-known key directory URL names that directory (WG-01 §5.5)"
_PARAMETER = (
    "a member with a parameter is ignored (WG-01 §5.2.1), so the signature names no directory"
)
_OTHER_URL = "another path, a query or a fragment is refused as signature_agent_not_key_directory"
_SIGN_ACCEPTS_URL = "a signer accepts the well-known key directory URL as its configured value"
_SIGN_OTHER_URL = (
    "a signer refuses another path, a query or a fragment with SignatureAgentNotKeyDirectoryError"
)

# The outcomes the Python SDK produces today.
_RPC_ACCEPT = (
    'sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1")'
    ';created;expires;tag="web-bot-auth"'
)
_POP_ACCEPT = (
    'sig1=("@method" "@target-uri" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"'
)
_RPC_REFUSED_AT_MEMBER = verify_outcome(False, "signature", _RPC_ACCEPT)
_POP_REFUSED_AT_MEMBER = verify_outcome(False, "bad_signature_agent", _POP_ACCEPT)
_VALID = verify_outcome(True)
_WRITES_ORIGIN = sign_outcome('sig1="https://agent.example"')
_TWO_ORIGINS = 'sig1="https://agent.example", sig2="https://broker.example"'
_THREE_ORIGINS = _TWO_ORIGINS + ', sig3="https://relay.example:8443"'
_REFUSES_URL = "raises SignatureAgentNotOriginError"

_WBA = "wba-signature-agent-vectors"
_SIGN_REQUEST = "sign-request-vectors"
_POP = "pop-vectors"
_MULTISIG = "multisig-chain-vectors"


def _rows(corpus: str, face: str, entry: Pending, names: Iterable[str]) -> dict[str, Pending]:
    return {f"{corpus}#{name}:{face}": entry for name in names}


PENDING_WBA_01: dict[str, Pending] = {
    # wba-signature-agent-vectors.json, verifier rows. The SDK refuses the URL member
    # as not an origin; it reads a parameter as -00 did; and it refuses another URL
    # as not an origin rather than as not the key directory.
    **_rows(
        _WBA,
        "verify",
        Pending(_READS_URL, _RPC_REFUSED_AT_MEMBER),
        (
            "vectors/well_known_url",
            "vectors/well_known_url_with_port",
            "vectors/legacy_string_well_known_url",
            "vectors/member_key_differs_from_label",
            "vectors/repeated_field_lines_member_on_first",
            "vectors/repeated_field_lines_member_on_second",
            "vectors/escaped_quote_in_another_member",
            "vectors/ignored_member_beside_the_signers",
        ),
    ),
    **_rows(
        _WBA,
        "verify",
        Pending(_PARAMETER, _RPC_REFUSED_AT_MEMBER),
        (
            "vectors/member_with_parameter",
            "vectors/member_with_other_parameter",
            "vectors/member_type_other",
            "vectors/member_not_a_string_with_parameter",
            "vectors/legacy_string_with_parameter",
            "vectors/repeated_field_lines_member_with_parameter",
        ),
    ),
    **_rows(
        _WBA,
        "verify",
        Pending(_PARAMETER, _VALID),
        ("vectors/member_type_directory_string", "vectors/member_type_directory_token"),
    ),
    **_rows(
        _WBA,
        "verify",
        Pending(_OTHER_URL, _RPC_REFUSED_AT_MEMBER),
        (
            "vectors/other_path",
            "vectors/origin_with_trailing_slash",
            "vectors/well_known_path_with_trailing_slash",
            "vectors/well_known_path_in_another_case",
            "vectors/query",
            "vectors/bare_origin_with_query",
            "vectors/fragment",
            "vectors/escaped_quote_in_the_covered_value",
        ),
    ),
    # wba-signature-agent-vectors.json, signer rows.
    **_rows(
        _WBA,
        "sign",
        Pending(_SIGNS_URL, _WRITES_ORIGIN),
        ("signer/origin_completed",),
    ),
    **_rows(
        _WBA,
        "sign",
        Pending(_SIGNS_URL, sign_outcome('sig1="https://relay.example:8443"')),
        ("signer/origin_with_port_completed",),
    ),
    **_rows(
        _WBA,
        "sign",
        Pending(_SIGN_ACCEPTS_URL, _REFUSES_URL),
        ("signer/well_known_url_as_given",),
    ),
    **_rows(
        _WBA,
        "sign",
        Pending(_SIGN_OTHER_URL, _REFUSES_URL),
        ("signer/other_path", "signer/query", "signer/fragment"),
    ),
    # sign-request-vectors.json: every row carries the well-known URL member. The SDK
    # signs each row's configured origin as the bare origin.
    **{
        f"{_SIGN_REQUEST}#{row}:sign": Pending(_SIGNS_URL, sign_outcome(f'sig1="{origin}"'))
        for row, origin in (
            ("post_with_authorization", "https://agent.example"),
            ("post_empty_authorization_bound", "https://agent.example:8443"),
            ("append_relay_leg", "https://relay.example"),
            ("post_with_nonce", "https://agent.example"),
            ("post_empty_authorization_bound_with_nonce", "https://agent.example:8443"),
            ("append_relay_leg_with_nonce", "https://relay.example"),
            ("doc_single_hop_example", "https://research.acme.com"),
            ("doc_broker_example", "https://broker.example"),
        )
    },
    **_rows(
        _SIGN_REQUEST,
        "verify",
        Pending(
            _READS_URL,
            {
                "test_sign_request_roundtrips_through_verify": verify_outcome(
                    False, "signature_agent_not_origin"
                ),
                "test_oracle_signed_request_verifies_through_server_face": _RPC_REFUSED_AT_MEMBER,
            },
        ),
        (
            "post_with_authorization",
            "post_empty_authorization_bound",
            "append_relay_leg",
            "post_with_nonce",
            "post_empty_authorization_bound_with_nonce",
            "append_relay_leg_with_nonce",
            "doc_single_hop_example",
            "doc_broker_example",
        ),
    ),
    # pop-vectors.json: the proofs the Go signer made carry the URL member.
    **_rows(_POP, "sign", Pending(_SIGNS_URL, _WRITES_ORIGIN), ("valid",)),
    **_rows(
        _POP,
        "verify",
        Pending(_READS_URL, _POP_REFUSED_AT_MEMBER),
        ("valid", "valid_no_nonce", "expired"),
    ),
    # multisig-chain-vectors.json: the positive chains' members name the URL.
    **_rows(
        _MULTISIG,
        "verify",
        Pending(_READS_URL, _RPC_REFUSED_AT_MEMBER),
        (
            "positive_independent_two",
            "positive_covering_two",
            "positive_covering_three",
            "positive_covering_two_nonce",
            "canonical_case_two",
            "duplicate_bound_two",
        ),
    ),
    **_rows(
        _MULTISIG,
        "sign",
        Pending(_SIGNS_URL, sign_outcome(_TWO_ORIGINS)),
        (
            "positive_independent_two",
            "positive_covering_two",
            "positive_covering_two_nonce",
            "canonical_case_two",
            "duplicate_bound_two",
        ),
    ),
    **_rows(
        _MULTISIG,
        "sign",
        Pending(_SIGNS_URL, sign_outcome(_THREE_ORIGINS)),
        (
            "positive_covering_three",
            "hop_budget_three_independent_over_two",
            "hop_budget_three_covering_over_two",
            "absent_authorization_over_budget",
        ),
    ),
}

#: Every key a test registered, pending or not: wba01_marks records it.
REGISTERED: set[str] = set()

_MARK = "wba01"


def wba01_marks(corpus: str, row: str, face: str) -> list[pytest.MarkDecorator]:
    """The marks for a test over one row: none, or, when the row is pending, the strict
    expected failure and the ``wba01`` mark the fixture reads the entry from."""
    key = f"{corpus}#{row}:{face}"
    REGISTERED.add(key)
    entry = PENDING_WBA_01.get(key)
    if entry is None:
        return []
    return [
        pytest.mark.xfail(strict=True, raises=AssertionError, reason=entry.rule),
        pytest.mark.wba01(key=key),
    ]


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


class Wba01Observer:
    """What the ``wba01`` fixture hands a test: ``observe`` takes the SDK's outcome."""

    def __init__(self, key: str | None, test: str) -> None:
        self.key = key
        self.test = test
        self.entry = PENDING_WBA_01.get(key) if key is not None else None
        self.observed = False

    @classmethod
    def for_node(cls, node: pytest.Item) -> Wba01Observer:
        marker = node.get_closest_marker(_MARK)
        test = getattr(node, "originalname", node.name)
        return cls(marker.kwargs["key"] if marker is not None else None, test)

    def observe(self, outcome: str) -> None:
        """Report the SDK's outcome on the row. For a pending row, any outcome but the
        recorded one raises PendingOutcomeChangedError."""
        self.observed = True
        if self.entry is None:
            return
        recorded = self.entry.today_for(self.test)
        if outcome != recorded:
            msg = (
                f"{self.key} [{self.test}]: the SDK's outcome is now {outcome!r}, the "
                f"pending list records {recorded!r}. Delete the entry if the row "
                "passes, or record the new outcome."
            )
            raise PendingOutcomeChangedError(msg)

    def check_observed(self) -> None:
        """A pending test must report its outcome, or its entry could not fail."""
        if self.entry is not None and not self.observed:
            msg = f"{self.key}: a test over a pending row never reported its outcome"
            raise PendingOutcomeChangedError(msg)


def check_marked_items_request_the_fixture(items: Iterable[pytest.Item]) -> None:
    """Refuse a pending test that does not take the ``wba01`` fixture: its outcome
    would never be compared, so the entry could not fail for the right reason."""
    for item in items:
        if item.get_closest_marker(_MARK) is not None and _MARK not in getattr(
            item, "fixturenames", ()
        ):
            msg = (
                f"{item.nodeid} is over a pending Web Bot Auth -01 row but does not take "
                "the wba01 fixture"
            )
            raise pytest.UsageError(msg)
