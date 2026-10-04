"""The Web Bot Auth profile's shared rules: what a signer refuses, what a verifier
accepts, and the Accept-Signature answer — the Python port of the Go oracle's
sdk/go/helpers/wba_profile_test.go.

The byte-level contract is pinned by the shared corpora elsewhere (sign-request,
verify-request-neg, verify-request-accept, multisig-chain). This suite pins the rules
those corpora cannot show on their own: the https-origin check case by case, every
sign-side refusal raising its typed error before anything is signed, and the verdict
the pure verifier returns for each profile refusal.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk import (
    MAX_SIGNATURE_LIFETIME,
    InvalidNonceError,
    SignatureAgentNotOriginError,
    SignatureAgentRequiredError,
    SignatureLabelError,
    SignatureLifetimeError,
    SignatureProfileError,
    accept_signature,
    check_https_origin,
)
from fora_sdk.httpsig import SignedRequest, sign_request, verify_request

_SEED = bytes(range(1, 33))
_PUB = Ed25519PrivateKey.from_private_bytes(_SEED).public_key().public_bytes_raw()
_URL = "https://exchange.example/fora.v1.ExchangeService/DiscoverResources"
_BODY = b'{"ver":"1.0"}'
_CREATED = 1_700_000_000
_DIRECTORY = "https://agent.example"


# --- check_https_origin -------------------------------------------------------------

_ORIGINS_ACCEPTED = [
    "https://agent.example",
    "https://agent.example:8443",
    "https://127.0.0.1",
    "https://[::1]:8443",
    "https://xn--bcher-kva.example",
    "https://a_b.example",
]

_ORIGINS_REFUSED = [
    "",
    "agent.example",
    "http://agent.example",
    "HTTPS://agent.example",
    "https://Agent.example",
    "https://agent.example/",
    "https://agent.example/keys",
    "https://agent.example?x=1",
    "https://agent.example#f",
    "https://user@agent.example",
    "https://agent.example:443",
    "https://agent.example:0",
    "https://agent.example:99999",
    "https://agent.example:",
    "https://bücher.example",
    "https://",
    "https://a..example",
    "https://agent.example%2F",
    'https://agent.example"',
    "https://[::1",
    "https://agent.example:08443",
]


@pytest.mark.parametrize("origin", _ORIGINS_ACCEPTED)
def test_check_https_origin_accepts_an_origin(origin: str) -> None:
    check_https_origin(origin)


@pytest.mark.parametrize("origin", _ORIGINS_REFUSED)
def test_check_https_origin_refuses_anything_else(origin: str) -> None:
    with pytest.raises(SignatureAgentNotOriginError):
        check_https_origin(origin)


# --- sign-side refusals -------------------------------------------------------------


def _sign(**overrides: object) -> SignedRequest:
    kwargs: dict[str, object] = {
        "method": "POST",
        "url": _URL,
        "body": _BODY,
        "authorization": "",
        "signer_seed": _SEED,
        "keyid": "agent.v1",
        "created": _CREATED,
        "expires": _CREATED + MAX_SIGNATURE_LIFETIME,
        "signature_agent": _DIRECTORY,
    }
    kwargs.update(overrides)
    return sign_request(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("overrides", "error"),
    [
        ({"signature_agent": ""}, SignatureAgentRequiredError),
        ({"signature_agent": "agent.example"}, SignatureAgentNotOriginError),
        ({"signature_agent": "https://agent.example/"}, SignatureAgentNotOriginError),
        ({"created": 0}, SignatureLifetimeError),
        ({"expires": _CREATED}, SignatureLifetimeError),
        ({"expires": _CREATED - 1}, SignatureLifetimeError),
        ({"expires": _CREATED + MAX_SIGNATURE_LIFETIME + 1}, SignatureLifetimeError),
        ({"nonce": 'a";tag="x'}, InvalidNonceError),
        ({"label": "Sig1"}, SignatureLabelError),
        ({"label": "1sig"}, SignatureLabelError),
    ],
    ids=[
        "no_directory",
        "bare_host",
        "trailing_slash",
        "no_created",
        "zero_window",
        "negative_window",
        "window_over_five_minutes",
        "nonce_outside_base64url",
        "uppercase_label",
        "label_starting_with_a_digit",
    ],
)
def test_sign_request_refuses_what_no_profile_signature_carries(
    overrides: dict[str, object], error: type[Exception]
) -> None:
    with pytest.raises(error):
        _sign(**overrides)


def test_every_sign_side_refusal_is_a_profile_error_and_a_value_error() -> None:
    # One except catches them all, and a caller that caught ValueError before still does.
    with pytest.raises(SignatureProfileError):
        _sign(signature_agent="")
    with pytest.raises(ValueError, match="Signature-Agent"):
        _sign(signature_agent="")


def test_sign_request_emits_the_profile() -> None:
    signed = _sign(nonce="abc", label="agent")
    assert signed.signature_agent == 'agent="https://agent.example"'
    assert signed.signature_input == (
        'agent=("@method" "@target-uri" "content-digest" "authorization" '
        f'"signature-agent";key="agent");created={_CREATED};'
        f'expires={_CREATED + MAX_SIGNATURE_LIFETIME};keyid="agent.v1";alg="ed25519";'
        'nonce="abc";tag="web-bot-auth"'
    )
    assert signed.signature.startswith("agent=:")


def test_a_window_of_exactly_five_minutes_is_accepted() -> None:
    assert _sign(expires=_CREATED + MAX_SIGNATURE_LIFETIME).signature


# --- Accept-Signature ---------------------------------------------------------------


def test_accept_signature_value() -> None:
    assert accept_signature(False) == (
        'sig1=("@method" "@target-uri" "content-digest" "authorization" '
        '"signature-agent";key="sig1");created;expires;tag="web-bot-auth"'
    )
    assert accept_signature(True) == (
        'sig1=("@method" "@target-uri" "content-digest" "authorization" '
        '"signature-agent";key="sig1" "x-entitlement-token");created;expires;'
        'tag="web-bot-auth"'
    )


# --- the pure verifier --------------------------------------------------------------


def _verify(signed: SignedRequest, **overrides: str) -> object:
    fields = {
        "signature_input": signed.signature_input,
        "signature": signed.signature,
        "content_digest": signed.content_digest,
        "authorization": signed.authorization,
        "signature_agent": signed.signature_agent,
    }
    fields.update(overrides)
    return verify_request(
        method="POST", url=_URL, body=_BODY, pubkey=_PUB, now=_CREATED + 10, **fields
    )


def test_verify_request_reports_the_directory_the_member_names() -> None:
    verdict = _verify(_sign())
    assert verdict.valid is True  # type: ignore[attr-defined]
    assert verdict.signature_agent == _DIRECTORY  # type: ignore[attr-defined]
    assert verdict.accept_signature is None  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("edit", "reason", "answers_with_accept_signature"),
    [
        # No tag: the profile's form, answered with what it requires.
        (lambda s: s.replace(';tag="web-bot-auth"', ""), "signature_tag", True),
        # A required RPC component left out.
        (lambda s: s.replace('"authorization" ', ""), "missing_component", True),
        # The signature-agent component not covered at all.
        (lambda s: s.replace(' "signature-agent";key="sig1"', ""), "missing_component", True),
    ],
    ids=["no_tag", "authorization_uncovered", "member_uncovered"],
)
def test_verify_request_refusals_of_the_form_carry_accept_signature(
    edit: object, reason: str, answers_with_accept_signature: bool
) -> None:
    signed = _sign()
    verdict = _verify(signed, signature_input=edit(signed.signature_input))  # type: ignore[operator]
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == reason  # type: ignore[attr-defined]
    assert (verdict.accept_signature == accept_signature(False)) is answers_with_accept_signature  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("signature_agent", "reason", "accept"),
    [
        ('"https://agent.example"', "signature_agent_form", True),
        ("https://agent.example", "signature_agent_form", True),
        ('other="https://agent.example"', "signature_agent_form", True),
        ('sig1="http://agent.example"', "signature_agent_not_origin", False),
        ("", "missing_component", True),
    ],
    ids=["legacy_string_for_a_keyed_member", "bare", "member_absent", "not_https", "absent"],
)
def test_verify_request_refuses_a_signature_agent_the_profile_does_not_accept(
    signature_agent: str, reason: str, accept: bool
) -> None:
    verdict = _verify(_sign(), signature_agent=signature_agent)
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == reason  # type: ignore[attr-defined]
    assert (verdict.accept_signature is not None) is accept  # type: ignore[attr-defined]


def test_verify_request_a_repointed_member_breaks_the_signature() -> None:
    # The member is covered: pointing it at another origin is a bad signature, not a
    # form error, so nothing is answered with Accept-Signature.
    verdict = _verify(_sign(), signature_agent='sig1="https://evil.example"')
    assert verdict.valid is False  # type: ignore[attr-defined]
    assert verdict.reason == "signature_verify"  # type: ignore[attr-defined]
    assert verdict.accept_signature is None  # type: ignore[attr-defined]
