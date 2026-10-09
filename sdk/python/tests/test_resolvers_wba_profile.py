"""WBAKeyResolver under the Web Bot Auth profile — the Python port of the Go oracle's
sdk/go/resolvers/wbakeyresolver_profile_test.go.

A key directory is fetched with no redirect, must be served as
``application/http-message-signatures-directory+json``, and only the keys that signed
its response are handed out. A member is an https origin and is always fetched over
https, so the in-process origin serves TLS. The last case drives a real
two-signature request through ``verify_multisig_request_server`` with this resolver,
each key published only in its own signer's directory.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resolvers_harness import (
    ANCHOR,
    HOUR,
    WBA_DIR_PATH,
    MutableClock,
    Origin,
    active_jwk,
    loopback_client,
    register_directory_key,
    wba_file_json,
)

from fora_sdk.b64 import b64url_nopad
from fora_sdk.httpsig import append_signature, sign_request
from fora_sdk.resolvers import (
    DirectoryUnavailableError,
    KeyExpiredError,
    UnknownKeyError,
    WBAKeyResolver,
)
from fora_sdk.server_verify import verify_multisig_request_server
from fora_sdk.thumbprint import thumbprint

if TYPE_CHECKING:
    from collections.abc import Iterator

_URL = "https://exchange.example/fora.v1.ExchangeService/ExecuteTransaction"
_BODY = b'{"idempotency_key":"idem-1"}'
_CREATED = int(ANCHOR.timestamp())


@pytest.fixture
def origin() -> Iterator[Origin]:
    o = Origin(tls=True)
    yield o
    o.close()


@pytest.fixture
def other() -> Iterator[Origin]:
    o = Origin(tls=True)
    yield o
    o.close()


def _resolver() -> WBAKeyResolver:
    return WBAKeyResolver(http=loopback_client(), now=MutableClock(ANCHOR))


def _key(*, signs: bool) -> tuple[Ed25519PrivateKey, str, str]:
    """A key, its base64url x and thumbprint; registered with the harness signer when
    it ``signs`` the directories that list it."""
    priv = Ed25519PrivateKey.generate()
    if signs:
        register_directory_key(priv)
    raw = priv.public_key().public_bytes_raw()
    return priv, b64url_nopad(raw), thumbprint(raw)


def test_only_keys_that_signed_the_response_are_handed_out(origin: Origin) -> None:
    _, signed_x, signed_tp = _key(signs=True)
    _, unsigned_x, unsigned_tp = _key(signs=False)
    origin.set_wba(wba_file_json([active_jwk(signed_x), active_jwk(unsigned_x)]))
    r = _resolver()

    assert r.resolve(signed_tp, origin.origin) is not None
    with pytest.raises(UnknownKeyError):
        r.resolve(unsigned_tp, origin.origin)


def test_a_member_origin_and_a_bare_host_are_fetched_over_https(origin: Origin) -> None:
    # The origin answers only TLS, so each resolve proves the directory was requested
    # over https: the member as written, and a bare host:port prefixed with https.
    _, x, tp = _key(signs=True)
    origin.set_wba(wba_file_json([active_jwk(x)]))
    assert _resolver().resolve(tp, origin.origin) is not None
    assert _resolver().resolve(tp, origin.host) is not None


def test_a_plaintext_directory_is_never_reached() -> None:
    # A directory served only in plaintext is unavailable under its https member, and
    # the resolver offers no option to fetch it over http instead.
    plain = Origin()
    try:
        _, x, tp = _key(signs=True)
        plain.set_wba(wba_file_json([active_jwk(x)]))
        with pytest.raises(DirectoryUnavailableError):
            _resolver().resolve(tp, plain.origin)
        with pytest.raises(DirectoryUnavailableError):
            _resolver().resolve(tp, plain.host)
        with pytest.raises(TypeError):
            WBAKeyResolver(http=loopback_client(), scheme="http")  # type: ignore[call-arg]
    finally:
        plain.close()


@pytest.mark.parametrize("served", ["application/jwk-set+json", "application/json", None])
def test_a_directory_served_under_another_media_type_is_unavailable(
    origin: Origin, served: str | None
) -> None:
    _, x, tp = _key(signs=True)
    origin.set_wba(wba_file_json([active_jwk(x)]))
    origin.set_content_type(WBA_DIR_PATH, served)
    with pytest.raises(DirectoryUnavailableError):
        _resolver().resolve(tp, origin.origin)


def test_a_directory_reached_through_a_redirect_is_unavailable(
    origin: Origin, other: Origin
) -> None:
    # The injected loopback client follows redirects; the directory fetch refuses them
    # whatever the client's policy, so the key published at the target is never read.
    _, x, tp = _key(signs=True)
    other.set_wba(wba_file_json([active_jwk(x)]))
    origin.set_redirect(WBA_DIR_PATH, other.url + WBA_DIR_PATH)
    with pytest.raises(DirectoryUnavailableError):
        _resolver().resolve(tp, origin.origin)


def test_each_signature_resolves_in_its_own_directory(origin: Origin, other: Origin) -> None:
    agent, agent_x, agent_tp = _key(signs=True)
    broker, broker_x, broker_tp = _key(signs=True)
    origin.set_wba(wba_file_json([active_jwk(agent_x)]))
    other.set_wba(wba_file_json([active_jwk(broker_x)]))
    common = {
        "method": "POST",
        "url": _URL,
        "body": _BODY,
        "authorization": "",
        "created": _CREATED,
        "expires": _CREATED + 300,
    }
    first = sign_request(
        signer_seed=agent.private_bytes_raw(), keyid=agent_tp, signature_agent=origin.origin,
        **common,  # type: ignore[arg-type]
    )  # fmt: skip
    second = append_signature(
        signer_seed=broker.private_bytes_raw(), keyid=broker_tp, signature_agent=other.origin,
        prev_signature_input=first.signature_input, prev_signature=first.signature,
        prev_signature_agent=first.signature_agent,
        **common,  # type: ignore[arg-type]
    )  # fmt: skip
    headers = {
        "content-digest": second.content_digest,
        "signature-input": second.signature_input,
        "signature": second.signature,
        "authorization": "",
        "signature-agent": second.signature_agent,
    }

    def verify(signature_agent: str) -> object:
        return verify_multisig_request_server(
            method="POST", url=_URL, body=_BODY,
            headers={**headers, "signature-agent": signature_agent},
            resolver=_resolver(), now=_CREATED + 10,
        )  # fmt: skip

    verdict = verify(second.signature_agent)
    assert verdict.valid is True, verdict.reason  # type: ignore[attr-defined]
    assert verdict.directories == (origin.origin, other.origin)  # type: ignore[attr-defined]

    # Point the broker's member at the agent's directory: its keyid is looked up there,
    # where it is not published, and the request is refused.
    swapped = f'sig1="{origin.origin}", sig2="{origin.origin}"'
    refused = verify(swapped)
    assert refused.valid is False  # type: ignore[attr-defined]
    assert refused.reason == "signature"  # type: ignore[attr-defined]


def test_a_clock_outside_the_key_validity_still_fails_closed(origin: Origin) -> None:
    # The profile adds checks; it does not replace the validity window.
    _, x, tp = _key(signs=True)
    origin.set_wba(wba_file_json([active_jwk(x)]))
    r = WBAKeyResolver(http=loopback_client(), now=MutableClock(ANCHOR + 2 * HOUR))
    with pytest.raises(KeyExpiredError):
        r.resolve(tp, origin.origin)
