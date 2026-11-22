"""A signature's lifetime under load, through the public signing surface.

Mirrors sdk/go/core/sigwindow_burst_test.go and sdk/ts/tests/signing-window.burst.test.ts.

The bound: every signature ``SigningTransport.sign_outbound`` emits has
``expires - created`` equal to the window's TTL, and that TTL is at most
``MAX_SIGNATURE_LIFETIME``, whatever the request rate. ``created`` is the clock's current
second, never ahead of it. Each test signs through the transport with an injected clock
and reads created and expires back off the emitted Signature-Input header.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk.signing_transport import SigningTransport
from fora_sdk.thumbprint import thumbprint
from fora_sdk.wba import MAX_SIGNATURE_LIFETIME, SignatureLifetimeError
from fora_sdk.window import Window, clock_window, monotonic_window

_SEED = bytes(range(1, 33))
_DIR = "https://agent.example"
_URL = "https://exchange.example/fora.exchange.v1.ExchangeService/DiscoverResources"
_BODY = b'{"query":"x"}'
_CREATED_EXPIRES = re.compile(r";created=(\d+);expires=(\d+)")


class _Clock:
    """A test clock in seconds that the test moves by hand."""

    def __init__(self, at: float) -> None:
        self.at = at

    def __call__(self) -> float:
        return self.at


def _transport(**kwargs: object) -> SigningTransport:
    pub = Ed25519PrivateKey.from_private_bytes(_SEED).public_key().public_bytes_raw()
    return SigningTransport(
        signer_seed=_SEED,
        keyid=thumbprint(pub),
        signature_agent=_DIR,
        **kwargs,  # type: ignore[arg-type]
    )


def _signed_window(transport: SigningTransport) -> tuple[int, int]:
    headers = transport.sign_outbound(method="POST", url=_URL, body=_BODY, authorization="").headers
    m = _CREATED_EXPIRES.search(headers["signature-input"])
    assert m is not None, headers["signature-input"]
    return int(m.group(1)), int(m.group(2))


@pytest.mark.parametrize("make", [monotonic_window, clock_window], ids=["monotonic", "clock"])
def test_a_burst_above_one_per_second_keeps_the_ttl(make: Callable[[Callable[[], float], int], Window]) -> None:
    # Ten requests per second for one simulated minute, then a thousand requests in one
    # frozen second. The old one-second-per-request shift had grown the last window of the
    # minute by about nine minutes.
    ttl = 30
    clock = _Clock(1_700_000_000.0)
    transport = _transport(window=make(clock, ttl))
    for i in range(600):
        created, expires = _signed_window(transport)
        assert expires - created == ttl, f"request {i}"
        assert created == int(clock.at), f"request {i}"
        clock.at += 0.1
    for i in range(1000):
        created, expires = _signed_window(transport)
        assert (created, expires) == (int(clock.at), int(clock.at) + ttl), f"request {600 + i}"


def test_the_window_follows_a_clock_that_goes_backwards() -> None:
    clock = _Clock(1_700_000_100.0)
    transport = _transport(window=monotonic_window(clock, 30))
    for _ in range(50):
        _signed_window(transport)
    clock.at -= 40
    assert _signed_window(transport) == (1_700_000_060, 1_700_000_090)


def test_a_window_of_exactly_the_limit_signs() -> None:
    transport = _transport(window=monotonic_window(_Clock(1_700_000_000.0), MAX_SIGNATURE_LIFETIME))
    for _ in range(100):
        created, expires = _signed_window(transport)
        assert expires - created == MAX_SIGNATURE_LIFETIME


def test_a_window_one_second_over_the_limit_signs_nothing() -> None:
    transport = _transport(window=clock_window(_Clock(1_700_000_000.0), MAX_SIGNATURE_LIFETIME + 1))
    with pytest.raises(SignatureLifetimeError):
        _signed_window(transport)


def test_the_default_window_under_a_burst() -> None:
    # No injected window: the transport's default reads the real clock and stamps the
    # longest permitted lifetime.
    transport = _transport()
    before = int(time.time())
    for i in range(500):
        created, expires = _signed_window(transport)
        assert expires - created == MAX_SIGNATURE_LIFETIME, f"request {i}"
        assert before <= created <= int(time.time()), f"request {i}"
