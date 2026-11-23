"""Signing-window parity: replay sdk/go/core/testdata/signing-window-vectors.json.

Each row names a window kind, its TTL and a sequence of clock readings in unix
milliseconds. Every reading is one request through ``SigningTransport.sign_outbound``
with the clock set to that reading, and the row records, per request, the ``created``
and ``expires`` the Go signing transport stamped, and ``expected_reason``: ``""`` for a
signed request, the refusal token when it refused and sent nothing. The window kinds
map to ``clock_window``, ``monotonic_window`` and, for ``default``, a transport given
only ``now``, which builds its own window with the default TTL.
"""

from __future__ import annotations

import re
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import GO_CORE_TESTDATA, load_json
from fora_sdk.signing_transport import SigningTransport
from fora_sdk.thumbprint import thumbprint
from fora_sdk.wba import MAX_SIGNATURE_LIFETIME, SignatureLifetimeError
from fora_sdk.window import clock_window, monotonic_window

_CORPUS: dict[str, Any] = load_json(GO_CORE_TESTDATA / "signing-window-vectors.json")
_VECTORS: list[dict[str, Any]] = _CORPUS["vectors"]

_SEED = bytes(range(1, 33))
_DIR = "https://agent.example"
_URL = "https://exchange.example/fora.exchange.v1.ExchangeService/DiscoverResources"
_BODY = b'{"test":true}'
_CREATED_EXPIRES = re.compile(r";created=(\d+);expires=(\d+)")
# The corpus token for a window the signer refuses, and the error this SDK raises for it.
_REFUSALS: dict[str, type[Exception]] = {"signature_lifetime": SignatureLifetimeError}


class _Clock:
    """A test clock in seconds, set to each reading before its request."""

    def __init__(self) -> None:
        self.at = 0.0

    def __call__(self) -> float:
        return self.at


def _transport(vector: dict[str, Any], clock: _Clock) -> SigningTransport:
    pub = Ed25519PrivateKey.from_private_bytes(_SEED).public_key().public_bytes_raw()
    kwargs: dict[str, Any] = {}
    kind, ttl = vector["window"], vector["ttl_sec"]
    if kind == "clock":
        kwargs["window"] = clock_window(clock, ttl)
    elif kind == "monotonic":
        kwargs["window"] = monotonic_window(clock, ttl)
    elif kind == "default":
        assert ttl == MAX_SIGNATURE_LIFETIME, "a default row records the default TTL"
        kwargs["now"] = clock
    else:
        pytest.fail(f"unknown window kind {kind!r}")
    return SigningTransport(
        signer_seed=_SEED, keyid=thumbprint(pub), signature_agent=_DIR, **kwargs
    )


def test_the_corpus_limit_is_this_sdks_limit() -> None:
    assert _CORPUS["max_signature_lifetime_sec"] == MAX_SIGNATURE_LIFETIME


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_signing_window_vector(vector: dict[str, Any]) -> None:
    clock = _Clock()
    transport = _transport(vector, clock)
    for i, (ms, want) in enumerate(zip(vector["clock_ms"], vector["expected"], strict=True)):
        clock.at = ms / 1000
        if want["expected_reason"]:
            with pytest.raises(_REFUSALS[want["expected_reason"]]):
                transport.sign_outbound(method="POST", url=_URL, body=_BODY, authorization="")
            continue
        headers = transport.sign_outbound(
            method="POST", url=_URL, body=_BODY, authorization=""
        ).headers
        m = _CREATED_EXPIRES.search(headers["signature-input"])
        assert m is not None, headers["signature-input"]
        got = (int(m.group(1)), int(m.group(2)))
        assert got == (want["created"], want["expires"]), f"request {i} at {ms} ms"
