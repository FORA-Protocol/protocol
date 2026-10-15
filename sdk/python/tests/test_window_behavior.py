"""Window behaviour (Python side).

Mirrors the sdk/ts sibling sdk/ts/tests/window.behavior.test.ts.

The signature Window (Go core/sigwindow.go) carries a clock → NOT vector-gated.
Two faces:
  - clock_window(now, ttl_sec): created = int(now()), expires = created+ttl
    (MUST int()-truncate — Go .Unix() floors; the current SigningTransport
     mint uses int(self._now()); an un-truncated default would change signature
     bytes).
  - monotonic_window(now, ttl_sec): deprecated, and the same as clock_window: it
    signs at the clock's current time, never ahead of it. The 64-byte nonce, not the
    window, makes each signature unique.
"""

from __future__ import annotations

from fora_sdk.window import clock_window, monotonic_window


def test_clock_window_truncates_created_and_adds_ttl() -> None:
    # A fractional-second now (seconds domain, matching Go's now().Unix()).
    w = clock_window(lambda: 1_700_000_000.987, 600)
    created, expires = w()
    assert created == 1_700_000_000  # truncated, not 1700000000.987
    assert expires == 1_700_000_600  # created + 600
    assert isinstance(created, int)
    assert isinstance(expires, int)


def test_clock_window_reads_clock_each_call() -> None:
    ts = [1_000.0]
    w = clock_window(lambda: ts[0], 60)
    assert w() == (1_000, 1_060)
    ts[0] = 2_000.5
    assert w() == (2_000, 2_060)


def test_monotonic_window_never_stamps_ahead_of_the_clock() -> None:
    # A thousand calls inside one frozen second: every one is stamped at the clock's
    # time. The old forward shift stamped the last one 999 seconds in the future.
    w = monotonic_window(lambda: 1_700_000_000.5, 300)
    assert {w() for _ in range(1000)} == {(1_700_000_000, 1_700_000_300)}
