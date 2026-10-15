"""Signature Window (sdk/python) — Python port of the sdk/go oracle
(core/sigwindow.go). A ``Window`` returns the RFC 9421 (created, expires) cutoffs
(unix seconds) to stamp on the next outbound signature; it is invoked once per
signed request. Both values derive from a single ``now()`` reading so a
deterministic-clock test stays inside the verifier's freshness window.

The clock is in the SECONDS domain (matching Go's ``now().Unix()``); both faces
truncate to integer seconds via ``int()`` so the produced RFC 9421
@signature-params bytes stay byte-identical to the sign-site's historical inline
mint.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TypeAlias

#: A Window yields the (created, expires) unix-second cutoffs for one signature.
Window: TypeAlias = Callable[[], "tuple[int, int]"]


def clock_window(now: Callable[[], float], ttl_sec: int) -> Window:
    """Return the plain production Window: it stamps each signature with
    clock-derived ``created = int(now())`` and ``expires = created + ttl_sec``.
    ``now`` reads seconds (fractional allowed); the truncation reproduces Go's
    ``.Unix()``.
    """

    def _window() -> tuple[int, int]:
        created = int(now())
        return created, created + ttl_sec

    return _window


def monotonic_window(now: Callable[[], float], ttl_sec: int) -> Window:
    """Return a Window that stamps each signature at the clock's current time,
    exactly as :func:`clock_window` does.

    It once bumped expires (and later created with it) by one second per call inside
    a wall-clock second, so no two signatures shared a window. That stamped
    signatures in the future at more than one request per second, by as many seconds
    as there were requests, which a verifier's future-skew allowance then absorbed.
    Uniqueness never needed it: every signature carries a fresh 64-byte nonce.

    Deprecated: use :func:`clock_window`. Kept so existing callers keep working, and
    behaves identically.
    """
    return clock_window(now, ttl_sec)
