"""``WBAKeyResolver.revoked`` finds the list it answers from by directory identity.

A snapshot is stored under the host a fetch spelled, and a caller may name the
same directory another way — an offer's bare exchange domain, an origin with
``:443`` written out, different letter case. Those name the same party under the
request-recipient identity rule, so they must reach the same list: matching the
spelling only would read a revoked key as unrevoked. A subdomain is a different
party and never borrows the list. Port of the Go
``TestRevokedMatchesTheDirectoryIdentity``.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from fora_sdk.resolvers import WBAKeyResolver
from fora_sdk.resolvers.wba import _RevSet

_AS_OF = datetime(2026, 5, 1, 12, 0, tzinfo=UTC)


def _resolver() -> WBAKeyResolver:
    r = WBAKeyResolver()
    r._revoked["exchange.example"] = _RevSet(thumbprints={"tp"}, as_of=_AS_OF)
    r._revoked["127.0.0.1:8443"] = _RevSet(thumbprints={"ip"}, as_of=_AS_OF)
    return r


@pytest.mark.parametrize(
    ("key_id", "directory", "want"),
    [
        ("tp", "https://exchange.example", True),
        ("tp", "exchange.example", True),
        ("tp", "https://Exchange.EXAMPLE", True),
        ("tp", "https://exchange.example:443", True),
        ("tp", "exchange.example:443", True),
        ("tp", "https://sub.exchange.example", False),
        ("tp", "https://example", False),
        ("tp", "https://exchange.example:8443", False),
        ("other", "https://exchange.example", False),
        ("ip", "https://127.0.0.1:8443", True),
        ("ip", "https://127.0.0.1:9443", False),
        ("tp", "", False),
        ("", "https://exchange.example", False),
    ],
)
def test_revoked_matches_the_directory_identity(key_id: str, directory: str, want: bool) -> None:
    assert _resolver().revoked(key_id, directory) is want
