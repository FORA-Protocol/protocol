"""The default offer-directory fetch, at parity with the Go oracle's
``NewWBADirectoryFetcher(client, scheme, port)``.

Two properties matter and they pull in opposite directions, which is why they are
tested together. The fetch must RESOLVE a reachable directory into a ``WBAFile``,
and it must CONTAIN every failure as ``None`` rather than raise — the contract
``CachedOfferKeyResolver.prefetch`` depends on, because it gathers these calls
through ``asyncio.gather`` without ``return_exceptions`` and one raised error
abandons the whole batch.

Driven against the real in-process origin from ``resolvers_harness``, never a mocked
HTTP callable: the face under test is IO-bound and the doctrine is that its transport
is the thing most likely to be wrong.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import pytest
from resolvers_harness import (
    ANCHOR,
    HOUR,
    Origin,
    loopback_client,
    make_key,
    wba_file_json,
    wba_jwk,
)

from fora_sdk.resolvers import create_wba_offer_directory_fetch, wba_directory_url
from fora_sdk.resolvers.offer_key_cache import _join_host_port

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


@pytest.fixture
def origin() -> Iterator[Origin]:
    o = Origin()
    yield o
    o.close()


def _serve_directory(o: Origin) -> str:
    """Publish one window-active key and return its base64url ``x``."""
    key = make_key()
    o.set_wba(wba_file_json([wba_jwk(key.x, ANCHOR - HOUR, ANCHOR + HOUR)]))
    return key.x


def _run(o: Origin, **kwargs: Any) -> Any:
    """Fetch ``o``'s directory through the factory, injecting the loopback client.

    The origin listens on 127.0.0.1, which the guarded default refuses by design;
    ``test_default_client_is_guarded`` below is what pins that default, so every
    other case here injects past it exactly as the Go oracle's httptest suites do.
    """
    kwargs.setdefault("http", loopback_client())
    kwargs.setdefault("scheme", "http")
    fetch = create_wba_offer_directory_fetch(**kwargs)
    return asyncio.run(fetch(o.host))


def test_resolves_a_served_directory(origin: Origin) -> None:
    """A 200 carrying a directory decodes to the WBAFile the origin published."""
    x = _serve_directory(origin)
    wba = _run(origin)
    assert wba is not None
    assert [k.x for k in wba.keys] == [x]


@pytest.mark.parametrize(
    ("name", "arrange"),
    [
        ("absent", lambda _o: None),
        ("server_error", lambda o: o.set_wba_status(500)),
        ("forbidden", lambda o: o.set_wba_status(403)),
        ("not_json", lambda o: o.set_wba("this is not json")),
        ("json_but_not_a_directory", lambda o: o.set_wba('{"keys": "not a list"}')),
    ],
)
def test_every_failure_is_contained_as_none(
    origin: Origin, name: str, arrange: Callable[[Origin], None]
) -> None:
    """Transport, status and decode failures all return None and none raises.

    ``absent`` is the origin's 404. The two statuses cover the fail-closed halt
    fetch_strict makes of any non-200. The last two are the decode arm: a body that
    is not JSON, and a body that is JSON and not a directory.
    """
    arrange(origin)
    assert _run(origin) is None, f"{name} should be contained as None"


def test_unreachable_origin_is_contained_as_none(origin: Origin) -> None:
    """A closed port is a transport failure, and it is contained like the rest."""
    origin.close()
    assert _run(origin) is None


def test_default_client_is_guarded(origin: Origin) -> None:
    """With no injected client the fetch refuses a loopback target.

    This is the assertion that the SSRF-guarded default was not quietly swapped for
    a plain one: the exchange domain arrives inside an offer, so the party choosing
    this address is not the party running the process. A guarded refusal is a
    transport failure, so it surfaces through the same None as everything else —
    which is why the positive case above must inject, and why this case is what
    proves the default.
    """
    _serve_directory(origin)
    fetch = create_wba_offer_directory_fetch(scheme="http")
    assert asyncio.run(fetch(origin.host)) is None


def test_an_injected_port_is_joined_onto_a_bare_domain(origin: Origin) -> None:
    """A domain with no port plus an injected ``port`` reaches the same origin.

    The origin's host already carries its port, so this splits the two apart and
    hands them in separately. Resolving the directory is what proves the join
    happened: the wrong join dials a different address and returns None.
    """
    x = _serve_directory(origin)
    address, port = origin.host.rsplit(":", 1)

    fetch = create_wba_offer_directory_fetch(http=loopback_client(), scheme="http", port=port)
    wba = asyncio.run(fetch(address))

    assert wba is not None
    assert [k.x for k in wba.keys] == [x]


def test_the_dialled_url_is_the_shared_builders() -> None:
    """The fetch dials exactly what wba_directory_url emits, https by default.

    Asserted through the builder rather than a dial, because the string is what the
    tri-language ``wba-url-vectors.json`` corpus pins and the Go oracle emits. An
    unset scheme means https on both sides.
    """
    assert wba_directory_url("", "exchange.example") == (
        "https://exchange.example/.well-known/http-message-signatures-directory"
    )
    assert wba_directory_url("http", "exchange.example:8443").startswith(
        "http://exchange.example:8443/"
    )


@pytest.mark.parametrize(
    ("host", "port", "expected"),
    [
        ("::1", "8443", "[::1]:8443"),
        ("::1", "", "::1"),
        ("[::1]", "8443", "[::1]:8443"),
        ("exchange.example", "8443", "exchange.example:8443"),
        ("exchange.example", "", "exchange.example"),
    ],
)
def test_host_and_port_join_as_net_joinhostport_does(host: str, port: str, expected: str) -> None:
    """A bare IPv6 literal gains brackets before the port, as Go's join does.

    The authority form requires them; without brackets the port reads as another
    hextet and the dial goes somewhere else entirely. An empty port leaves the host
    untouched so the scheme default applies.
    """
    assert _join_host_port(host, port) == expected
