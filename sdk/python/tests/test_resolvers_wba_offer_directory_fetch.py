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

from fora_sdk.resolvers import create_wba_offer_directory_fetch

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


def test_default_client_is_guarded(origin: Origin, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no injected client the fetch refuses a loopback target on ADDRESS alone.

    This is the assertion that the SSRF-guarded default was not quietly swapped for a
    plain one: the exchange domain arrives inside an offer, so the party choosing this
    address is not the party running the process.

    Two independent gates can refuse this fetch. The scheme gate rejects plaintext
    http, and the address guard rejects 127.0.0.1. An earlier version of this test
    asked for ``scheme="http"`` and asserted None, which the scheme gate alone
    satisfied — so the address guard, the half this test exists to pin, could have
    been removed with the test still passing. Two things fix that. ALLOW_INSECURE is
    SET, which opens the scheme gate and leaves the address guard as the only thing
    that can refuse. And SKIP_SSRF is cleared rather than inherited, so a developer
    with it exported does not see a pass that means nothing.
    """
    for name in ("SKIP_SSRF", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ALLOW_INSECURE", "true")

    _serve_directory(origin)
    fetch = create_wba_offer_directory_fetch(scheme="http")
    assert asyncio.run(fetch(origin.host)) is None


def test_the_guarded_default_reaches_a_permitted_address(
    origin: Origin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same wiring with the address guard OFF resolves the directory.

    Without this, ``test_default_client_is_guarded`` could pass because the fetch is
    broken for some unrelated reason rather than because the guard refused. Turning
    the one guard under test off and getting the directory back is what shows the
    refusal above came from the address check and from nothing else.
    """
    x = _serve_directory(origin)
    for name in ("HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ALLOW_INSECURE", "true")
    monkeypatch.setenv("SKIP_SSRF", "true")

    fetch = create_wba_offer_directory_fetch(scheme="http")
    wba = asyncio.run(fetch(origin.host))

    assert wba is not None
    assert [k.x for k in wba.keys] == [x]


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
