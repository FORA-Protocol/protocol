"""Real-dial behavioral convergence for the SSRF guard's redirect-depth cap and its
overall wall-clock budget — the sdk/python behavioral half (the input->verdict
predicate parity for redirect + host-set lives in test_resolvers_wba_ssrf.py, next
to the address/scheme replays).

The real httpx client is configured to the same redirect cap the shared corpus
pins (max_redirects), and the deadline test proves a slow resolution is bounded
rather than pinning the caller forever.
"""

from __future__ import annotations

import http.server
import socket
import time

import httpx
import pytest
from tls_loopback import loopback_client, start_tls_server

from fora_sdk.resolvers import _http
from fora_sdk.resolvers._http import fetch_strict, guarded_client
from fora_sdk.resolvers._ssrf import MAX_REDIRECTS
from fora_sdk.resolvers.errors import DirectoryUnavailableError


class _RedirectChainHandler(http.server.BaseHTTPRequestHandler):
    """/n redirects to /(n-1); /0 is the terminal 200. The server's own base URL is
    injected as a class attribute so redirects are absolute."""

    base: str = ""

    def do_GET(self) -> None:
        try:
            n = int(self.path.lstrip("/"))
        except ValueError:
            n = 0
        if n <= 0:
            self.send_response(200)
            self.end_headers()
            return
        self.send_response(302)
        self.send_header("Location", f"{self.base}/{n - 1}")
        self.end_headers()

    def log_message(self, *_a: object) -> None:
        return


def test_the_guarded_clients_carry_the_shared_redirect_cap() -> None:
    """Both guarded factories configure the corpus's redirect cap, not httpx's default."""
    with guarded_client() as client:
        assert client.max_redirects == MAX_REDIRECTS
        assert client.follow_redirects is True


def test_redirect_depth_cap_real_dial() -> None:
    """A client carrying the guarded factory's redirect settings follows exactly
    MAX_REDIRECTS hops and refuses the next — the real-dial confirmation of the cap.

    The origin is a loopback TLS server, which the guarded client refuses by address, so
    the dial goes through an injected client that trusts the origin and takes its
    redirect settings from the guarded client itself; no classifier is patched.
    """
    server, port = start_tls_server(_RedirectChainHandler)
    _RedirectChainHandler.base = f"https://127.0.0.1:{port}"
    with guarded_client() as guarded:
        cap = guarded.max_redirects
    client = loopback_client()
    client.max_redirects = cap
    try:
        # Exactly at the cap: followed to the 200 terminal.
        assert client.get(f"https://127.0.0.1:{port}/{MAX_REDIRECTS}").status_code == 200
        # One hop over the cap: refused (httpx raises TooManyRedirects).
        with pytest.raises(httpx.TooManyRedirects):
            client.get(f"https://127.0.0.1:{port}/{MAX_REDIRECTS + 1}")
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_total_wall_clock_budget_bounds_slow_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow getaddrinfo must not pin the guarded fetch past the overall budget.

    httpx's timeout is per-phase and does not cover our getaddrinfo, so the guarded
    fetch wraps an OVERALL wall-clock budget. Here getaddrinfo is made to block far
    longer than a shrunk budget; fetch_strict must return (as a DirectoryUnavailable
    outage) well within the sleep, proving the caller is bounded.
    """
    real_getaddrinfo = socket.getaddrinfo

    def _slow_getaddrinfo(*args: object, **kwargs: object):
        time.sleep(5.0)
        return real_getaddrinfo(*args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _slow_getaddrinfo)
    monkeypatch.setattr(_http, "_TOTAL_FETCH_DEADLINE_S", 0.3)

    client = guarded_client()
    start = time.monotonic()
    try:
        with pytest.raises(DirectoryUnavailableError):
            fetch_strict(client, "https://127.0.0.1:9/")
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"guarded fetch was not bounded by the budget (took {elapsed:.2f}s)"
    finally:
        client.close()
