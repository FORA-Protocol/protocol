"""SSRF-guard parity for the WBA default transport (port of the Go oracle's
wbakeyresolver_ssrf_internal_test.go).

The WBA directory host is derived from a caller-supplied Signature-Agent header
and fetched BEFORE the ed25519 signature check, so the DEFAULT transport must be
SSRF-guarded. These suites pin (1) the reserved-range classification byte-for-byte
against the Go set — including the ranges the naive ipaddress heuristics miss
(CGNAT 100.64/10, 0.0.0.0/8, v4-mapped and NAT64 forms embedding a private v4) —
and (2) that the guarded default transport refuses a loopback target.
"""

from __future__ import annotations

import asyncio
import http.server
import threading
from typing import Any

import httpx
import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json
from tls_loopback import loopback_client, start_tls_server

from fora_sdk.resolvers._http import (
    fetch_soft,
    fetch_strict,
    guarded_async_client,
    guarded_client,
)
from fora_sdk.resolvers._ssrf import (
    SsrfError,
    allowed_scheme,
    blocked_address,
    redirect_chain_refused,
)
from fora_sdk.resolvers.errors import DirectoryUnavailableError

# The shared adversarial corpora (Go emits, all SDKs consume — never edited here).
_ADDRESS_VECTORS = load_json(GO_RESOLVERS_TESTDATA / "ssrf-address-vectors.json")["vectors"]
_SCHEME_VECTORS = load_json(GO_RESOLVERS_TESTDATA / "ssrf-scheme-vectors.json")["vectors"]
_REDIRECT_VECTORS = load_json(GO_RESOLVERS_TESTDATA / "ssrf-redirect-vectors.json")["vectors"]
_HOSTSET_VECTORS = load_json(GO_RESOLVERS_TESTDATA / "ssrf-hostset-vectors.json")["vectors"]


@pytest.mark.parametrize("vec", _ADDRESS_VECTORS, ids=lambda v: v["name"])
def test_address_corpus_parity(vec: dict[str, Any]) -> None:
    """blocked_address must agree with the Go oracle on EVERY address vector."""
    assert _ADDRESS_VECTORS, "address corpus must be non-empty"
    assert blocked_address(vec["addr"]) is vec["blocked"], (
        f"{vec['name']} ({vec['addr']}): expected blocked={vec['blocked']}"
    )


@pytest.mark.parametrize("vec", _SCHEME_VECTORS, ids=lambda v: v["name"])
def test_scheme_corpus_parity(vec: dict[str, Any]) -> None:
    """allowed_scheme must agree with the Go oracle on EVERY scheme vector."""
    assert _SCHEME_VECTORS, "scheme corpus must be non-empty"
    assert allowed_scheme(vec["scheme"]) is vec["allowed"], (
        f"{vec['name']} ({vec['scheme']}): expected allowed={vec['allowed']}"
    )


@pytest.mark.parametrize("vec", _REDIRECT_VECTORS, ids=lambda v: v["name"])
def test_redirect_corpus_parity(vec: dict[str, Any]) -> None:
    """redirect_chain_refused must agree with the Go oracle on EVERY hop count."""
    assert _REDIRECT_VECTORS, "redirect corpus must be non-empty"
    assert redirect_chain_refused(vec["hops"]) is vec["refused"], (
        f"{vec['name']} (hops={vec['hops']}): expected refused={vec['refused']}"
    )


@pytest.mark.parametrize("vec", _HOSTSET_VECTORS, ids=lambda v: v["name"])
def test_hostset_corpus_parity(vec: dict[str, Any]) -> None:
    """The multi-address rule (fail closed if ANY resolved address is reserved) must
    agree with the Go oracle on EVERY host-set vector."""
    assert _HOSTSET_VECTORS, "host-set corpus must be non-empty"
    any_blocked = any(blocked_address(addr) for addr in vec["addrs"])
    assert any_blocked is vec["blocked"], (
        f"{vec['name']} ({vec['addrs']}): expected blocked={vec['blocked']}"
    )


# Mirrors TestSSRFBlocked_ReservedRanges (Go): each MUST be classified blocked.
_BLOCKED = [
    "0.1.2.3",  # 0.0.0.0/8 non-zero host — missed by ipaddress is_reserved alone
    "10.0.0.1",  # RFC 1918
    "100.64.0.1",  # CGNAT — missed by is_private
    "127.0.0.1",  # loopback
    "169.254.169.254",  # link-local / cloud metadata
    "172.16.5.5",  # RFC 1918
    "192.168.1.1",  # RFC 1918
    "198.18.0.1",  # benchmarking
    "192.0.2.7",  # TEST-NET-1
    "::1",  # v6 loopback
    "fc00::1",  # ULA
    "fe80::1",  # v6 link-local
    "::ffff:169.254.1.1",  # v4-mapped link-local — must unwrap
    "::ffff:10.0.0.1",  # v4-mapped RFC 1918
    "64:ff9b::a9fe:a9fe",  # NAT64-embedded 169.254.169.254 — must unwrap
    "64:ff9b::0a00:0001",  # NAT64-embedded 10.0.0.1
    "2001:db8::1",  # documentation
    # Extra coverage beyond the Go list, all in the shared prefix table:
    "240.0.0.1",  # reserved / future use (240/4)
    "255.255.255.255",  # limited broadcast
    "224.0.0.1",  # multicast
    "192.88.99.1",  # 6to4 relay anycast
    "203.0.113.9",  # TEST-NET-3
    "198.51.100.9",  # TEST-NET-2
    "64:ff9b:1::1",  # NAT64 local-use /48 (prefix-table hit, not unwrap)
]

# Mirrors the Go allowed list — public addresses must NOT be blocked.
_ALLOWED = [
    "8.8.8.8",  # public v4
    "1.1.1.1",  # public v4
    "93.184.216.34",  # public v4 (example.com)
    "2606:4700:4700::1111",  # public v6 (cloudflare)
    "2606:4700::",  # public v6
]


@pytest.mark.parametrize("addr", _BLOCKED)
def test_blocked_address_rejects_reserved(addr: str) -> None:
    assert blocked_address(addr) is True, f"{addr} should be blocked"


@pytest.mark.parametrize("addr", _ALLOWED)
def test_blocked_address_allows_public(addr: str) -> None:
    assert blocked_address(addr) is False, f"{addr} should be allowed"


def test_blocked_address_accepts_ipaddress_object() -> None:
    import ipaddress

    assert blocked_address(ipaddress.ip_address("10.0.0.1")) is True
    assert blocked_address(ipaddress.ip_address("8.8.8.8")) is False


def test_guarded_client_refuses_loopback() -> None:
    """The guarded default transport must refuse a loopback target.

    Port of TestGuardedWBAClientBlocksLoopback: an in-process server listens on
    127.0.0.1, so a successful GET would prove the guard is absent. The refusal is
    an ``SsrfError`` (an ``OSError``) raised at the dial seam, mentioning the guard.
    """
    server, port = _serve(_OkHandler)
    client = guarded_client()
    try:
        with pytest.raises(SsrfError) as excinfo:
            client.get(f"https://127.0.0.1:{port}/")
        assert "SSRF" in str(excinfo.value)
    finally:
        client.close()
        server.shutdown()
        server.server_close()


def test_guarded_async_client_refuses_loopback() -> None:
    """The guarded ASYNC transport must refuse a loopback target at the dial seam.

    Async twin of test_guarded_client_refuses_loopback: an in-process server
    listens on 127.0.0.1, so a successful GET would prove the guard is absent. The
    refusal is an ``SsrfError`` raised at the connect seam — the connect-time
    closure of the DNS-rebinding window the async path previously lacked. Driven
    via ``asyncio.run`` so the suite needs no async-test plugin.
    """
    server, port = _serve(_OkHandler)

    async def _attempt() -> None:
        client = guarded_async_client()
        try:
            await client.get(f"https://127.0.0.1:{port}/")
        finally:
            await client.aclose()

    try:
        with pytest.raises(SsrfError) as excinfo:
            asyncio.run(_attempt())
        assert "SSRF" in str(excinfo.value)
    finally:
        server.shutdown()
        server.server_close()


def _serve(
    handler: type[http.server.BaseHTTPRequestHandler],
) -> tuple[http.server.ThreadingHTTPServer, int]:
    """Start an in-process HTTP server on 127.0.0.1; return (server, port)."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def test_a_redirect_to_ftp_is_a_directory_outage() -> None:
    """A 302 into a non-http(s) scheme is refused deny-by-default and folds into the
    fetch taxonomy as an outage. httpx has no transport for ftp/telnet/gopher/…, so
    following such a redirect raises ``httpx.UnsupportedProtocol``; the ftp target is
    never dialed. The origin is reached through an injected client that trusts it.
    """

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(302)
            self.send_header("Location", "ftp://ftp.example.com/secret")
            self.end_headers()

        def log_message(self, *_a: object) -> None:
            return

    server, port = start_tls_server(_RedirectHandler)
    client = loopback_client()
    url = f"https://127.0.0.1:{port}/"
    try:
        with pytest.raises(httpx.UnsupportedProtocol):
            client.get(url)
        with pytest.raises(DirectoryUnavailableError):
            fetch_strict(client, url)
    finally:
        client.close()
        server.shutdown()
        server.server_close()


# A redirect to an internal address mid-chain is not tested here: every hop dials through
# the same guarded backend, whose refusal of each reserved address of the shared corpus
# test_resolvers_guard_always_on.py replays through the public guarded clients.


def test_a_non_2xx_is_a_status_not_a_crash() -> None:
    """A non-2xx is an ordinary status — never a crash — and the fail-closed taxonomy
    still holds: fetch_soft drops the refresh (None, keeping the poller's soft-fail
    intact) and fetch_strict classifies it as an outage. The origin is reached through
    an injected client that trusts it.
    """

    class _NotFoundHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.end_headers()

        def log_message(self, *_a: object) -> None:
            return

    server, port = start_tls_server(_NotFoundHandler)
    url = f"https://127.0.0.1:{port}/"
    client = loopback_client()
    try:
        assert client.get(url).status_code == 404
        assert fetch_soft(client, url) is None
        with pytest.raises(DirectoryUnavailableError):
            fetch_strict(client, url)
    finally:
        client.close()
        server.shutdown()
        server.server_close()


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:  # silence the test server
        return


@pytest.mark.parametrize(
    ("name", "domain"),
    [
        ("over_long_label", "a" * 64 + ".example"),
        ("malformed_a_label", "xn--zz.example"),
    ],
)
def test_a_name_the_idna_codec_refuses_is_a_directory_outage(name: str, domain: str) -> None:
    """``fetch_strict`` folds a name httpx cannot encode into DirectoryUnavailableError.

    This is the SHARED fold, asserted at the shared layer rather than through a caller
    that contains everything anyway. Both WBA paths pass through here — the offer-key
    fetch and ``WBAKeyResolver`` — and only one of them has a catch of its own, so a
    raw codec error escaping this function reaches an application through the other.

    Both domains satisfy the ``Offer.exchange`` pattern in proto/fora/v1/fora.proto,
    which bounds the whole value and the character set but sets no per-label limit and
    cannot tell a valid ``xn--`` A-label from an invalid one. They fail in different
    places: the over-long label inside ``socket.getaddrinfo``, which IDNA-encodes
    before resolving, and the malformed A-label in ``URL.host`` while the request is
    still being built. Neither raise is an ``OSError`` or an ``httpx.HTTPError``.
    """
    client = guarded_client()
    try:
        with pytest.raises(DirectoryUnavailableError):
            fetch_strict(client, f"https://{domain}/.well-known/http-message-signatures-directory")
    finally:
        client.close()


@pytest.mark.parametrize(
    ("name", "domain"),
    [
        ("over_long_label", "a" * 64 + ".example"),
        ("malformed_a_label", "xn--zz.example"),
    ],
)
def test_the_same_name_leaves_the_soft_fetch_as_none(name: str, domain: str) -> None:
    """``fetch_soft`` absorbs it too, so a revocation refresh keeps its snapshot.

    The soft fetch exists so a blip leaves the prior revocation snapshot in place. A
    raised codec error there would drop revocations instead, which fails OPEN.
    """
    client = guarded_client()
    try:
        assert (
            fetch_soft(client, f"https://{domain}/.well-known/http-message-signatures-directory")
            is None
        )
    finally:
        client.close()
