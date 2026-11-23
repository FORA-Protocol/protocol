"""What the shared corpus does not carry about the endpoint resolver's DEFAULT client.

Which outcome the default gives for a loopback, private or link-local address and for plain
http is pinned across the three languages by ``resolver-default-vectors.json``
(``test_resolver_default_parity.py``). The cases here are
the ones that corpus does not express: a host NAME that resolves to a reserved address,
IPv4 and IPv6, rather than an IP literal; an injected client used exactly as given; and
the default built once per resolver rather than per resolve. TypeScript pins the first
two in ``resolvers-wellknown-endpoint-guarded-default.test.ts``.

Nothing in the SDK is replaced. The standard library's ``socket.getaddrinfo`` answers a
few ``.example`` names with reserved addresses, so a private or link-local answer can be
driven without a listener on that address.
"""

from __future__ import annotations

import http.server
import json
import socket
import threading
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from resolvers_harness import loopback_client

from fora_sdk.resolvers import DirectoryUnavailableError, SsrfError, WellKnownEndpointResolver

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

_REAL_GETADDRINFO = socket.getaddrinfo


class _Origin:
    """A loopback origin that serves a manifest naming itself, and counts the requests
    it answers."""

    def __init__(self) -> None:
        self.requests = 0
        origin = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
                origin.requests += 1
                host = self.headers.get("Host", "")
                body = json.dumps(
                    {
                        "ver": "1.0",
                        "role": "ROLE_EXCHANGE",
                        "endpoint": f"http://{host}/fora.v1.ExchangeService",
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.host = f"127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def origin() -> Iterator[_Origin]:
    o = _Origin()
    yield o
    o.close()


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    # Both guards are env-driven, so the flags are cleared rather than inherited from
    # whatever shell ran the suite.
    for name in ("SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)


def _answer_dns(monkeypatch: pytest.MonkeyPatch, answers: dict[str, str]) -> None:
    """Answer the names in ``answers`` with the given address; resolve the rest for real."""

    def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        address = answers.get(host)
        if address is None:
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)
        if ":" in address:
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port, 0, 0))
            ]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)


def _guard_refusal(resolve: Callable[[], object]) -> SsrfError:
    """The guard refusal a resolve ends in: a DirectoryUnavailableError (a failed read,
    the only retryable exit) caused by the guarded client's SsrfError, so a refusal for
    any other reason does not pass."""
    with pytest.raises(DirectoryUnavailableError) as excinfo:
        resolve()
    cause = excinfo.value.__cause__
    assert isinstance(cause, SsrfError), f"refused for another reason: {cause!r}"
    return cause


@pytest.mark.parametrize(
    "address",
    [
        pytest.param("10.0.0.5", id="private IPv4 (10/8)"),
        pytest.param("192.168.1.10", id="private IPv4 (192.168/16)"),
        pytest.param("169.254.169.254", id="link-local IPv4 (cloud metadata)"),
        pytest.param("fd00::1", id="unique-local IPv6"),
        pytest.param("fe80::1", id="link-local IPv6"),
    ],
)
def test_refuses_an_exchange_whose_name_resolves_to_a_reserved_address(
    address: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ALLOW_INSECURE", "1")
    _answer_dns(monkeypatch, {"exchange.example": address})
    r = WellKnownEndpointResolver(scheme="http")
    refusal = _guard_refusal(lambda: r.resolve_endpoint("exchange.example"))
    # The generic refusal: it names the host, never the address it resolved to.
    assert "exchange.example" in str(refusal)
    assert address not in str(refusal)


def test_uses_an_injected_client_exactly_as_given(origin: _Origin) -> None:
    # No flags are set, so the guarded default would refuse this loopback origin: only
    # the injected client, used as given, can reach it.
    seen: list[str] = []
    client = loopback_client()
    client.event_hooks["request"].append(lambda request: seen.append(str(request.url)))
    try:
        r = WellKnownEndpointResolver(scheme="http", http=client)
        assert r.resolve_endpoint(origin.host) == f"http://{origin.host}/fora.v1.ExchangeService"
        assert seen == [f"http://{origin.host}/.well-known/fora.json"]
    finally:
        client.close()


def test_an_httpx_client_is_built_once_per_resolver_not_per_resolve(
    origin: _Origin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """guarded_client() builds a connection pool, so the default is built with the
    resolver; a per-resolve default would leak one pool per call. A refusal is never
    cached, so each of the three resolves below goes back to the transport."""
    monkeypatch.setenv("ALLOW_INSECURE", "1")
    built: list[httpx.Client] = []
    real_init = httpx.Client.__init__

    def counting_init(self: httpx.Client, *args: Any, **kwargs: Any) -> None:
        built.append(self)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", counting_init)
    r = WellKnownEndpointResolver(scheme="http")
    assert len(built) == 1
    for _ in range(3):
        _guard_refusal(lambda: r.resolve_endpoint(origin.host))
    assert len(built) == 1
