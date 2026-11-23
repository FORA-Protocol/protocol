"""The guarded clients have no switch (mirror of sdk/go/resolvers/guardedclient_test.go).

``SKIP_SSRF`` and ``ALLOW_INSECURE`` once turned the two checks off for a whole process;
they are set here to prove nothing reads them any more. Every reserved address of the
shared address corpus, and a plaintext URL, is refused by the guard through the public
``guarded_client`` and ``guarded_async_client``, and a loopback listener standing in for
the target records that no connection was made.
"""

from __future__ import annotations

import asyncio
import re
import socket
import threading
from typing import TYPE_CHECKING, Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json

from fora_sdk.resolvers import SsrfError, guarded_async_client, guarded_client

if TYPE_CHECKING:
    from collections.abc import Iterator

#: The environment variables that used to relax the guard.
RETIRED_SWITCHES = ("SKIP_SSRF", "ALLOW_INSECURE")

# Every reserved row of the shared corpus.
_RESERVED = [
    v["addr"]
    for v in load_json(GO_RESOLVERS_TESTDATA / "ssrf-address-vectors.json")["vectors"]
    if v["blocked"]
]


class _CountingListener:
    """A loopback port that accepts connections and counts them."""

    def __init__(self) -> None:
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.accepted += 1
            conn.close()

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def listener(monkeypatch: pytest.MonkeyPatch) -> Iterator[_CountingListener]:
    for name in RETIRED_SWITCHES:
        monkeypatch.setenv(name, "true")
    served = _CountingListener()
    try:
        yield served
    finally:
        served.close()


def _targets(port: int) -> list[str]:
    def authority(addr: str) -> str:
        # An IPv6 literal is bracketed, and a zone in it is written the RFC 6874 way.
        host = "[" + addr.replace("%", "%25") + "]" if ":" in addr else addr
        return f"{host}:{port}"

    assert _RESERVED, "the address corpus has no reserved row"
    plaintext = [f"http://127.0.0.1:{port}/", "http://example.com/"]
    return [f"https://{authority(a)}/" for a in _RESERVED] + plaintext


def test_the_sync_client_relaxes_nothing(listener: _CountingListener) -> None:
    with guarded_client(timeout=2.0) as client:
        for url in _targets(listener.port):
            with pytest.raises(SsrfError):
                client.get(url)
    assert listener.accepted == 0, "a refused target is never dialed"


def test_the_async_client_relaxes_nothing(listener: _CountingListener) -> None:
    async def run() -> None:
        async with guarded_async_client(timeout=2.0) as client:
            for url in _targets(listener.port):
                with pytest.raises(SsrfError):
                    await client.get(url)

    asyncio.run(run())
    assert listener.accepted == 0, "a refused target is never dialed"


def _resolving_every_row(monkeypatch: pytest.MonkeyPatch, port: int) -> dict[str, list[str]]:
    """Make the system resolver answer ``row-N.peer.example`` with reserved row N.

    A literal in a URL reaches the guard only as the resolver echoes it back, and the
    resolver of some platforms drops an IPv6 zone on the way, so the guard would see
    fe80::1 and not fe80::1%eth0. Here the resolver's answer carries the row exactly as the
    corpus writes it, the zone included, which is what the guard sees on a platform whose
    resolver keeps the zone. Returns, for each name asked, the rows it was answered with.
    """
    rows = {f"row-{i}.peer.example": addr for i, addr in enumerate(_RESERVED)}
    asked: dict[str, list[str]] = {}

    def answer(host: str, *_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        if host not in rows:
            raise socket.gaierror(socket.EAI_NONAME, f"{host} is not a row of the corpus")
        asked.setdefault(host, []).append(rows[host])
        addr = rows[host]
        if ":" in addr:
            return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (addr, port, 0, 0))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, port))]

    monkeypatch.setattr(socket, "getaddrinfo", answer)
    return asked


def test_every_reserved_row_as_a_resolver_answer_is_refused(
    listener: _CountingListener, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every reserved row, the zoned ones included, is refused when the resolver answers
    a name with it, by the sync and the async client.

    The resolver answers, so only the address check can refuse: a check that let a zoned
    address through would hand it to the dial, and the request would fail with a
    connection error rather than the guard's refusal.
    """
    asked = _resolving_every_row(monkeypatch, listener.port)
    names = [f"row-{i}.peer.example" for i in range(len(_RESERVED))]
    assert any("%" in addr for addr in _RESERVED), "the corpus has no zoned row"

    async def run_async() -> None:
        async with guarded_async_client(timeout=2.0) as client:
            for name in names:
                with pytest.raises(SsrfError, match=re.escape(f"refusing to dial '{name}'")):
                    await client.get(f"https://{name}:{listener.port}/")

    with guarded_client(timeout=2.0) as client:
        for name in names:
            with pytest.raises(SsrfError, match=re.escape(f"refusing to dial '{name}'")):
                client.get(f"https://{name}:{listener.port}/")
    asyncio.run(run_async())
    assert asked == {name: [addr, addr] for name, addr in zip(names, _RESERVED, strict=True)}
    assert listener.accepted == 0, "a refused target is never dialed"


def test_proxy_env_does_not_tunnel_past_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    """A set HTTP(S)_PROXY does not take a dial around the address guard.

    The proxy is a loopback listener that counts connections. A guarded client that
    honoured the proxy would dial it, so the refusal must name the target and the proxy
    must see no connection.
    """
    proxy = _CountingListener()
    try:
        for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.port}")
        with guarded_client(timeout=2.0) as client, pytest.raises(SsrfError) as caught:
            client.get("https://10.0.0.1/")
        assert "'10.0.0.1'" in str(caught.value), "the refusal names the target, not the proxy"
        assert proxy.accepted == 0, "the guarded client must not dial the proxy"
    finally:
        proxy.close()
