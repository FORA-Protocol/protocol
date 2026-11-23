"""The guarded clients have no switch (mirror of sdk/go/resolvers/guardedclient_test.go).

``SKIP_SSRF`` and ``ALLOW_INSECURE`` once turned the two checks off for a whole process;
they are set here to prove nothing reads them any more. Every reserved address of the
shared address corpus, and a plaintext URL, is refused by the guard through the public
``guarded_client`` and ``guarded_async_client``, and a loopback listener standing in for
the target records that no connection was made.
"""

from __future__ import annotations

import asyncio
import socket
import threading
from typing import TYPE_CHECKING

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
