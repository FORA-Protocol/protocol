"""What the shared corpus does not carry about the endpoint resolver's DEFAULT client.

Which outcome the default gives for a loopback, private or link-local address and for plain
http is pinned across the three languages by ``resolver-default-vectors.json``
(``test_resolver_default_parity.py``). The cases here are the ones that corpus does not
express: a host NAME that resolves to a reserved address, IPv4 and IPv6, rather than an IP
literal; an injected client used exactly as given; and the default built once per resolver
rather than per resolve. TypeScript pins the same three cases in
``resolvers-wellknown-endpoint-guarded-default.test.ts``.

Nothing in the SDK is replaced. The test replaces ``socket.getaddrinfo``, the resolver the
guarded client's dial calls, so a few ``.example`` names answer with reserved addresses and
no listener is needed on them; the fake records every name it is asked, so a test can show
the refusal came from the fake's answer and not from a name that does not resolve. It also
counts ``httpx.Client`` constructions. Both belong to libraries, not to the SDK.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from harness.loopback import loopback_client
from harness.origin import Origin, manifest_json

from fora_sdk.resolvers import DirectoryUnavailableError, SsrfError, WellKnownEndpointResolver

if TYPE_CHECKING:
    from collections.abc import Callable

# Every test starts from a cleared SSRF environment (conftest.ssrf_env).
pytestmark = pytest.mark.usefixtures("ssrf_env")

_REAL_GETADDRINFO = socket.getaddrinfo


def _answer_dns(monkeypatch: pytest.MonkeyPatch, answers: dict[str, str]) -> list[str]:
    """Answer the names in ``answers`` with the given address and resolve the rest for
    real. Returns the list of every name asked, in order."""
    asked: list[str] = []

    def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        asked.append(host)
        address = answers.get(host)
        if address is None:
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)
        if ":" in address:
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port, 0, 0))
            ]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return asked


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
    # The default https scheme with no flag set, so only the address guard can refuse.
    asked = _answer_dns(monkeypatch, {"exchange.example": address})
    r = WellKnownEndpointResolver()
    refusal = _guard_refusal(lambda: r.resolve_endpoint("exchange.example"))
    # The generic refusal: it names the host, never the address it resolved to.
    assert "exchange.example" in str(refusal)
    assert address not in str(refusal)
    # The guard asked the fake, so the refusal is of its reserved answer; a name that did
    # not resolve at all would be refused with the same message.
    assert "exchange.example" in asked


def test_uses_an_injected_client_exactly_as_given() -> None:
    # No flags are set, so the guarded default would refuse this loopback origin: only
    # the injected client, used as given, can reach it.
    origin = Origin()
    origin.set_manifest(manifest_json(f"http://{origin.host}/fora.v1.ExchangeService"))
    seen: list[str] = []
    client = loopback_client()
    client.event_hooks["request"].append(lambda request: seen.append(str(request.url)))
    try:
        r = WellKnownEndpointResolver(scheme="http", http=client)
        assert r.resolve_endpoint(origin.host) == f"http://{origin.host}/fora.v1.ExchangeService"
        assert seen == [f"http://{origin.host}/.well-known/fora.json"]
    finally:
        client.close()
        origin.close()


def test_an_httpx_client_is_built_once_per_resolver_not_per_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """guarded_client() builds a connection pool, so the default is built with the
    resolver; a per-resolve default would leak one pool per call. A refusal is never
    cached, so each of the three resolves below goes back to the transport. The default
    https scheme with no flag set: the address guard refuses the loopback host."""
    built: list[httpx.Client] = []
    real_init = httpx.Client.__init__

    def counting_init(self: httpx.Client, *args: Any, **kwargs: Any) -> None:
        built.append(self)
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", counting_init)
    r = WellKnownEndpointResolver()
    assert len(built) == 1
    for _ in range(3):
        _guard_refusal(lambda: r.resolve_endpoint("127.0.0.1:9"))
    assert len(built) == 1
