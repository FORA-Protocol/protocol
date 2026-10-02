"""A peer that authenticates every request before it answers, behind ``httpx.MockTransport``.

The client suites inject an httpx transport so a test sees exactly what went on the wire.
A plain recorder proves the bytes were sent; it cannot prove a server would have ACCEPTED
them. Two capabilities depend on that second property: a request altered before it is
signed is only useful if the signature covers the altered bytes, and a freshly minted
identity is only useful if a verifier can resolve its key. So this peer runs the SDK's own
server-side verifier, ``verify_request_server``, on every request and refuses one that
fails with the 401 envelope an Exchange sends.

The key lookup is injected as a function of the covered Signature-Agent header, which is
how a real Exchange finds a caller's key: a static map for a test that only needs one
fixed identity, a WBA directory resolver for one that mints its own.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

from fora_sdk.server_verify import verify_request_server

if TYPE_CHECKING:
    from collections.abc import Callable

    from fora_sdk.httpsig import VerifiedRequest
    from fora_sdk.keyresolver import KeyResolver

#: What a peer answers a verified request with when the test supplies no answer of its
#: own. Both ResourceResponse and every catalog response validate against it.
DEFAULT_ANSWER: dict[str, Any] = {"ver": "1.0", "exchange": "exchange.test"}


@dataclass(frozen=True)
class Received:
    """One request as the peer received it, and the verifier's verdict on it."""

    request: httpx.Request
    verdict: VerifiedRequest

    def header(self, name: str) -> str | None:
        return self.request.headers.get(name)


@dataclass
class SignedPeer:
    """An httpx MockTransport peer that verifies the RFC 9421 signature first.

    ``keys`` maps the received Signature-Agent value to the resolver the verifier uses.
    ``answer`` builds the response for a request that verified; it defaults to a 200
    carrying :data:`DEFAULT_ANSWER`.
    """

    keys: Callable[[str], KeyResolver]
    answer: Callable[[httpx.Request], httpx.Response] | None = None
    seen: list[Received] = field(default_factory=list)

    def _respond(self, request: httpx.Request) -> httpx.Response:
        request.read()
        headers = {k.lower(): v for k, v in request.headers.items()}
        verdict = verify_request_server(
            method=request.method,
            url=str(request.url),
            body=request.content,
            headers=headers,
            resolver=self.keys(headers.get("signature-agent", "")),
            now=int(time.time()),
        )
        self.seen.append(Received(request=request, verdict=verdict))
        if not verdict.valid:
            return httpx.Response(
                401, json={"code": "unauthenticated", "message": verdict.reason or "signature"}
            )
        if self.answer is not None:
            return self.answer(request)
        return httpx.Response(200, json=DEFAULT_ANSWER)

    def sync(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._respond))

    def async_(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._respond))

    def only(self) -> Received:
        """The single request this peer received; fails the test on any other count."""
        assert len(self.seen) == 1, f"expected exactly one request, peer saw {len(self.seen)}"
        return self.seen[0]


def envelope_response(status: int, envelope: dict[str, Any]) -> httpx.Response:
    """A Connect error answer carrying ``envelope`` verbatim."""
    return httpx.Response(status, content=json.dumps(envelope).encode(),
                          headers={"content-type": "application/json"})
