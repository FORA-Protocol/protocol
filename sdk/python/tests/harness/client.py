"""The two client faces and the transport that records what a client sent.

Every client suite runs each case on both faces: the async client is the core and the
sync module is a facade over a blocking httpx client, so a case that passes on one and
fails on the other is a defect. ``Recorder`` answers a fixed body and keeps every request
it was handed, so a test reads what went on the wire through the client it injected.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

import fora_sdk.sync as sync_client
from fora_sdk.client import BrokerClient, Client, ClientConfig
from fora_sdk.resolvers import RegistrationRequirements
from fora_sdk.wire import WellKnownManifestVersion

from .origin import manifest_json


class Answerer:
    """An httpx transport answered by ``_respond``, as a client of either face."""

    def _respond(self, request: httpx.Request) -> httpx.Response:
        raise NotImplementedError

    def sync(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self._respond))

    def async_(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self._respond))


class Recorder(Answerer):
    """An httpx transport that records what it was handed and answers a fixed body.

    The body is ``answer`` as JSON; ``Recorder.raw`` answers raw bytes and headers instead.
    """

    def __init__(self, answer: Any, status: int = 200) -> None:
        self.answer = answer
        self.status = status
        self.seen: list[httpx.Request] = []
        self._raw: tuple[bytes, dict[str, str]] | None = None

    @classmethod
    def raw(cls, status: int, body: bytes = b"", headers: dict[str, str] | None = None) -> Recorder:
        """A Recorder that answers ``status`` with exactly ``body`` and ``headers``."""
        recorder = cls(None, status)
        recorder._raw = (body, headers or {})
        return recorder

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        if self._raw is not None:
            return httpx.Response(self.status, content=self._raw[0], headers=self._raw[1])
        return httpx.Response(self.status, json=self.answer)

    @property
    def urls(self) -> list[str]:
        """The URL of every request handed to this transport, in order."""
        return [str(request.url) for request in self.seen]

    def body(self, index: int = 0) -> dict[str, Any]:
        return json.loads(self.seen[index].content)


class Face:
    """One client face, driven synchronously so both read the same in a test."""

    def __init__(self, name: str, is_async: bool) -> None:
        self.name = name
        self._async = is_async

    def client(self, config: ClientConfig, answer: Answerer | httpx.MockTransport) -> Any:
        """The client of this face over ``answer``: an Answerer, or any httpx transport."""
        if self._async:
            return Client(config, http=self._async_http(answer))
        return sync_client.Client(config, http=self._sync_http(answer))

    def broker(self, config: ClientConfig, recorder: Recorder) -> Any:
        if self._async:
            return BrokerClient(config, http=recorder.async_())
        return sync_client.BrokerClient(config, http=recorder.sync())

    @staticmethod
    def _async_http(answer: Answerer | httpx.MockTransport) -> httpx.AsyncClient:
        if isinstance(answer, httpx.MockTransport):
            return httpx.AsyncClient(transport=answer)
        return answer.async_()

    @staticmethod
    def _sync_http(answer: Answerer | httpx.MockTransport) -> httpx.Client:
        if isinstance(answer, httpx.MockTransport):
            return httpx.Client(transport=answer)
        return answer.sync()

    def run(self, call: Any) -> Any:
        return asyncio.run(call) if self._async else call


FACES = [Face("async", True), Face("sync", False)]
FACE_IDS = [f.name for f in FACES]


def manifest_client(
    endpoint: str | None = None, *, ver: str | None = WellKnownManifestVersion
) -> httpx.Client:
    """A client whose every request is answered with the manifest ``manifest_json``
    renders for ``endpoint`` and ``ver``."""
    body = manifest_json(endpoint, ver=ver).encode()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    return httpx.Client(transport=httpx.MockTransport(handler))


class FixedEndpoint:
    """An endpoint resolver that answers ``endpoint`` for every host."""

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint

    def resolve_endpoint(self, host: str) -> str:
        del host  # the test decides the endpoint
        return self._endpoint


class ApiSubdomain:
    """An endpoint resolver that answers ``https://api.<host>``."""

    def resolve_endpoint(self, host: str) -> str:
        return f"https://api.{host}"


class FixedRequirements:
    """A requirements reader that answers ``reqs``, or raises it, and counts its calls.

    With no argument it answers an Exchange that publishes neither a terms digest nor a
    registration schema.
    """

    def __init__(self, reqs: RegistrationRequirements | Exception | None = None) -> None:
        self._reqs = RegistrationRequirements() if reqs is None else reqs
        self.calls = 0

    def resolve_registration_requirements(self, exchange: str) -> RegistrationRequirements:
        del exchange  # the test decides the requirements
        self.calls += 1
        if isinstance(self._reqs, Exception):
            raise self._reqs
        return self._reqs
