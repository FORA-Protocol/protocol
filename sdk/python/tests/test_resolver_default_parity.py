"""Replays resolver-default-vectors.json: which transport each resolver face takes when the
caller injects none, and what that default does with each target.

The Go oracle (``sdk/go/resolvers/gen_resolver_default_vectors_test.go``) emits every row by
driving its own face against a real listener, so the outcomes are Go's observed behaviour,
not a table written by hand. This replay drives the same face through this SDK's public
constructor, with no transport injected, against the same harness:

- one loopback listener that counts the TCP connections it accepts, so a refusal before the
  dial is observable as zero connections;
- IP-literal hosts for the private and link-local targets, which have no listener.

Nothing in the SDK is replaced: the transport under test is always the face's own default.

The rule the rows pin is that a resolver's default follows its URL's provenance: a fixed,
operator-chosen address takes the plain client, a host another party named takes the guarded
one. Changing a row obliges a check of the ``License.uri`` SSRF guards in
``proto/fora/v1/fora.proto`` and Licensing Terms (``/protocol/licensing-terms/``), which say
what a consumer must apply before it fetches a URL another party named.
"""

from __future__ import annotations

import http.server
import json
import threading
from typing import Any

import pytest
from conftest import GO_RESOLVERS_TESTDATA, load_json
from wire.models import License

from fora_sdk.resolvers import (
    SsrfError,
    WellKnownEndpointResolver,
    WellKnownKeyResolver,
    WellKnownRequirementsReader,
    read_license_document,
    read_manifest,
    read_revocation_list,
    read_wba_directory,
)

_VECTORS = load_json(GO_RESOLVERS_TESTDATA / "resolver-default-vectors.json")["resolver_defaults"]

_PRIVATE = "10.0.0.5:9"
_LINK_LOCAL = "169.254.169.254:9"
_LISTENER = "127.0.0.1"
# Well-formed, so the License passes its strict check and the read reaches the transport.
_LICENSE_DIGEST = "sha256:" + "0" * 64


class _Listener:
    """The loopback origin: serves a manifest naming itself and counts accepted
    connections."""

    def __init__(self) -> None:
        self.connections = 0
        listener = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
                host = self.headers.get("Host", "")
                body = json.dumps(
                    {
                        "ver": "1.0",
                        "role": "ROLE_EXCHANGE",
                        "endpoint": f"http://{host}/fora.v1.ExchangeService",
                        "keys": [],
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return

        class _CountingServer(http.server.ThreadingHTTPServer):
            def verify_request(self, request: Any, client_address: Any) -> bool:  # noqa: ARG002 - socketserver hook, called once per accepted connection
                listener.connections += 1
                return True

        self._server = _CountingServer((_LISTENER, 0), _Handler)
        self.host = f"{_LISTENER}:{self._server.server_address[1]}"
        threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        ).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _exercise(face: str, host: str) -> None:
    """Run one face's DEFAULT construction against ``host``, as a caller injecting nothing."""
    if face == "wellknown_key_resolver":
        WellKnownKeyResolver(f"http://{host}/.well-known/fora.json").resolve("ex.v1")
    elif face == "wellknown_endpoint_resolver":
        WellKnownEndpointResolver(scheme="http").resolve_endpoint(host)
    elif face == "registration_requirements_reader":
        WellKnownRequirementsReader(scheme="http").resolve_registration_requirements(host)
    elif face == "manifest_reader":
        read_manifest(host, scheme="http")
    elif face == "wba_directory_reader":
        read_wba_directory(host, scheme="http")
    elif face == "revocation_list_reader":
        read_revocation_list(f"http://{host}/revocation")
    elif face == "license_document_reader":
        read_license_document(License(uri=f"http://{host}/license", uri_digest=_LICENSE_DIGEST))
    else:
        raise AssertionError(f"unknown face {face!r}")


def _classify(exc: BaseException | None) -> str:
    """Which check refused, read from the exception a face raised and its cause chain."""
    if exc is None:
        return "no error"
    cur: BaseException | None = exc
    while cur is not None:
        if isinstance(cur, SsrfError):
            return "refused_scheme" if "scheme" in str(cur) else "refused_address"
        cur = cur.__cause__ or cur.__context__
    return f"other: {exc!r}"


def _run(face: str, host: str) -> BaseException | None:
    try:
        _exercise(face, host)
    except Exception as exc:  # the refusal is classified, not handled
        return exc
    return None


@pytest.mark.parametrize("vector", _VECTORS, ids=[v["name"] for v in _VECTORS])
def test_resolver_default_matches_the_oracle(
    vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)
    if vector["allow_insecure"]:
        monkeypatch.setenv("ALLOW_INSECURE", "1")
    target = vector["target"]

    if target == "private":
        got = _classify(_run(vector["face"], _PRIVATE))
    elif target == "link_local":
        got = _classify(_run(vector["face"], _LINK_LOCAL))
    else:
        listener = _Listener()
        try:
            exc = _run(vector["face"], listener.host)
        finally:
            listener.close()
        got = "reached" if listener.connections > 0 else _classify(exc)

    assert got == vector["outcome"], (
        f"{vector['name']}: this SDK's default transport gave {got!r}, the Go oracle "
        f"{vector['outcome']!r}. If the change is intended, change the oracle and check it "
        "against the License.uri SSRF guards in proto/fora/v1/fora.proto."
    )
