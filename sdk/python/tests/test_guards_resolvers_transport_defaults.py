"""Which transport a resolver takes when the caller injects none, for the one face the
shared corpus cannot carry.

The rule is that a resolver's default follows its URL's PROVENANCE: a fixed,
operator-chosen address takes the plain client, a host another party named takes the
guarded one (the Go oracle's ``WellKnownOptions.HTTP`` comment). Every face whose outcome
reads the same through all three public surfaces is pinned by the shared corpus
``resolver-default-vectors.json``, replayed in ``test_resolver_default_parity.py``.

The offer-directory fetch is the exception. Its default is guarded in all three
languages, but this seam contains every failure as ``None`` where Go returns the error, so
the refusal a corpus row records is not observable here. What every language can observe
is the socket: the guarded default never connects to a loopback listener. Each language
pins that in its own copy of this test.

CHANGING THIS OBLIGES A CHECK OF THE ``License.uri`` SSRF GUARDS in
``proto/fora/v1/fora.proto`` and Licensing Terms
(``website/src/content/docs/protocol/licensing-terms.mdx``), which say what a consumer must
apply before it fetches a URL another party named.
"""

from __future__ import annotations

import asyncio
import http.server
import threading
from typing import TYPE_CHECKING, Any

from fora_sdk.resolvers import create_wba_offer_directory_fetch

if TYPE_CHECKING:
    import pytest


def test_offer_directory_fetch_defaults_to_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    # The flags are cleared rather than inherited from the shell, and ALLOW_INSECURE is
    # set so the scheme guard is not what refuses the plaintext listener: the address
    # guard must.
    for name in ("SKIP_SSRF", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ALLOW_INSECURE", "1")
    connections = 0

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # BaseHTTPRequestHandler contract
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            return

    class _CountingServer(http.server.ThreadingHTTPServer):
        def verify_request(self, request: Any, client_address: Any) -> bool:  # noqa: ARG002 - socketserver hook, called once per accepted connection
            nonlocal connections
            connections += 1
            return True

    server = _CountingServer(("127.0.0.1", 0), _Handler)
    threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    ).start()
    try:
        fetch = create_wba_offer_directory_fetch(scheme="http")
        # The result is deliberately not read: the seam answers None for a refusal and a
        # failed read alike, and ``connections`` is what says which happened.
        asyncio.run(fetch(f"127.0.0.1:{server.server_address[1]}"))
    finally:
        server.shutdown()
        server.server_close()
    assert connections == 0, (
        "the offer-directory fetch's default transport reached a loopback origin; its "
        "exchange domain comes off an offer, so the default must be the guarded client"
    )
