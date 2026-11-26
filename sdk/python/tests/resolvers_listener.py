"""The loopback listener the resolver suites serve from.

``listen`` builds a server on 127.0.0.1 and a free port that counts the connections it
accepts (``CountingServer``), answering over TLS when asked with the self-signed identity
for 127.0.0.1 that ``tls_loopback`` mints and ``tls_loopback.loopback_client()`` trusts, the
way the Go suites use the client of an ``httptest.NewTLSServer``. Split from
``resolvers_harness`` so each module stays under the file-length limit; it imports nothing
from ``fora_sdk``.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tls_loopback import serve_tls


class CountingServer(ThreadingHTTPServer):
    """A ``ThreadingHTTPServer`` that counts the connections it accepts.

    A refusal before the dial makes no connection at all, so the count, not a request
    count, is what tells a refused fetch from a fetch that reached the server and then
    failed. ``verify_request`` runs once per accepted connection, before any request is
    read; on a TLS server it runs after the handshake, so a client whose handshake failed
    is not counted."""

    connections = 0

    def verify_request(self, _request: object, _client_address: object) -> bool:
        """The socketserver hook called once per accepted connection: count it, keep it."""
        self.connections += 1
        return True


def listen(handler: type[BaseHTTPRequestHandler], *, tls: bool) -> CountingServer:
    """A server for ``handler`` on 127.0.0.1 and a free port, answering over TLS when
    ``tls`` is set."""
    server = CountingServer(("127.0.0.1", 0), handler)
    if tls:
        serve_tls(server)
    return server
