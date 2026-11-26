"""The loopback listener the resolver suites serve from.

``listen`` builds a server on 127.0.0.1 and a free port that counts the connections it
accepts (``CountingServer``), answering over TLS with a self-signed identity for 127.0.0.1
when asked. ``resolvers_harness.loopback_client()`` trusts that identity, the way the Go
suites use the client of an ``httptest.NewTLSServer``. Split from ``resolvers_harness`` so
each module stays under the file-length limit; it imports nothing from ``fora_sdk``.
"""

from __future__ import annotations

import functools
import ipaddress
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID


@functools.cache
def tls_files() -> tuple[str, str]:
    """The certificate and key files of the self-signed TLS identity every
    ``Origin(tls=True)`` serves: one P-256 certificate for 127.0.0.1 and localhost,
    minted once per test run and trusted by ``loopback_client()``."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fora-sdk test origin")])
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    tmp = Path(tempfile.mkdtemp(prefix="fora-sdk-tls-"))
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(Encoding.PEM))
    key_path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    return str(cert_path), str(key_path)


def serve_tls(server: ThreadingHTTPServer) -> None:
    """Make ``server`` answer over TLS with the test identity ``loopback_client()``
    trusts. Call it before the server starts serving."""
    cert_path, key_path = tls_files()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)


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
