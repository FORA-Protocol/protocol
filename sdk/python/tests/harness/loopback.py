"""The in-process loopback servers the suites drive the SDK against.

A server listens on 127.0.0.1 and a free port, over TLS with a self-signed identity
when asked. ``loopback_client()`` is the plain httpx.Client that trusts that identity
and reaches the loopback address the SDK's guarded default refuses.
"""

from __future__ import annotations

import functools
import ipaddress
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

_FETCH_TIMEOUT_S = 10.0


@functools.cache
def _tls_files() -> tuple[str, str]:
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
    cert_path, key_path = _tls_files()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)


def listen(handler: type[BaseHTTPRequestHandler], *, tls: bool) -> ThreadingHTTPServer:
    """A server for ``handler`` on 127.0.0.1 and a free port, answering over TLS when
    ``tls`` is set."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if tls:
        serve_tls(server)
    return server


def loopback_client() -> httpx.Client:
    """An UNGUARDED httpx.Client the resolver suites inject to reach the in-process
    origin.

    The origin listens on 127.0.0.1, which the SDK's default SSRF-guarded transport
    refuses to dial (loopback is a reserved target). Mirroring the Go oracle — whose
    httptest suites inject their own client past the guarded default — the
    integration suites inject this plain client via ``http=`` to REACH the private
    test directory. It is the escape hatch: a maintained httpx.Client with no SSRF
    guard, so 127.0.0.1 is reachable. It trusts the certificate a TLS origin serves
    (``Origin(tls=True)``, ``serve_tls``), the way the Go suites use the client of an
    ``httptest.NewTLSServer``.
    """
    verify = ssl.create_default_context(cafile=_tls_files()[0])
    return httpx.Client(follow_redirects=True, timeout=_FETCH_TIMEOUT_S, verify=verify)


def serve(handler: type[BaseHTTPRequestHandler]) -> tuple[ThreadingHTTPServer, int]:
    """Start a plain-HTTP server for ``handler`` on 127.0.0.1; return it and its port.
    The caller shuts it down."""
    server = listen(handler, tls=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]
