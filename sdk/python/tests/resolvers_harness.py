"""Shared served-directory harness for the resolver integration suites.

Per the FORA testing doctrine the ported resolver faces are IO-BOUND, so the
suites drive them against a REAL in-process ``http.server.ThreadingHTTPServer``
on 127.0.0.1:0 — never a mocked HTTP callable. The WBA suites inject
``loopback_client()`` (a plain, unguarded httpx.Client) so the guarded default
does not refuse the loopback origin; only the clock (and the poll timer/seams for
the WBA poller) are injected for determinism.

A key directory is served under the Web Bot Auth profile: its own media type and a
response signed, for the authority it was fetched from, by every listed key a test
minted. Every key ``make_key`` mints is registered by its public half, and a test that
mints keys elsewhere registers them with ``register_directory_key``; a listed key
nobody registered is left unsigned, which a reader treats as absent. A member is an
https origin and ``WBAKeyResolver`` always fetches it over https, so a WBA suite builds
``Origin(tls=True)``: the origin serves TLS with a certificate for 127.0.0.1 that
``loopback_client()`` trusts, and ``Origin.origin`` is the member.

This module imports ONLY the byte-parity-pinned SDK primitives (``thumbprint``,
``b64url_nopad``, the directory response signer) and never the ``fora_sdk.resolvers``
faces, so a RED run points at the faces rather than at this fixture.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import queue
import ssl
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from fora_sdk.wire import WellKnownManifestVersion

from fora_sdk.b64 import b64url_nopad
from fora_sdk.directory_signature import sign_directory_response
from fora_sdk.thumbprint import thumbprint

# Well-known paths the origin serves. The WBA directory path is the fixed Web Bot
# Auth path; the JWKS key doc and the endpoint manifest sit on distinct paths so
# the key face (fixed URL) and endpoint face (host-keyed fora.json) never collide.
WBA_DIR_PATH = "/.well-known/http-message-signatures-directory"
REVOCATION_PATH = "/.well-known/fora-key-revocations.json"
MANIFEST_PATH = "/.well-known/fora.json"
JWKS_PATH = "/keys.json"
LICENSE_PATH = "/licensing/terms.txt"

# The shared anchor sits well inside the validity windows the active-key builders
# emit.
ANCHOR = datetime(2026, 5, 1, 12, 0, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)

_FETCH_TIMEOUT_S = 10.0

#: The media type a key directory is served under (WG-00 §5.5).
WBA_MEDIA_TYPE = "application/http-message-signatures-directory+json"

# A window wide enough to contain every injected test clock.
_DIRECTORY_SIGNATURE_CREATED = 1
_DIRECTORY_SIGNATURE_EXPIRES = 1 << 40

# base64url public key -> the private key that signs a directory listing it.
_DIRECTORY_KEYS: dict[str, Ed25519PrivateKey] = {}
_DIRECTORY_KEYS_LOCK = threading.Lock()


def register_directory_key(priv: Ed25519PrivateKey) -> None:
    """Make ``priv`` sign every served directory that lists its public key."""
    x = b64url_nopad(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    with _DIRECTORY_KEYS_LOCK:
        _DIRECTORY_KEYS[x] = priv


def signed_directory_headers(authority: str, body: bytes) -> dict[str, str]:
    """The response-signature headers for a directory ``body`` served under
    ``authority``: one signature per listed key a test registered, none when the
    body lists no registered key or is not a directory at all."""
    try:
        listed = [k.get("x") for k in json.loads(body).get("keys") or []]
    except (ValueError, AttributeError, TypeError):
        return {}
    with _DIRECTORY_KEYS_LOCK:
        privs = [_DIRECTORY_KEYS[x] for x in listed if isinstance(x, str) and x in _DIRECTORY_KEYS]
    if not privs:
        return {}
    seeds = [p.private_bytes_raw() for p in privs]
    signed = sign_directory_response(
        authority, body, seeds, _DIRECTORY_SIGNATURE_CREATED, _DIRECTORY_SIGNATURE_EXPIRES
    )
    return signed.headers()


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


@dataclass
class TestKey:
    """A real Ed25519 key: raw 32-byte public key, its base64url ``x``, and its
    RFC 7638 thumbprint (the WBA keyid), derived through the SDK's own primitive."""

    raw_pub: bytes
    x: str
    tp: str


def make_key() -> TestKey:
    """Mint a fresh Ed25519 key and derive its SDK thumbprint."""
    priv = Ed25519PrivateKey.generate()
    register_directory_key(priv)
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x = b64url_nopad(raw)
    return TestKey(raw_pub=raw, x=x, tp=thumbprint(raw))


def rfc3339(instant: datetime) -> str:
    """RFC3339-Z rendering of an aware instant."""
    return instant.astimezone(UTC).isoformat().replace("+00:00", "Z")


def wba_jwk(x: str, not_before: datetime, not_after: datetime) -> dict[str, Any]:
    """One JWK member of a WBA directory, snake_case exactly as the Go oracle
    emits it via protojson (UseProtoNames)."""
    return {
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "x": x,
        "not_before": rfc3339(not_before),
        "not_after": rfc3339(not_after),
    }


def wba_file_json(keys: list[dict[str, Any]], revocation_url: str | None = None) -> str:
    """Serialize a WBAFile carrying keys (and optionally a revocation_url)."""
    doc: dict[str, Any] = {"keys": keys}
    if revocation_url is not None:
        doc["revocation_url"] = revocation_url
    return json.dumps(doc)


def revocation_json(as_of: datetime, revoked: list[str]) -> str:
    """Serialize a KeyRevocationList snapshot (as_of RFC3339-Z + thumbprints)."""
    return json.dumps({"as_of": rfc3339(as_of), "revoked": revoked})


def jwks_entry(kid: str, x: str) -> dict[str, Any]:
    """A valid Ed25519 JWKS entry keyed by kid (the ad-hoc doc shape)."""
    return {"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": x}


def jwks_key_doc_json(entries: list[dict[str, Any]]) -> str:
    """Serialize the ad-hoc kid-carrying JWKS key doc: ``{keys:[{kid,kty,crv,x}]}``."""
    return json.dumps({"keys": entries})


def manifest_json(
    endpoint: str | None = None, *, ver: str | None = WellKnownManifestVersion
) -> str:
    """Serialize a WellKnownManifest projection ({ver, role, endpoint}); omit
    endpoint to model a valid-but-inert manifest, and pass ``ver=None`` to omit
    the version member and model a manifest with no version at all."""
    doc: dict[str, Any] = {"role": "ROLE_EXCHANGE"}
    if ver is not None:
        doc["ver"] = ver
    if endpoint is not None:
        doc["endpoint"] = endpoint
    return json.dumps(doc)


@dataclass
class _State:
    wba: str | None = None
    wba_status: int = 0
    rev: str | None = None
    jwks: str | None = None
    jwks_status: int = 0
    jwks_hits: int = 0
    manifest: str | None = None
    manifest_status: int = 0
    manifest_hits: int = 0
    license: bytes | None = None
    # A path's Content-Type, where it is not application/json; None omits the header.
    content_types: dict[str, str | None] = field(default_factory=dict)
    # A path answered with a 302 to the given location instead of its document.
    redirects: dict[str, str] = field(default_factory=dict)


def _resolve_route(state: _State, path: str) -> tuple[int, bytes] | None:  # noqa: PLR0911 — flat route table
    if path == WBA_DIR_PATH:
        if state.wba_status != 0:
            return state.wba_status, b""
        if state.wba is None:
            return 404, b""
        return 200, state.wba.encode()
    if path == REVOCATION_PATH:
        if state.rev is None:
            return 404, b""
        return 200, state.rev.encode()
    if path == JWKS_PATH:
        state.jwks_hits += 1
        if state.jwks_status != 0:
            return state.jwks_status, b""
        if state.jwks is None:
            return 404, b""
        return 200, state.jwks.encode()
    if path == MANIFEST_PATH:
        state.manifest_hits += 1
        if state.manifest_status != 0:
            return state.manifest_status, b""
        if state.manifest is None:
            return 404, b""
        return 200, state.manifest.encode()
    if path == LICENSE_PATH:
        if state.license is None:
            return 404, b""
        return 200, state.license
    return None


class Origin:
    """A real in-process origin serving the WBA directory, revocation snapshot,
    JWKS key doc, and fora.json manifest. Each doc is independently settable so a
    test can rotate keys, publish a new revocation snapshot, or force a 500.

    ``tls=True`` serves https, which is how a ``WBAKeyResolver`` reaches it."""

    def __init__(self, *, tls: bool = False) -> None:
        self._state = _State()
        state = self._state

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = self.path.split("?")[0]
                if path in state.redirects:
                    self.send_response(302)
                    self.send_header("location", state.redirects[path])
                    self.end_headers()
                    return
                hit = _resolve_route(state, path)
                if hit is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                code, body = hit
                self.send_response(code)
                default_type = WBA_MEDIA_TYPE if path == WBA_DIR_PATH else "application/json"
                content_type = state.content_types.get(path, default_type)
                if content_type is not None:
                    self.send_header("content-type", content_type)
                if path == WBA_DIR_PATH and code == 200:
                    authority = (self.headers.get("Host") or "").lower()
                    for name, value in signed_directory_headers(authority, body).items():
                        self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: Any) -> None:  # silence the test server
                return

        self._server = listen(_Handler, tls=tls)
        self.host = f"127.0.0.1:{self._server.server_address[1]}"
        self.url = f"{'https' if tls else 'http'}://{self.host}"
        #: The https origin a Signature-Agent member names for this origin's directory.
        #: Only an ``Origin(tls=True)`` answers it.
        self.origin = f"https://{self.host}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def set_wba(self, body: str) -> None:
        self._state.wba = body

    def set_wba_status(self, code: int) -> None:
        self._state.wba_status = code

    def set_revocation(self, body: str) -> None:
        self._state.rev = body

    def set_jwks(self, body: str) -> None:
        self._state.jwks = body

    def set_jwks_status(self, code: int) -> None:
        self._state.jwks_status = code

    def jwks_hits(self) -> int:
        return self._state.jwks_hits

    def set_manifest(self, body: str) -> None:
        self._state.manifest = body

    def set_manifest_status(self, code: int) -> None:
        self._state.manifest_status = code

    def manifest_hits(self) -> int:
        return self._state.manifest_hits

    def revocation_url(self) -> str:
        return self.url + REVOCATION_PATH

    def set_license(self, body: bytes) -> None:
        self._state.license = body

    def license_url(self) -> str:
        return self.url + LICENSE_PATH

    def set_redirect(self, path: str, location: str) -> None:
        """Answer ``path`` with a 302 to ``location``."""
        self._state.redirects[path] = location

    def set_content_type(self, path: str, value: str | None) -> None:
        """Serve ``path`` with ``value`` as its Content-Type; ``None`` sends none."""
        self._state.content_types[path] = value

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class MutableClock:
    """A settable ``now`` seam for the non-poller cases: ``t`` is mutated between
    resolves to expire TTLs and cross validity windows."""

    def __init__(self, start: datetime) -> None:
        self.t = start

    def __call__(self) -> datetime:
        return self.t


@dataclass
class DeterministicClock:
    """A deterministic clock for the poller test: ``now()`` is a mutable instant;
    ``after(delay)`` returns a queue that receives a value when ``advance()`` moves
    the clock to or past the scheduled instant. Port of the Go pollClock
    (func() time.Time / func(Duration) <-chan time.Time) — the poller crosses a
    boundary without sleeping."""

    _now: datetime
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _pending: list[tuple[datetime, queue.Queue[datetime]]] = field(default_factory=list)

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def after(self, delay: timedelta) -> queue.Queue[datetime]:
        q: queue.Queue[datetime] = queue.Queue(maxsize=1)
        with self._lock:
            if delay <= timedelta(0):
                q.put(self._now)
                return q
            self._pending.append((self._now + delay, q))
        return q

    def advance(self, delay: timedelta) -> None:
        with self._lock:
            self._now = self._now + delay
            due = [p for p in self._pending if p[0] <= self._now]
            self._pending = [p for p in self._pending if p[0] > self._now]
            fire_at = self._now
        for _, q in due:
            q.put(fire_at)


class PollSignals:
    """Bridges the resolver's on_poll_armed / on_poll_cycle seams to the test, so
    it can wait for the poller to arm its timer, advance the clock, then wait for
    the refresh to complete — port of the Go pollSignals."""

    def __init__(self) -> None:
        self.armed: queue.Queue[bool] = queue.Queue()
        self.cycled: queue.Queue[bool] = queue.Queue()

    def on_armed(self) -> None:
        self.armed.put(True)

    def on_cycled(self) -> None:
        self.cycled.put(True)

    def cross_one(self, clk: DeterministicClock, advance: timedelta) -> None:
        self.armed.get(timeout=5)
        clk.advance(advance)
        self.cycled.get(timeout=5)


# Convenience validity-window builders around the shared anchor.
def active_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR - HOUR, ANCHOR + HOUR)


def expired_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR - 2 * HOUR, ANCHOR - HOUR)


def long_jwk(x: str) -> dict[str, Any]:
    return wba_jwk(x, ANCHOR - HOUR, ANCHOR + 1000 * HOUR)


NowFn = Callable[[], datetime]
