"""A real in-process Exchange: the WBA directory, fora.json, the three agent RPCs and
the delivery edge, over one ``ThreadingHTTPServer``.

``resolvers_harness`` serves the well-known documents the resolvers read, and stops
there on purpose — its docstring pins the constraint that it imports only
byte-parity-guarded primitives so a red run points at a missing resolver face. An
Exchange needs more: POST routing, a JCS-signed offer, an Ed25519 signed delivery URL
and a delivery leg that checks the proof of possession. That belongs in its own module,
which imports the shared document builders rather than restating them.

**Everything it answers is really signed, and everything an agent sends is really
checked.** The offer carries a signature the strict Verifier resolves against the key
this origin publishes in its directory; the delivery URL is bound to the agent's
thumbprint and the edge refuses a fetch whose proof does not present that key. Without
that, a test could only prove the calls did not raise — not that an Exchange would have
accepted them.

**The exchange domain IS the origin string** (``127.0.0.1:<port>``), and that is
load-bearing rather than convenient. It passes ``is_bare_domain``, so the wire fields
carrying a recipient validate; it passes ``is_bare_host``, so the client's own
``vet_exchange_endpoint`` lets a usage report through; and it anchors under
``endpoint_refusal``, which compares hostname AND canonical port, so the manifest may
advertise this origin as its own endpoint. Serving the Exchange on a different port from
the one its domain names breaks the third of those.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from resolvers_harness import (
    MANIFEST_PATH,
    WBA_DIR_PATH,
    make_key,
    manifest_json,
    rfc3339,
    wba_file_json,
    wba_jwk,
)

from fora_sdk.b64 import b64url_nopad
from fora_sdk.core import sign_offer_jcs
from fora_sdk.pop import verify_agent_binding
from fora_sdk.signedurl import sign_ed25519_signed_url, verify_ed25519_signed_url
from fora_sdk.thumbprint import thumbprint

if TYPE_CHECKING:
    from collections.abc import Callable

DISCOVER_PATH = "/fora.v1.ExchangeService/DiscoverResources"
EXECUTE_PATH = "/fora.v1.ExchangeService/ExecuteTransaction"
REPORT_PATH = "/fora.v1.ExchangeService/ReportUsage"
CONTENT_PATH = "/content/asset-1"

#: How far the published key window and the delivery URL's expiry sit from now. Every
#: clock in this harness is the REAL one — nothing injects a clock into the example
#: under test — so the windows are generous enough that a slow run cannot cross them.
_SLACK = timedelta(minutes=30)


@dataclass
class FakeExchange:
    """One running Exchange. ``domain`` is what an agent addresses it as."""

    domain: str
    url: str
    content: bytes
    #: Stops the origin's server thread. Set by `fake_exchange`, which is the only
    #: constructor — typed as a required callable rather than `Any = None`, so a
    #: FakeExchange built without one is a type error here instead of "NoneType is not
    #: callable" raised from `close()` at the end of a test.
    _shutdown: Callable[[], None]
    seen: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def close(self) -> None:
        self._shutdown()


def _signed_offer(*, seed: bytes, exchange: str, uri: str) -> dict[str, Any]:
    """An offer in WIRE form, signed over its CANONICAL form.

    That split is what a real Exchange does, and keeping it here is what makes the
    offer survive the client's ``from_wire_offer`` inversion: the client verifies the
    signature over the canonical projection of whatever it received, so signing the
    canonical form is the only thing that agrees with it.
    """
    # `identity.canonical_url` is how an Offer names its resource. Offer has no `uri`
    # field — that one belongs to OfferGroup, which carries it below — and signing a
    # field the schema does not define would have this harness prove the example
    # against a message no Exchange can send.
    offer: dict[str, Any] = {
        "offer_id": "offer-1",
        "exchange": exchange,
        "identity": {
            "canonical_url": uri,
            # Required, and {not_in:[0]} — an Exchange must state mutability
            # explicitly rather than leave it UNSPECIFIED.
            "resource_mutability": "RESOURCE_MUTABILITY_STATIC",
        },
        "expires_at": rfc3339(datetime.now(UTC) + _SLACK),
    }
    signature, algorithm = sign_offer_jcs(seed=seed, offer=offer)
    return {**offer, "signature": signature, "signature_algorithm": algorithm}


class _Exchange:
    """The mutable state one running origin serves."""

    def __init__(self, *, agent_thumbprint: str, content: bytes, tamper_offer: bool) -> None:
        self.offer_key = Ed25519PrivateKey.generate()
        self.offer_seed = self.offer_key.private_bytes_raw()
        self.offer_pub = self.offer_key.public_key().public_bytes_raw()
        self.delivery_key = Ed25519PrivateKey.generate()
        self.delivery_seed = self.delivery_key.private_bytes_raw()
        self.delivery_pub = self.delivery_key.public_key().public_bytes_raw()
        self.agent_thumbprint = agent_thumbprint
        self.content = content
        self.tamper_offer = tamper_offer
        self.serve_directory = True
        self.domain = ""
        self.url = ""
        self.seen: list[tuple[str, dict[str, Any]]] = []

    def directory(self) -> str:
        now = datetime.now(UTC)
        key = make_key()  # a second, inactive key so selection is doing real work
        return wba_file_json(
            [
                wba_jwk(key.x, now - 2 * _SLACK, now - _SLACK),
                wba_jwk(_b64(self.offer_pub), now - _SLACK, now + _SLACK),
            ]
        )

    def discover(self, body: dict[str, Any]) -> dict[str, Any]:
        uri = (body.get("uris") or ["https://publisher.example/article"])[0]
        offer = _signed_offer(seed=self.offer_seed, exchange=self.domain, uri=uri)
        if self.tamper_offer:
            offer["signature"] = _flip_one_nibble(offer["signature"])
        return {
            "ver": "1.0",
            "exchange": self.domain,
            "offer_groups": [{"uri": uri, "offers": [offer]}],
        }

    def execute(self, _body: dict[str, Any]) -> dict[str, Any]:
        signed = sign_ed25519_signed_url(
            self.url + CONTENT_PATH,
            seed=self.delivery_seed,
            kid="ex.v1",
            agent_id=self.agent_thumbprint,
            exp=int(time.time() + _SLACK.total_seconds()),
        )
        return {
            "ver": "1.0",
            "items": [
                {
                    "offer_id": "offer-1",
                    "transaction_id": "tx-1",
                    "billing_id": "bill-1",
                    "retrieval_endpoint": signed,
                    "expires_at": rfc3339(datetime.now(UTC) + _SLACK),
                }
            ],
        }


def _b64(raw: bytes) -> str:
    return b64url_nopad(raw)


def _flip_one_nibble(signature_hex: str) -> str:
    """Corrupt a signature by one nibble, leaving its length and alphabet intact.

    A truncated or non-hex value would be refused as malformed before any key was
    resolved, which is a different rejection from the one under test.
    """
    swapped = "0" if signature_hex[0] != "0" else "1"
    return swapped + signature_hex[1:]


def _make_handler(state: _Exchange) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, code: int, body: bytes, content_type: str) -> None:
            self.send_response(code)
            self.send_header("content-type", content_type)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: dict[str, Any]) -> None:
            self._send(code, json.dumps(payload).encode(), "application/json")

        def do_GET(self) -> None:
            path = self.path.split("?")[0]
            if path == WBA_DIR_PATH:
                if not state.serve_directory:
                    self._send(404, b"", "application/json")
                    return
                self._send(200, state.directory().encode(), "application/json")
                return
            if path == MANIFEST_PATH:
                self._send(200, manifest_json(endpoint=state.url).encode(), "application/json")
                return
            if path == CONTENT_PATH:
                self._deliver()
                return
            self._send(404, b"", "application/json")

        def _refuse(self, token: str) -> None:
            """Answer a delivery refusal the way the edge protocol defines it.

            The body is ``{"error": ..., "reason": ...}`` and the reason is the SHORT
            token the checkers themselves emit — "expired", "thumbprint_mismatch",
            "pop_sig_invalid". That is the edge's own vocabulary, and
            ``fora_sdk.client.content`` is what maps it onto the protocol's
            RetrievalAuthFailureReason. Passing the verifier's own reason through is
            also what a real edge does, so a refusal here is one the SDK can read
            instead of a string invented for the test.
            """
            self._json(403, {"error": "delivery refused", "reason": token})

        def _deliver(self) -> None:
            """The delivery edge: verify the signed URL, then the proof of possession.

            Both halves run, because each answers a different question. The signed URL
            proves the Exchange authorised this fetch; the proof proves the fetcher holds
            the key the URL was bound to. An edge checking only the first serves content
            to whoever copied the link.
            """
            target = f"http://{self.headers['host']}{self.path}"
            now = int(time.time())
            verdict = verify_ed25519_signed_url(
                target, now=now, resolve_key=lambda _kid: state.delivery_pub
            )
            if not verdict.valid or verdict.expired:
                self._refuse(verdict.reason or "signature_mismatch")
                return
            headers = {k.lower(): v for k, v in self.headers.items()}
            proof = verify_agent_binding(
                method="GET",
                url=target,
                headers=headers,
                agent_id=verdict.agent_id or "",
                now=now,
            )
            if not proof.ok:
                self._refuse(proof.reason or "pop_sig_invalid")
                return
            self._send(200, state.content, "text/plain; charset=utf-8")

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("content-length") or 0))
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                self._json(400, {"code": "invalid_argument", "message": "body is not JSON"})
                return
            path = self.path.split("?")[0]
            state.seen.append((path, body))
            if path == DISCOVER_PATH:
                self._json(200, state.discover(body))
            elif path == EXECUTE_PATH:
                self._json(200, state.execute(body))
            elif path == REPORT_PATH:
                self._json(200, {"ver": "1.0", "report_id": "report-1"})
            else:
                self._json(404, {"code": "unimplemented", "message": path})

        def log_message(self, *_args: Any) -> None:  # silence the test server
            return

    return _Handler


def fake_exchange(
    *,
    agent_seed: bytes,
    content: bytes = b"the licensed bytes",
    tamper_offer: bool = False,
    serve_directory: bool = True,
) -> FakeExchange:
    """Start one Exchange bound to ``agent_seed``'s identity. Call ``close()`` when done.

    The agent's thumbprint is needed up front because the delivery URL is BOUND to it:
    an Exchange issues a URL for the agent that bought the offer, and the edge refuses a
    proof presenting any other key.

    ``tamper_offer`` corrupts the offer signature, and ``serve_directory=False`` makes
    the WBA directory a 404. Both drive the fail-closed paths, and they fail closed for
    DIFFERENT reasons: one is an offer whose signature does not check out, the other an
    exchange whose key never resolved.
    """
    agent_public = Ed25519PrivateKey.from_private_bytes(agent_seed).public_key().public_bytes_raw()
    state = _Exchange(
        agent_thumbprint=thumbprint(agent_public), content=content, tamper_offer=tamper_offer
    )
    state.serve_directory = serve_directory

    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    state.domain = f"127.0.0.1:{server.server_address[1]}"
    state.url = f"http://{state.domain}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def shutdown() -> None:
        server.shutdown()
        server.server_close()

    return FakeExchange(
        domain=state.domain,
        url=state.url,
        content=state.content,
        seen=state.seen,
        _shutdown=shutdown,
    )
