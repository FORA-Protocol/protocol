# fora-protocol-sdk

FORA protocol libraries for Python, co-located with the contract (ADR-020). One
distribution, the `fora_sdk` package, layered so that the parts holding no keys and doing
no I/O can be used on their own.

| Layer | Module | What it is |
|---|---|---|
| **L0** | `wire.models`, `vocab.*` | generated wire types, from the separate `fora-protocol` distribution (consumed, never rebuilt) |
| **L1** | **`fora_sdk`** (top level) | stateless, **IO-free** protocol mechanics — RFC 9421/7638 crypto, offer and acceptance signatures, signed URLs, validation. Byte-parity-guarded against the `sdk/go` oracle |
| L2 · I/O | **`fora_sdk.resolvers`** | the only tier that dials the network: Web Bot Auth directories, well-known JWKS and `fora.json`, plus the SSRF-guarded HTTP client every one of them runs on |
| L2 · transport | `fora_sdk.core` (transport-neutral: `Verifier`, `VerifiedOffer`, `DiscoveryResult`, `Window`) · `fora_sdk.client` (the async Connect-unary JSON client: the agent verbs **`discover` · `execute` · `report_usage` · `dispute` · `fetch`**, the account-setup verbs **`register` · `get_account_status`**, the broker verb **`resolve`** and the publisher verbs **`push_resources` · `remove_resources` · `refresh_catalog`**) · `fora_sdk.sync` (the same faces, blocking) · `fora_sdk.server_verify` (the server side of RFC 9421) | state is injected, never owned |

```sh
pip install fora-protocol-sdk
```

Python 3.11 or later. The package ships `py.typed`, so mypy reads its annotations.

`httpx` and `httpcore` are installed with every consumer, including one that uses only
the IO-free mechanics: keeping them non-optional is what makes their version ceilings,
which guard the resolvers' SSRF seam, bind every install.

The generated wire types are a separate distribution, `fora-protocol`: Pydantic v2 models
at `wire.models` and the registered vocabulary at `vocab.*`. This package pins it to its
own version and installs it as a dependency. It owns the top-level import names `wire` and
`vocab`, so it can collide with another distribution that owns either name; install it
into an environment that does not. Its README explains the tradeoff.

---

## A complete agent

Everything below is one working client: identity from a seed, offers verified against
keys fetched from the issuing Exchange, a purchase, a bound fetch, and a usage report.
The rest of this document explains the pieces it composes.

<!-- fora:agent-example — executed verbatim by sdk/python/tests/test_readme_agent_example.py -->
```python
import asyncio
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from fora_sdk.core import Mode, StaticOfferKeyResolver, Verifier
from fora_sdk.resolvers import (
    CachedOfferKeyResolver,
    WellKnownEndpointResolver,
    create_wba_offer_directory_fetch,
)
from fora_sdk.signing_transport import SigningTransport
from fora_sdk.sync import Client, ClientConfig
from fora_sdk.thumbprint import thumbprint

# This agent's identity, as it states it to an Exchange.
AGENT = {"id": "agent-1", "domain": "agent.example", "type": "REQUESTER_TYPE_AGENT"}

# https in production. A local sandbox serving plaintext sets FORA_WELLKNOWN_SCHEME=http,
# and ALLOW_INSECURE=true for the guarded transports.
SCHEME = os.environ.get("FORA_WELLKNOWN_SCHEME", "https")


def buy_and_fetch(*, exchange: str, uri: str, seed: bytes) -> bytes:
    """Discover an offer for `uri`, buy it, fetch the bytes, and report the usage."""
    # 1. Identity. The RFC 9421 keyid IS the RFC 7638 thumbprint of the agent's public
    #    key, which is also the value a delivery URL gets bound to. One key, one name.
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    signer = SigningTransport(signer_seed=seed, keyid=thumbprint(public))

    # 2. Where this Exchange serves its API, read from its own /.well-known/fora.json
    #    rather than from configuration. The same resolver later routes the usage report
    #    back to whichever Exchange issued the offer.
    endpoints = WellKnownEndpointResolver(scheme=SCHEME)

    # 3. Offer-signing keys, from the Exchange's Web Bot Auth directory — the only place
    #    they are published. Fetched, revocation-screened and TTL-cached, then frozen
    #    into the map the (synchronous) Verifier resolves against. STRICT plus a map that
    #    resolves nothing rejects every offer: that is the fail-closed posture, not a bug.
    directory = CachedOfferKeyResolver(fetch=create_wba_offer_directory_fetch(scheme=SCHEME))
    keys = asyncio.run(directory.prefetch([exchange]))
    verifier = Verifier(
        mode=Mode.STRICT,
        resolver=StaticOfferKeyResolver(keys),
        now=lambda: int(time.time()),
    )

    config = ClientConfig(
        base_url=endpoints.resolve_endpoint(exchange),
        signer=signer,
        requester=AGENT,
        verifier=verifier,
        endpoint_resolver=endpoints,
    )

    with Client(config) as client:
        # 4. Discover. Every offer arrives already sorted into verified or rejected, and
        #    a rejected one keeps its reason instead of being dropped silently.
        found = client.discover({"exchange": exchange, "uris": [uri]})
        offers = found.verified()
        if not offers:
            refused = [r.reason for group in found.groups for r in group.result.rejected]
            raise RuntimeError(f"no verifiable offer for {uri}: {refused}")

        # 5. Buy it. execute() accepts only a verified offer, so an unverified one
        #    cannot be paid for by mistake.
        item = client.execute(offers[0]).items[0]

        # 6. Fetch. The delivery URL is bound to the agent's thumbprint and the client
        #    presents the matching proof of possession, so a copied link fetches nothing.
        content = client.fetch(item.retrieval_endpoint)

        # 7. Report what was used. It goes to the Exchange the offer named, resolved the
        #    same way as step 2 — never to whatever base_url happened to be configured.
        client.report_usage(
            {
                "exchange": exchange,
                "transaction_id": item.transaction_id,
                "billing_id": item.billing_id,
                "usage": {"consumed_quantity": len(content.body), "function": ["ai-input"]},
            }
        )

    return content.body


if __name__ == "__main__":
    sys.stdout.buffer.write(
        buy_and_fetch(
            exchange=os.environ["FORA_EXCHANGE"],  # a bare domain, e.g. "exchange.example"
            uri=sys.argv[1],
            seed=bytes.fromhex(os.environ["FORA_AGENT_SEED"]),
        )
    )
```

`fora_sdk.client.Client` is the same surface with `await`; nothing else changes. That one
is the core, and `fora_sdk.sync` is a blocking facade over a synchronous httpx client
rather than an `asyncio.run` wrapper, which would break inside a running event loop.

That example is not decoration: a test extracts this exact block from this file, runs it
against an in-process Exchange, and fails if any name in it stops resolving.

---

## L1 — the protocol mechanics

Stateless, **no network I/O**, no secret custody, no state. The same code the Broker,
Exchange, MCP adapter and edge worker build on.

```python
from fora_sdk import thumbprint, sign_request, verify_request
```

**RFC 9421 request signing and verification.** `sign_request` covers the exact body
bytes; `verify_request` checks a received one against a key you hold, and
`fora_sdk.server_verify.verify_request_server` is the framework-agnostic server face,
including the multi-signature relay chain:

```python
signed = sign_request(method="POST", url=url, body=body, seed=seed, keyid=keyid)
verdict = verify_request_server(
    method="POST", url=url, body=body, headers=headers,
    resolver=resolver, replay=replay_store, now=lambda: int(time.time()),
)
```

**Offer authenticity.** The signature covers the offer's pricing, terms and expiry, so an
offer must be verified before anything selects on it. That is what `fora_sdk.core.Verifier`
does in bulk, and `sign_offer_jcs` / `verify_offer_acceptance_jcs` are the primitives
underneath it. Canonicalization is RFC 8785 JCS through a vetted library, never
hand-rolled.

**Signed delivery URLs and proof of possession.** Byte-identical with the edge worker:

```python
url = sign_ed25519_signed_url(raw_url, seed=seed, kid="ex.v1", agent_id=tp, exp=exp)
verdict = verify_ed25519_signed_url(url, now=now, resolve_key=resolve)
proof = verify_agent_binding(method="GET", url=url, headers=headers,
                             agent_id=verdict.agent_id, now=now)
```

The covered set for the proof is exactly `@method` + `@target-uri`: a GET has no body to
digest, and the signed URL is itself the credential.

**License-term pre-check.** The two tiers an Exchange applies to a pushed catalog entry,
runnable by a publisher before signing — the wire rules over the entry as given, then
canonicalization and registry membership over a copy of its terms:

```python
verdict = validate_resource_entry(entry)   # never modifies entry
normalize_resource_entry(entry)            # the form the Exchange stores
```

**Money.** Exact decimal in and out, canonical decimal string on the wire:
`parse_money`, `format_money`, `canonicalize_money`. Never floats.

**Registration schema.** An Exchange may publish a JSON Schema for the
`registration_data` it expects. Both ends validate against it, so the rules live in one
place: 2020-12 only, same-document `$ref` only, size, depth and evaluation caps, and a
`pattern` alphabet all three SDK languages express identically.

```python
schema, verdict = compile_registration_schema(raw)
```

**Do not discard that verdict.** The two callers read a non-accepted one differently, and
getting it backwards is the easy mistake. A *client* pre-checking a payload skips the
check and sends anyway, because the Exchange's enforcement decides and a local check that
could not run must not veto your own user. An *Exchange* compiling its own configured
schema treats anything but accepted or not-published as a misconfigured deployment, and
must not advertise a schema it is not enforcing.

**Routing and audience.** `is_bare_host` and `host_anchored` are the pure checks that
precede a signed call to an address a network party named. `check_audience` is the other
direction: a request arrived, does it name *this* Exchange? The signature does not answer
that — it proves the sender signed the URL it dialled, and that URL came out of a fetched
manifest, so a poisoned resolution redirects the request while every signature still
verifies.

**Also:** `errordetail` (the typed error taxonomy and its constructors),
`generate_idempotency_key`, `apply_scopes`, `hash_url`, `monotonic_window`, and
`redact_url` — a signed URL carries its credential in the query, so never log one raw.

---

## L2 · I/O — `fora_sdk.resolvers`

The network-fetching tier. Everything that dials a host a third party can influence lives
here, behind one SSRF-guarded HTTP client, so the pre-auth-reachable network surface never
enters the pure core.

- **Key resolvers** — `WellKnownKeyResolver` (well-known JWKS, TTL-cached) and
  `WBAKeyResolver` (Web Bot Auth directory, revocation- and expiry-aware, with a
  background poller).
- **Endpoint resolver** — `WellKnownEndpointResolver` discovers an Exchange's own service
  endpoint from `/.well-known/fora.json`, host-keyed and cached. Its exits are worth
  knowing apart, because the difference decides whether a caller should retry:
  `ManifestVersionRefusedError` when the document carries a `ver` this reader does not
  accept or none at all, `NoEndpointError` when it advertises none, and
  `EndpointRefusedError` when it advertises one this resolver will not hand back. All
  three are verdicts and therefore final; anything else is a transport failure and worth
  retrying.
- **Offer keys** — `CachedOfferKeyResolver` caches an Exchange's offer-signing key with an
  expiry clamped to the key's own `not_after`, and `create_wba_offer_directory_fetch` is
  the fetch it runs on. `active_ed25519_key_screened` and its siblings are the underlying
  window-and-revocation selection.
- **Registration requirements** — `WellKnownRequirementsReader` reads what one Exchange
  asks of a registration from the same manifest, and holds no document cache: the contract
  requires the terms digest to come from a freshly fetched document.
- **The guarded client** — `guarded_client` and `guarded_async_client` are the one
  construction path a third-party-influenceable fetch uses. `ssrf_guard` and
  `async_ssrf_guard` are the transports underneath, for a caller wiring its own.

**Which default a resolver takes follows its URL's provenance, and that is the whole
rule.** A fixed, operator-chosen address — an on-premise JWKS — may legitimately be
private, and the operator rather than an attacker chose it. A request-derived host — the
directory named by a `Signature-Agent` header, an Exchange domain read off an offer —
takes the guarded client, because the party choosing the address is not the party running
the process.

**Redirects: the guarded client follows, a signed leg refuses.** Following a bounded chain
is right for a public well-known document, where the address is re-pinned and the scheme
re-vetted at every hop. It is wrong for anything carrying a credential, so the content
fetch and the RPC legs install their own refusal: following a redirect either replays a
proof bound to the old URL, or hands a fresh proof of possession of the agent's key to
whatever host the first hop named.

Two orthogonal environment flags drive the guard, both defaulting to the guarded posture:
`SKIP_SSRF` drops the dial-time address check, and `ALLOW_INSECURE` permits plaintext
http. The transport caps redirect depth, bounds well-known bodies at 1 MiB, and fails
closed if **any** resolved address of a host is reserved.

---

## L2 · transport — `fora_sdk.client` and `fora_sdk.sync`

`ClientConfig` is the whole of a client's wiring, and three of its fields are things the
client refuses to guess:

- **`signer`** — a `SigningTransport` over the agent's own key. The SDK holds one agent
  key: the one the request is signed with.
- **`verifier`** — fail-closed by default. An unconfigured client gets a verifier over a
  resolver that resolves nothing, so it rejects **every** offer, with a reason. That is
  the correct default and on a first run it looks exactly like a broken stack.
- **`endpoint_resolver`** — turns the exchange domain inside a signed offer into the
  origin that Exchange advertises for itself. A usage report goes where the signed offer
  says, never where configuration says, so this is not an optional convenience.

The rest are bounds and seams with working defaults: `call_timeout_sec`,
`max_rpc_read_bytes`, `content_timeout_sec`, `max_content_bytes`, `sign_window`,
`proof_window`, `request_id`, `validation`, `registration_requirements`.

Failures arrive as one `CallError` carrying a `CallErrorKind` — `NOT_SENT`, `REFUSED`,
`UNREACHABLE`, `MALFORMED`, `TOO_LARGE`, `NOT_SIGNABLE`, `UNKNOWN` — plus the peer's own
reason token and, when the peer sent one, a typed `ErrorDetail`. One failure type for
every verb, so a caller branches in one place.

`BrokerClient` carries `resolve` for brokered discovery, and `CatalogClient` carries the
publisher verbs. Both take the same `ClientConfig`, because a publisher addresses a
different endpoint with a different key.

---

## Guarantees

- **Byte-parity with Go.** Thumbprints, RFC 9421 signature bases, acceptance payload
  bytes, delivery-proof values and money formatting are byte-for-byte identical to the
  `sdk/go` oracle. If those bytes differ, signatures do not verify and nothing works. Go
  emits the vectors; this package's parity suites replay them.
- **The public surface is gated.** Every public Go symbol is either mapped to its Python
  and TypeScript counterparts or recorded as a deliberate divergence with a reason, and
  the allowlist may only shrink.
- **Fail-closed by default.** An unresolvable Exchange is absent rather than trusted, an
  unverified offer is rejected rather than dropped, and a directory fetch that fails
  returns nothing rather than an empty document.
- **Library-first.** JCS canonicalization, JSON Schema evaluation, the HTTP client and the
  cryptography are vetted libraries. The SDK owns the protocol, not the primitives.

Source, tests and the release process are in
[FORA-Protocol/protocol](https://github.com/FORA-Protocol/protocol) under `sdk/python` and
`gen/python`. Licensed under Apache-2.0.
