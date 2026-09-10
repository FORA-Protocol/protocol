# FORA

Open transaction protocol for licensed AI content access.

Built on [IAB Tech Lab CoMP V1](https://github.com/IABTechLab/CoMP/blob/880238e0100b3d0d67d5afd7357a18fc21a97be5/CoMP-1.0.md) and [RSL 1.0](https://rslstandard.org/rsl); extends both with discovery, transaction execution, and settlement infrastructure so an autonomous agent can negotiate access to a publisher's content under that publisher's licensing terms, pay through an exchange, and produce a cryptographically auditable record of the transaction.

📖 **Spec & docs:** [fora-protocol.org](https://fora-protocol.org) — start with the [proto reference](https://fora-protocol.org/reference/proto-fora/) · 🧩 **Reference implementation:** [FORA-Protocol/reference-implementation](https://github.com/FORA-Protocol/reference-implementation)

Maintainers: see [RELEASING.md](RELEASING.md) for the version, tag, registry, and
recovery procedure.

> **The wire format is stable.** `fora.v1` is released and installed from public
> registries, so it is no longer ours to change freely. Within v1 the proto is
> **additive only**: fields and enum values may be added, nothing already shipped
> is renamed, renumbered, retyped or removed. A change that cannot be made
> additively belongs in a new proto package, not in a minor release. This is
> enforced rather than promised — `buf breaking` gates every build against the
> `v1.0.0` tag, so a break fails CI on the pull request that introduces it.
>
> The generated types and the SDKs version together off a single `v*` tag: the Go
> module, `@fora-protocol/sdk` on npm, and `fora-protocol` plus
> `fora-protocol-sdk` on PyPI all carry the same version, and the release workflow
> refuses a tag that disagrees with any manifest. Their public API surface is held
> by the [SDK parity matrix](docs/sdk-parity-matrix.md) and its shrink-only
> allowlist rather than by an automated breaking-change check, so treat the wire
> guarantee above as the stronger of the two. See [RELEASING.md](RELEASING.md) for
> the procedure, and [`docs/design-history.md`](docs/design-history.md) for the
> rationale behind the major design decisions.

## Standards and versions

What FORA builds on, and exactly how much of each it uses. Both upstreams are on their
first release; neither has published a successor.

| Standard | Version we use | How FORA uses it |
|---|---|---|
| **IAB Tech Lab CoMP** | **V1**, finalized 2026-04-28. Pinned to the immutable blob [`880238e…/CoMP-1.0.md`](https://github.com/IABTechLab/CoMP/blob/880238e0100b3d0d67d5afd7357a18fc21a97be5/CoMP-1.0.md) — the `1.0-202604` release tag does not carry the spec | 1:1 mapping in [`proto/comp/v1/comp.proto`](proto/comp/v1/comp.proto), field names, enum values and semantics preserved. Surfaced to agents as the `fora-comp-v1` extension profile |
| **RSL** | **1.0** (`RSL-SPEC-1.0`, Recommendation, published 2025-12-10), namespace [`rslstandard.org/rsl`](https://rslstandard.org/rsl) | Vocabulary source, not a parsed format: RSL's AI-use terms seed FORA's `FUNCTION` restriction tokens, and `INGESTION_SOURCE_RSL` names it as a catalog source. FORA neither defines nor parses RSL documents |
| **FORA wire** | **1.0** — the `ver` field, proto packages `fora.v1`, `fora.admin.v1`, `comp.v1` | This repository |
| **Connect** | protocol version **1** | The RPC binding the SDKs speak |
| **JSON Schema** | draft **2020-12** | The dialect an Exchange's published `registration_data` schema must use |

`fora-comp-v1` is a **FORA profile version and not CoMP's**. The two are deliberately
decoupled, so the profile id stays `fora-comp-v1` for as long as it tracks CoMP V1 —
there is no `fora-comp-v2` to rename it to.

The signature and canonicalization standards carry no version of their own; they are
listed with their canonical links on the
[References page](https://fora-protocol.org/reference/standards/).

## What's in this repo

```
proto/          Protocol buffer source — the wire format
  fora/v1/      FORA messages and services
  fora/admin/v1/  AdminService — the Exchange operator/config plane
  comp/v1/      IAB CoMP V1 (1:1 mapping; included for reference)
  buf.yaml      Buf module config

gen/          Generated wire types (L0) — never hand-edited
  go/         Go types + Connect-Go client/server (native protobuf)
  ts/         TypeScript Zod schemas + vocab constants
  python/     Pydantic v2 models + vocab constants

sdk/          Protocol SDK (L1/L2) — hand-written behavioral libraries, one per language
  go/         helpers · resolvers · core · connect · connectserver
  python/     fora_sdk
  ts/         src · resolvers · core · hono
  parity/     symbol-map.json — the cross-language API-surface parity source

cmd/          Build tooling (Go) — protoc-gen-foravocab (vocabulary codegen plugin)
website/      Documentation site (Astro Starlight)
amplify.yml   AWS Amplify build configuration for the website
```

## Reference implementation

A working multi-language stack — Exchange (Go), Broker (Go), Identity with the MCP adapter (Go), and Edge (TypeScript) — lives at [`FORA-Protocol/reference-implementation`](https://github.com/FORA-Protocol/reference-implementation). It implements the protocol end-to-end, and its docker-compose suite drives the whole stack — three Exchanges, a Broker, and the edge worker on all three runtimes — on one machine.

## Wire types (generated)

All three languages are generated from `proto/`: Go is native protobuf + Connect via
`buf generate` (it is the server/runtime); the Python and TypeScript **types exports**
— Pydantic models and Zod schemas — are generated from the same proto via JSON Schema
by `scripts/gen-sdk-types.sh` (their consumers — the TypeScript edge worker and the
Python SDK and e2e harness — cannot use protobuf natively). All three carry **registered
vocabulary constants** per axis (`pricingunits`, `quotametrics`, `functiontokens`,
`geographytokens`, `usertypes`) so consumers use typed constants and an
`IsRegistered`/`isRegistered`/`is_registered` membership check instead of magic
strings. The vocab is emitted from the single `(fora.v1.vocab)` source in one pass, so
the three languages cannot drift from each other.

### Go

```go
import (
    forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
    "github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
    "github.com/FORA-Protocol/protocol/gen/go/vocab/pricingunits"
)
```

### TypeScript

Zod schemas for every message are generated under [`gen/ts/wire/schemas.ts`](gen/ts/wire/schemas.ts) (validated message types; the edge worker uses them for request validation), with vocabulary constants under [`gen/ts/vocab/`](gen/ts/vocab); the [reference implementation](https://github.com/FORA-Protocol/reference-implementation) shows them in use.

```typescript
import { OfferSchema } from "@fora-protocol/sdk/wire/schemas";
import { pricingunits } from "@fora-protocol/sdk/vocab/pricingunits";
```

### Python

Pydantic v2 models for every message (extending the hand-written `wire.base.WireModel` seam) plus vocabulary constants are generated under [`gen/python/`](gen/python) (`pip install .` from that directory; see its [README](gen/python/README.md)).

```python
from wire.models import Offer, Pricing
from vocab import pricingunits
```

## Protocol SDK

Beyond the generated wire types, the repo ships a hand-written **protocol SDK** in all
three languages under [`sdk/`](sdk) — the behavioral layer an agent, broker, exchange,
or edge verifier builds on: RFC 9421 request signing/verification, offer & acceptance
signatures, signed-URL delivery + proof-of-possession, key/endpoint resolution,
window-active key selection, an SSRF-guarded fetch client, and typed `ErrorDetail`s.
[`sdk/go/README.md`](sdk/go/README.md) and [`sdk/python/README.md`](sdk/python/README.md)
walk their tiers face by face; the Python one carries a complete worked agent whose code
is extracted and executed by that package's test suite, so it cannot drift from the
release. TypeScript has no README of its own yet — its surface is the parity matrix and
the source.

The SDK is **layered the same way in every language** — full detail in
[`sdk/go/README.md`](sdk/go/README.md):

| Layer | What it is | Go | Python | TypeScript |
|---|---|---|---|---|
| **L0** | generated wire types (consumed, never rebuilt) | `gen/go/…` | `wire.models` | `wire/schemas` |
| **L1** | stateless, **IO-free** trust core — crypto sign/verify, canonicalization, money, scopes, thumbprint, the license-term pre-check | `sdk/go/helpers` | `fora_sdk` (`httpsig`, `signedurl`, `pop`, `money`, `licenseterm`, …) | `sdk/ts/src` |
| **L2 · I/O** | the only tier that dials the network — key/endpoint/offer-key resolvers behind one SSRF-guarded client | `sdk/go/resolvers` | `fora_sdk.resolvers` | `sdk/ts/resolvers` |
| **L2 · transport** | transport-neutral composition + Connect bindings; the agent, broker and catalog clients | `sdk/go/core` · `connect` · `connectserver` | `fora_sdk.core` · `server_verify` · `fora_sdk.client` (+ `sync`) | `sdk/ts/core` · `hono` · `sdk/ts/client` |

The SDK is scored by integration role — edge, agent, account setup, publisher, exchange operator — and the agent, account-setup and publisher roles ship in all three languages: the agent verbs (`discover` / `resolve` / `execute` / `reportUsage` / `dispute` / `fetch`), the account-setup verbs (`register` / `getAccountStatus`) with the fresh-manifest read of an Exchange's registration requirements, and the publisher verbs (`pushResources` / `removeResources` / `refreshCatalog`) plus the two-tier entry pre-check. Go is the reference/oracle; Python and TypeScript mirror it face-for-face. The exact
public surface per language — every symbol and its cross-language counterpart, the
documented divergences, and the conformance-vector replay coverage — is tracked in the
**generated, CI-drift-gated** [SDK parity matrix](docs/sdk-parity-matrix.md). The
design rationale (why the trust core is dependency-free, the SSRF transport model,
naming conventions) is recorded in [`docs/design-history.md`](docs/design-history.md).

> The SDK is installed from a registry, not pinned off a commit: `go get
> github.com/FORA-Protocol/protocol`, `npm install @fora-protocol/sdk`, `pip install
> fora-protocol-sdk`. The Python SDK depends on the generated types as a separate
> distribution (`fora-protocol`) pinned to its own version; Go and TypeScript ship
> theirs inside the one package. A consumer that installs from git still works — the
> root export map resolves for a commit pin — but a release is the supported path.

## License

Code (everything under `proto/`, `gen/`, and `cmd/`) is licensed under the [Apache License 2.0](LICENSE). Documentation (the website source under `website/` and the rendered spec) is licensed under [Creative Commons Attribution-NoDerivatives 4.0 International (CC BY-ND 4.0)](https://creativecommons.org/licenses/by-nd/4.0/) — that license is declared in the website footer.
