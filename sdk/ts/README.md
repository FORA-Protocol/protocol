# @fora-protocol/sdk

FORA protocol SDK for TypeScript. One package with three layers:

- the generated wire types: Zod schemas (`@fora-protocol/sdk/wire/schemas`), the wire
  parsing policy (`@fora-protocol/sdk/wire/base`), the registered vocabulary
  (`@fora-protocol/sdk/vocab/*`) and the published JSON Schemas, one file per message
  (`@fora-protocol/sdk/jsonschema/*`);
- the IO-free protocol mechanics: thumbprint, signed-URL verification, RFC 9421 request
  signing and verification, offer and acceptance signatures, canonicalization;
- the IO tiers built on them: the key and endpoint resolvers and the Connect-unary JSON
  client.

```sh
npm install @fora-protocol/sdk zod
```

`zod` is a peer dependency (Zod 3.23 or later, or Zod 4). `hono` is an optional peer
dependency, needed only for `@fora-protocol/sdk/hono`.

Runtime: Node 22 or later (the resolvers use `node:dns`).

TypeScript: 5.7 or later (the declarations use the `Uint8Array<ArrayBuffer>` generic).
The generated schema types ship as `.ts` source and compile under your compiler settings.
They compile with `target` `ES2020` or later and that target's default `lib`; no extra
`lib` entries are needed. The release smoke test checks both floors.

```ts
import { thumbprint } from "@fora-protocol/sdk/thumbprint";
import { createClient } from "@fora-protocol/sdk/client";
import { parseWire } from "@fora-protocol/sdk/wire/base";
import { OfferSchema } from "@fora-protocol/sdk/wire/schemas";
```

The JSON Schemas are JSON files, one per message in a default and a strict variant
(`fora.v1.ResourceResponse.schema.json`, `fora.v1.ResourceResponse.schema.strict.json`).
The strict variant refuses unknown fields. Each file is self-contained, so it compiles on
its own with Ajv, which the package already depends on:

```ts
import Ajv2020 from "ajv/dist/2020.js";
import schema from "@fora-protocol/sdk/jsonschema/fora.v1.ResourceResponse.schema.strict.json" with { type: "json" };

const validate = new Ajv2020({ validateFormats: false }).compile(schema);
```

Strict decoding uses these same files: `createClient(url, { strict: true })` refuses an
answer that carries an unknown field or breaks a cross-field rule, and an error answer
whose Connect envelope or `ErrorDetail` (binary `value` or `debug` projection) the
contract does not define; a refused envelope is `malformed` with `code` kept. A harness that tests
FORA services through the client has three more seams on it: `beforeSign` alters a
request just before it is signed, a `RawBody` passed in place of a verb's request is sent
exactly as given, and `ForaCallError.code` carries the Connect code of a refusal next to
its typed `detail`. `execute` returns each delivery URL as the Exchange issued it, and
`fetch` dials it as given with the agent's proof of possession: the delivery edge verifies
the URL, and its refusal comes back with the edge's `retrieval_auth_failure` reason.
`createAdminClient` covers the operator RPCs, and `@fora-protocol/sdk/identity` mints an
agent key, its key directory, the directory's response signatures
(`signDirectoryResponse`) and a signer.

Requests are signed under the Web Bot Auth profile of RFC 9421
(draft-ietf-webbotauth-httpsig-protocol-00). A signature covers `@method`, `@target-uri`,
`content-digest`, `authorization` and its own `Signature-Agent` member, such as
`sig1="https://agent.example"`, which names the key directory its keyid is resolved in. It
carries `tag="web-bot-auth"`, a 64-byte nonce, and a window of at most five minutes
(`MAX_SIGNATURE_LIFETIME`). A client needs `signatureAgent`, the https origin of its key
directory, to sign: without one, a signed call is refused as `malformed` before anything is
sent. A party that adds its own signature to a request (`appendSignature`, or `appendOnly`
on `createSigningTransport`) appends its member beside the earlier ones, and covers the
earlier signature only when `coverPrevious` is set; a `signerSource` signs each request as
a different identity. `verifyRequestServer` and `verifyMultisigRequestServer` resolve each
signature's key in the directory its own member names and report that directory. A refusal
for a missing component, a missing or wrong tag, a refused `Signature-Agent` form, or a
`Signature-Agent` member that is not an https origin carries the `Accept-Signature` value
(`acceptSignature`) to answer with. The delivery proof `fetch` presents is the same profile
over `@method`, `@target-uri` and the agent's member. `verifyAgentBinding` accepts a proof
that covers at least those three, so a Web Bot Auth library's proof that also covers
`@authority` or a header verifies, and the `@fora-protocol/sdk/hono` middleware answers a
proof it can ask for again with 401 and `Accept-Signature`.

`@fora-protocol/sdk/resolvers` reads and checks the documents a party publishes:
`readManifest`, `readWBADirectory`, `readRevocationList` and `readLicenseDocument` fetch
through the guarded transport, refuse the wrong media type (`MediaTypeRefused`) and a body
the strict contract refuses (`StrictViolation`), and resolve to the parsed model with its
URL, bytes and media type; the license reader also verifies the bytes against
`uri_digest` (`DigestMismatch`). A key directory is fetched with no redirect, must be
served as `application/http-message-signatures-directory+json`, and must carry a response
signature by every key it lists (`DirectoryResponseUnsigned`); the WBA key resolver hands
out only the keys that signed. `checkStrict(message, payload)` from
`@fora-protocol/sdk/client` applies the same check to any decoded message. The strict
schema of every message the SDK reads is compiled when the SDK is built, so the check
generates no code at run time and works where `eval` is refused, as on Cloudflare
Workers. A schema passed to `checkStrict` as its third argument is compiled at run time,
with ajv, so that form needs a runtime that allows code generation.

`@fora-protocol/sdk/resolvers` is the Node entry: its readers and resolvers default their
transport to the SSRF-guarded undici client. An edge runtime (Cloudflare Workers, Fastly
Compute, Deno) imports `@fora-protocol/sdk/resolvers/edge` instead. It exports the same
readers and resolvers, imports nothing Node-only, and has no default transport: each
call takes `fetch`, the runtime's own fetch or a wrapper around it. The read bounds itself
whatever fetch it is given, on both entries: a body over 1 MiB is refused, never
truncated; the whole read ends at 30 seconds; and the read follows redirects itself, at
most five, never out of http(s), never from https down to http and never for a key
directory. The address guard for a host another party named is the caller's:
`blockedAddress` is exported for it, and `allowedScheme`, the scheme allowlist (http and
https) that guard applies, which is not an https-only rule. The protocol mechanics (`core`, `identity`,
`hono`, and the `src` helpers such as `pop` and `verify`) are edge-safe too.
`verifyAgentBinding`, `verifyDirectoryResponse`, `readWBADirectory`, `createWBAKeyResolver`
and `createWBAOfferDirectoryFetch` take `verifyEd25519` for a runtime without WebCrypto
Ed25519, such as Fastly Compute; without it, every listed key of a directory reads as
unsigned there. The package is marked free of side effects, so a bundler keeps only what
a Worker imports: importing one constant from the edge entry carries a few bytes, and a
reader carries its own message's validator and Zod schema.

`@fora-protocol/sdk/discovery-hint` reads the edge discovery headers of a 403:
`parseDiscoveryHint(status, headers)` returns each of `X-Content-Rules` and
`X-FORA-Exchange` with a state of `absent`, `valid` or `malformed`, and
`reconcileDiscoveryHint(hint, listed)` checks the hinted Exchange against the domains the
publisher manifest lists (`listed`, `unlisted` or `no_exchange`; the manifest wins). The
header names are `ContentRulesHeader` and `ExchangeHeader` in `@fora-protocol/sdk/wire`.

`@fora-protocol/sdk/money` holds the metered-offer checks. A `PER_UNIT` offer may carry an
estimate. The purchase charges estimate × rate, or one unit's rate without an estimate,
and the charge is final. `isMeteredOffer(offer)` says whether an offer is metered, and
`checkMeteredEstimate(offer)` throws on a metered offer whose stated estimate is not
positive; the offer `Verifier` rejects such an offer.
An offer's price is `offer.pricing`, and the term it sells carries none:
`checkOfferTermsUnpriced(offer)` throws on a priced term, `signOffer` refuses to sign such
an offer, and the `Verifier` rejects one.

Every module is a named subpath export; there is no package root import. The full list is
the `exports` map of the package manifest. Source, tests and the release process are in
[FORA-Protocol/protocol](https://github.com/FORA-Protocol/protocol) under `sdk/ts` and
`gen/ts`. Licensed under Apache-2.0.
