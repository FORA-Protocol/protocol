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
its typed `detail`. `execute` and `fetch` verify a delivery URL's signature, agent binding
and expiry against the issuing Exchange's key directory before handing it back or dialling
it. `createAdminClient` covers the operator RPCs, and `@fora-protocol/sdk/identity` mints an
agent key, its key directory and a signer.

`@fora-protocol/sdk/resolvers` reads and checks the documents a party publishes:
`readManifest`, `readWBADirectory`, `readRevocationList` and `readLicenseDocument` fetch
through the guarded transport, refuse the wrong media type (`MediaTypeRefused`) and a body
the strict contract refuses (`StrictViolation`), and resolve to the parsed model with its
URL, bytes and media type; the license reader also verifies the bytes against
`uri_digest` (`DigestMismatch`). `checkStrict(message, payload)` from
`@fora-protocol/sdk/client` applies the same check to any decoded message.

`@fora-protocol/sdk/discovery-hint` reads the edge discovery headers of a 403:
`parseDiscoveryHint(status, headers)` returns each of `X-Content-Rules` and
`X-FORA-Exchange` with a state of `absent`, `valid` or `malformed`, and
`reconcileDiscoveryHint(hint, listed)` checks the hinted Exchange against the domains the
publisher manifest lists (`listed`, `unlisted` or `no_exchange`; the manifest wins). The
header names are `ContentRulesHeader` and `ExchangeHeader` in `@fora-protocol/sdk/wire`.

Every module is a named subpath export; there is no package root import. The full list is
the `exports` map of the package manifest. Source, tests and the release process are in
[FORA-Protocol/protocol](https://github.com/FORA-Protocol/protocol) under `sdk/ts` and
`gen/ts`. Licensed under Apache-2.0.
