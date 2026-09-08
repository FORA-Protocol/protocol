# @fora-protocol/sdk

FORA protocol SDK for TypeScript. One package with three layers:

- the generated wire types: Zod schemas (`@fora-protocol/sdk/wire/schemas`), the wire
  parsing policy (`@fora-protocol/sdk/wire/base`) and the registered vocabulary
  (`@fora-protocol/sdk/vocab/*`);
- the IO-free protocol mechanics: thumbprint, signed-URL verification, RFC 9421 request
  signing and verification, offer and acceptance signatures, canonicalization;
- the IO tiers built on them: the key and endpoint resolvers and the Connect-unary JSON
  client.

```sh
npm install @fora-protocol/sdk zod
```

`zod` is a peer dependency. `hono` is an optional peer dependency, needed only for
`@fora-protocol/sdk/hono`. Requires Node 22 or later (the resolvers use `node:dns`).

```ts
import { thumbprint } from "@fora-protocol/sdk/thumbprint";
import { createClient } from "@fora-protocol/sdk/client";
import { parseWire } from "@fora-protocol/sdk/wire/base";
import { OfferSchema } from "@fora-protocol/sdk/wire/schemas";
```

Every module is a named subpath export; there is no package root import. The full list is
the `exports` map of the package manifest. Source, tests and the release process are in
[FORA-Protocol/protocol](https://github.com/FORA-Protocol/protocol) under `sdk/ts` and
`gen/ts`. Licensed under Apache-2.0.
