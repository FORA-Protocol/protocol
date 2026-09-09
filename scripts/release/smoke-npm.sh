#!/usr/bin/env bash
# Smoke test for the published TypeScript package.
# Installs one @fora-protocol/sdk tarball (or a registry version) into a fresh
# empty ESM project per supported Zod major, outside the checkout, and in each:
#   - imports one L1 module, the client, the generated schemas and a cross-field
#     schema under plain Node (no TypeScript loader) and parses valid and invalid
#     inputs;
#   - replays the shared wire-canonical vectors through fromWireOffer, so the
#     canonical bytes a consumer signs and verifies are the Go oracle's under
#     BOTH Zod majors (the inversion reads Zod internals, which differ per major);
#   - compiles a strict NodeNext TypeScript consumer against the installed types
#     with skipLibCheck false AND true, including type probes: inferred schema
#     types are not `any`, valid assignments pass, invalid ones fail.
#   - compiles the same consumer at target ES2020 with the default lib (the floor).
# The first Zod project also compiles the consumer once under the TypeScript
# floor the README promises. One extra compile, not a Zod x TypeScript product:
# the two floors do not interact.
#   scripts/release/smoke-npm.sh path/to/fora-protocol-sdk-1.2.3.tgz
#   scripts/release/smoke-npm.sh @fora-protocol/sdk@1.2.3
# ZOD_VERSIONS overrides the matrix (default: the peer-range floor, latest 3, latest 4).
# Every install runs with --ignore-scripts: this runs inside the release build
# before the checksums exist, and a lifecycle script of a resolved dependency
# must not be able to touch the artifact set.
set -euo pipefail
spec=$1
case "$spec" in *.tgz) spec=$(cd "$(dirname "$spec")" && pwd)/$(basename "$spec") ;; esac
here=$(cd "$(dirname "$0")" && pwd)
vectors="$here/../../sdk/go/helpers/testdata/wire-canonical-vectors.json"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Exact pins: the result for one tag must not depend on the day. typescript is the
# version the package is built with (sdk/ts lockfile); ts_floor is the README floor.
typescript=6.0.3
ts_floor=5.7.3
types_node=26.1.0

first=true
for zod in ${ZOD_VERSIONS:-3.23.0 3 4}; do
  proj="$work/zod-$zod"; mkdir -p "$proj"; cd "$proj"
  echo '{ "name": "smoke", "private": true, "type": "module" }' > package.json
  npm install --ignore-scripts --no-audit --no-fund --loglevel=error "$spec" "zod@$zod" "typescript@$typescript" "@types/node@$types_node" >/dev/null
  installed=$(node -p "require('zod/package.json').version")
  echo "== zod $installed"

  cp "$vectors" vectors.json
  cat > check.mjs <<'JS'
import { readFileSync } from "node:fs";
import canonicalize from "canonicalize";
import { thumbprint } from "@fora-protocol/sdk/thumbprint";
import { createClient } from "@fora-protocol/sdk/client";
import { OfferSchema } from "@fora-protocol/sdk/wire/schemas";
import { parseWire } from "@fora-protocol/sdk/wire/base";
import { PricingCrossFieldSchema } from "@fora-protocol/sdk/crossfield";
import { fromWireOffer } from "@fora-protocol/sdk/core/wire-canon";
import { isRegistered } from "@fora-protocol/sdk/vocab/pricingunits";
const tp = await thumbprint(new Uint8Array(32));
if (tp !== "ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0") throw new Error(`thumbprint mismatch: ${tp}`);
if (typeof createClient("https://exchange.example").discover !== "function") throw new Error("client not constructed");
if (!isRegistered("fetches")) throw new Error("vocab missing");
// generated schema: a valid and an invalid input
if (!parseWire(OfferSchema, { exchange: "exchange.example", ext: null }).success) throw new Error("valid Offer rejected");
if (OfferSchema.safeParse({ exchange: 42 }).success) throw new Error("invalid Offer accepted");
// cross-field schema: field-level and cross-field verdicts both reachable
if (!PricingCrossFieldSchema.safeParse({ model: "PRICING_MODEL_FREE" }).success) throw new Error("valid Pricing rejected");
if (PricingCrossFieldSchema.safeParse({ currency: 42 }).success) throw new Error("invalid Pricing accepted");
const crossField = PricingCrossFieldSchema.safeParse({ model: "PRICING_MODEL_PER_UNIT" });
if (crossField.success || !crossField.error.issues.some((i) => i.params?.ruleId)) throw new Error("cross-field rule not applied");
// wire-canonical vectors: the bytes a consumer verifies offer signatures over
const { vectors } = JSON.parse(readFileSync("vectors.json", "utf8"));
if (vectors.length === 0) throw new Error("no wire-canonical vectors");
for (const v of vectors) {
  if (canonicalize(fromWireOffer(v.wire_json)) !== canonicalize(v.canonical_json)) throw new Error(`wire-canonical vector ${v.name} differs from the Go oracle`);
}
console.log(`plain Node import + validation + ${vectors.length} wire-canonical vectors ok`);
JS
  node check.mjs

  cat > consumer.ts <<'TS'
import { thumbprint } from "@fora-protocol/sdk/thumbprint";
import { createClient, type Client } from "@fora-protocol/sdk/client";
import { OfferSchema, PricingSchema } from "@fora-protocol/sdk/wire/schemas";
import { parseWire } from "@fora-protocol/sdk/wire/base";
import { PricingCrossFieldSchema } from "@fora-protocol/sdk/crossfield";
import { isRegistered } from "@fora-protocol/sdk/vocab/pricingunits";
import { createWellKnownEndpointResolver } from "@fora-protocol/sdk/resolvers";
import type { z } from "zod";

export const tp: Promise<string> = thumbprint(new Uint8Array(32));
export const client: Client = createClient("https://exchange.example");
export const registered: boolean = isRegistered("fetches");
export const resolver = createWellKnownEndpointResolver({ fetch, ttlMs: 1000, scheme: "https" });

// ---- type probes: inference must be real, not `any`, for generated AND cross-field schemas
type IsAny<T> = 0 extends 1 & T ? true : false;
type Offer = z.infer<typeof OfferSchema>;
type Pricing = z.infer<typeof PricingSchema>;
type PricingCrossField = z.infer<typeof PricingCrossFieldSchema>;
export const offerNotAny: IsAny<Offer> = false;
export const offerInputNotAny: IsAny<z.input<typeof OfferSchema>> = false;
export const pricingNotAny: IsAny<Pricing> = false;
export const crossFieldNotAny: IsAny<PricingCrossField> = false;
// valid assignments
export const offer: Offer = OfferSchema.parse({ exchange: "exchange.example" });
export const exchange: string = offer.exchange;
export const pricing: PricingCrossField = PricingCrossFieldSchema.parse({ model: "PRICING_MODEL_FREE" });
export const currency: string = pricing.currency;
export const parsed = parseWire<Offer>(OfferSchema, {});
export const parsedExchange: string | undefined = parsed.success ? parsed.data.exchange : undefined;
// invalid assignments must fail
// @ts-expect-error a number is not an Offer
export const badOffer: Offer = 42;
// @ts-expect-error exchange is a string
export const badField: Offer["exchange"] = 42;
// @ts-expect-error a number is not a cross-field Pricing
export const badPricing: PricingCrossField = 42;
// @ts-expect-error currency is a string
export const badCurrency: PricingCrossField["currency"] = 42;
TS
  for skip in false true; do
    cat > tsconfig.json <<JSON
{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "strict": true,
    "noEmit": true, "skipLibCheck": $skip, "types": ["node"], "lib": ["ES2022", "DOM"] },
  "files": ["consumer.ts"] }
JSON
    npx tsc -p tsconfig.json
    echo "TypeScript consumer + type probes compile (skipLibCheck: $skip)"
  done
  # The generated schemas ship as .ts source, so they compile under the consumer's
  # settings. target ES2020 with its DEFAULT lib (no "lib" list) is the floor the
  # README promises; an ES2021+ API in shipped source fails here.
  cat > tsconfig.json <<JSON
{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "strict": true,
    "noEmit": true, "skipLibCheck": false, "types": ["node"], "target": "ES2020" },
  "files": ["consumer.ts"] }
JSON
  npx tsc -p tsconfig.json
  echo "TypeScript consumer compiles at target ES2020 with the default lib"

  if $first; then
    first=false
    npm install --ignore-scripts --no-save --no-audit --no-fund --loglevel=error "typescript@$ts_floor" >/dev/null
    cat > tsconfig.json <<JSON
{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "strict": true,
    "noEmit": true, "skipLibCheck": false, "types": ["node"], "lib": ["ES2022", "DOM"] },
  "files": ["consumer.ts"] }
JSON
    npx tsc -p tsconfig.json
    echo "TypeScript consumer compiles under TypeScript $(npx tsc --version | cut -d' ' -f2) (the floor)"
  fi
done
echo "smoke-npm ok: $spec"
