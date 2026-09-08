#!/usr/bin/env bash
# Smoke test for the published TypeScript package (FORA-291).
# Installs @fora-protocol/sdk from a packed tarball or from the npm registry into
# an empty project outside the checkout, imports one L1 module and one client
# module under plain Node (no TypeScript loader), and compiles a small
# TypeScript consumer against the installed types.
#   scripts/release/smoke-npm.sh path/to/fora-protocol-sdk-1.2.3.tgz
#   scripts/release/smoke-npm.sh @fora-protocol/sdk@1.2.3
set -euo pipefail
spec=$1
case "$spec" in *.tgz) spec=$(cd "$(dirname "$spec")" && pwd)/$(basename "$spec") ;; esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
npm init -y >/dev/null
npm install --no-audit --no-fund --loglevel=error "$spec" zod@3 typescript @types/node >/dev/null

cat > check.mjs <<'JS'
import { thumbprint } from "@fora-protocol/sdk/thumbprint";
import { createClient } from "@fora-protocol/sdk/client";
import { OfferSchema } from "@fora-protocol/sdk/wire/schemas";
import { isRegistered } from "@fora-protocol/sdk/vocab/pricingunits";
const tp = await thumbprint(new Uint8Array(32));
if (tp !== "ogRZbCR5KTrPFCAfuYmCMwj0w7Yuk3Lr6YWQWfpkbf0") throw new Error(`thumbprint mismatch: ${tp}`);
const client = createClient("https://exchange.example");
if (typeof client.discover !== "function") throw new Error("client not constructed");
if (OfferSchema.safeParse({}).success !== false) throw new Error("schema did not validate");
if (isRegistered("fetches") !== true) throw new Error("vocab missing");
console.log("plain Node import ok");
JS
node check.mjs

cat > consumer.ts <<'TS'
import { thumbprint } from "@fora-protocol/sdk/thumbprint";
import { createClient, type Client } from "@fora-protocol/sdk/client";
import { OfferSchema } from "@fora-protocol/sdk/wire/schemas";
import { parseWire } from "@fora-protocol/sdk/wire/base";
import { isRegistered } from "@fora-protocol/sdk/vocab/pricingunits";
import { createWellKnownEndpointResolver } from "@fora-protocol/sdk/resolvers";
export const tp: Promise<string> = thumbprint(new Uint8Array(32));
export const client: Client = createClient("https://exchange.example");
export const parsed = parseWire(OfferSchema, {});
export const registered: boolean = isRegistered("fetches");
export const resolver = createWellKnownEndpointResolver({ fetch, ttlMs: 1000, scheme: "https" });
TS
cat > tsconfig.json <<'JSON'
{ "compilerOptions": { "module": "NodeNext", "moduleResolution": "NodeNext", "strict": true,
    "noEmit": true, "skipLibCheck": false, "types": ["node"], "lib": ["ES2022", "DOM"] },
  "files": ["consumer.ts"] }
JSON
npx tsc -p tsconfig.json
echo "TypeScript consumer compiles"
echo "smoke-npm ok: $spec"
