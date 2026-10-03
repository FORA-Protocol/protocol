// Identity helpers: mint a fresh agent — a key, the WBA directory publishing it, and a
// signer that signs as it — and show a verifier accepts it.
//
// The verifier side is the SDK's own: the WBA resolver reads the directory from the origin
// the covered Signature-Agent names (served here through its injected fetch), and
// verifyRequestServer checks the request against the key it resolved.
import { describe, expect, it } from "vitest";

import { createClient, type UnarySend } from "../client/index.ts";
import {
	DEFAULT_KEY_VALIDITY_MS,
	directoryDocument,
	generateKey,
	signingTransportFor,
} from "../core/identity.ts";
import type { OutboundInit } from "../core/signing-transport.ts";
import { type VerifyRequestHeaders, verifyRequestServer } from "../core/verify-request.ts";
import { parseWire } from "../../../gen/ts/wire/base.ts";
import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { createWBAKeyResolver } from "../resolvers/index.ts";
import { WBA_DIRECTORY_PATH } from "../resolvers/wba.ts";

const DIRECTORY = "https://agent.example";

/** A verifier that resolves the caller's key from the directory its request names. */
async function verifies(
	documents: Record<string, unknown>,
	req: { url: string; body: Uint8Array<ArrayBuffer>; headers: Record<string, string> },
): Promise<boolean> {
	const resolver = createWBAKeyResolver({
		fetch: async (url) => {
			const doc = documents[url];
			return { status: doc === undefined ? 404 : 200, text: async () => JSON.stringify(doc ?? {}) };
		},
	});
	const headers: Record<string, string> = {};
	for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
	const keyid = /keyid="([^"]+)"/.exec(headers["signature-input"] ?? "")?.[1] ?? "";
	const key = await resolver.resolve(keyid, headers["signature-agent"] ?? "");
	const verdict = await verifyRequestServer({
		method: "POST",
		url: req.url,
		body: req.body,
		headers: headers as VerifyRequestHeaders,
		resolve: { resolve: (k) => (k === keyid && key !== undefined ? new Uint8Array(key) : undefined) },
		now: () => Math.floor(Date.now() / 1000),
	});
	return verdict.valid;
}

describe("identity helpers", () => {
	it("mint a fresh agent whose signed request a directory-resolving verifier accepts", async () => {
		const { keyPair, thumbprint: keyid } = await generateKey();
		const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
		expect(keyid).toBe(await thumbprint(raw));

		const document = await directoryDocument([keyPair.publicKey]);
		const documents = { [`${DIRECTORY}${WBA_DIRECTORY_PATH}`]: document };

		const sent: { url: string; init: OutboundInit }[] = [];
		const signing = await signingTransportFor(keyPair, DIRECTORY, async (url: string, init: OutboundInit) => {
			sent.push({ url, init });
		});
		const url = "https://exchange.example/fora.v1.ExchangeService/GetAccountStatus";
		const body = new TextEncoder().encode('{"exchange":"exchange.example"}') as Uint8Array<ArrayBuffer>;
		await signing(url, { method: "POST", body });

		const out = sent[0];
		if (out === undefined) throw new Error("nothing was sent");
		expect(out.init.headers?.["signature-agent"]).toBe(DIRECTORY);
		expect(out.init.headers?.["signature-input"]).toContain(`keyid="${keyid}"`);
		expect(await verifies(documents, { url, body, headers: out.init.headers ?? {} })).toBe(true);

		// A directory that does not publish the key: the same request no longer verifies.
		const stranger = await generateKey();
		const otherDocs = { [`${DIRECTORY}${WBA_DIRECTORY_PATH}`]: await directoryDocument([stranger.keyPair.publicKey]) };
		expect(await verifies(otherDocs, { url, body, headers: out.init.headers ?? {} })).toBe(false);
	});

	it("drive the client as the minted agent", async () => {
		const { keyPair, thumbprint: keyid } = await generateKey();
		const documents = { [`${DIRECTORY}${WBA_DIRECTORY_PATH}`]: await directoryDocument([keyPair.publicKey]) };
		const accepted: boolean[] = [];
		const send: UnarySend = async (req) => {
			accepted.push(await verifies(documents, req));
			return { status: 200, body: JSON.stringify({ ver: "1.0" }) };
		};
		const client = createClient("https://exchange.example", {
			signer: { privKey: keyPair.privateKey, keyid },
			signatureAgent: DIRECTORY,
			agentPublicKey: keyPair.publicKey,
			guardedSend: send,
			endpointResolver: { resolveEndpoint: async (host) => `https://${host}` },
		});
		await client.getAccountStatus({ exchange: "exchange.example" });
		expect(accepted).toEqual([true]);
	});

	it("build the directory document the WBA schema describes", async () => {
		const a = await generateKey();
		const b = await generateKey();
		const now = new Date("2026-01-01T00:00:00Z");
		const doc = await directoryDocument([a.keyPair.publicKey, b.keyPair.publicKey], { now });
		expect(parseWire(WBAFileSchema, doc).success).toBe(true);
		expect(doc.keys).toHaveLength(2);
		const first = doc.keys?.[0];
		expect(first).toMatchObject({ kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig" });
		expect(first?.not_before).toBe("2025-12-31T23:55:00.000Z");
		expect(first?.not_after).toBe(new Date(now.getTime() + DEFAULT_KEY_VALIDITY_MS).toISOString());
		expect(doc).not.toHaveProperty("revocation_url");
		const short = await directoryDocument([a.keyPair.publicKey], { now, validForMs: 60_000 });
		expect(short.keys?.[0]?.not_after).toBe("2026-01-01T00:01:00.000Z");
	});
});
