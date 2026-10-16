// Identity helpers: mint a fresh agent — a key, the WBA directory publishing it, the
// response signatures that directory is served with, and a signer that signs as it — and
// show a verifier accepts it.
//
// The verifier side is the SDK's own: verifyRequestServer resolves each signature's key
// through the WBA resolver, in the directory the signature's covered Signature-Agent
// member names (served here through the resolver's injected fetch, signed by the keys it
// lists and under the profile's media type).
import { describe, expect, it } from "vitest";

import { createClient, type UnarySend } from "../client/index.ts";
import {
	DEFAULT_KEY_VALIDITY_MS,
	directoryDocument,
	generateKey,
	signDirectoryResponse,
	signingTransportFor,
	verifyDirectoryResponse,
	type WBAFile,
} from "../core/identity.ts";
import type { OutboundInit } from "../core/signing-transport.ts";
import { type VerifyRequestHeaders, verifyRequestServer } from "../core/verify-request.ts";
import { parseWire } from "../../../gen/ts/wire/base.ts";
import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { decodeBase64Url } from "../src/base64url.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { createWBAKeyResolver, type FetchLike, WBA_DIRECTORY_MEDIA_TYPE } from "../resolvers/index.ts";
import { WBA_DIRECTORY_PATH } from "../resolvers/wba.ts";

const DIRECTORY = "https://agent.example";
const DIRECTORY_URL = `${DIRECTORY}${WBA_DIRECTORY_PATH}`;
const created = () => Math.floor(Date.now() / 1000) - 60;

/** One served directory: the document, signed by `signers` for the directory's host. */
async function served(
	doc: WBAFile,
	signers: Array<{ privKey: CryptoKey; keyid: string }>,
): Promise<{ body: string; headers: Record<string, string> }> {
	const body = JSON.stringify(doc);
	const sig = await signDirectoryResponse(
		new URL(DIRECTORY).host,
		new TextEncoder().encode(body) as Uint8Array<ArrayBuffer>,
		signers,
		created(),
		created() + 3600,
	);
	return {
		body,
		headers: {
			"content-type": WBA_DIRECTORY_MEDIA_TYPE,
			"content-digest": sig.contentDigest,
			"signature-input": sig.signatureInput,
			signature: sig.signature,
		},
	};
}

/** A verifier that resolves the caller's key from the directory its signature names. */
async function verifies(
	documents: Record<string, { body: string; headers: Record<string, string> }>,
	req: { url: string; body: Uint8Array<ArrayBuffer>; headers: Record<string, string> },
): Promise<boolean> {
	const fetch: FetchLike = async (url) => {
		const doc = documents[url];
		return {
			status: doc === undefined ? 404 : 200,
			text: async () => doc?.body ?? "",
			headers: { get: (name: string) => doc?.headers[name] ?? null },
		};
	};
	const resolver = createWBAKeyResolver({ fetch });
	const headers: Record<string, string> = {};
	for (const [k, v] of Object.entries(req.headers)) headers[k.toLowerCase()] = v;
	const verdict = await verifyRequestServer({
		method: "POST",
		url: req.url,
		body: req.body,
		headers: headers as VerifyRequestHeaders,
		resolve: {
			resolve: async (keyid, directory) => {
				const key = await resolver.resolve(keyid, directory);
				return key === undefined ? undefined : new Uint8Array(key);
			},
		},
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
		const documents = { [DIRECTORY_URL]: await served(document, [{ privKey: keyPair.privateKey, keyid }]) };

		const sent: { url: string; init: OutboundInit }[] = [];
		const signing = await signingTransportFor(keyPair, DIRECTORY, async (url: string, init: OutboundInit) => {
			sent.push({ url, init });
		});
		const url = "https://exchange.example/fora.v1.ExchangeService/GetAccountStatus";
		const body = new TextEncoder().encode('{"exchange":"exchange.example"}') as Uint8Array<ArrayBuffer>;
		await signing(url, { method: "POST", body });

		const out = sent[0];
		if (out === undefined) throw new Error("nothing was sent");
		expect(out.init.headers?.["signature-agent"]).toBe(`sig1="${DIRECTORY}"`);
		expect(out.init.headers?.["signature-input"]).toContain(`keyid="${keyid}"`);
		expect(await verifies(documents, { url, body, headers: out.init.headers ?? {} })).toBe(true);

		// A directory that does not publish the key: the same request no longer verifies.
		const stranger = await generateKey();
		const otherDocs = {
			[DIRECTORY_URL]: await served(await directoryDocument([stranger.keyPair.publicKey]), [
				{ privKey: stranger.keyPair.privateKey, keyid: stranger.thumbprint },
			]),
		};
		expect(await verifies(otherDocs, { url, body, headers: out.init.headers ?? {} })).toBe(false);

		// A directory that lists the key without the key's own response signature: the
		// resolver does not hand the key out, so the request does not verify either.
		const unsignedByIt = {
			[DIRECTORY_URL]: await served(document, [{ privKey: stranger.keyPair.privateKey, keyid: stranger.thumbprint }]),
		};
		expect(await verifies(unsignedByIt, { url, body, headers: out.init.headers ?? {} })).toBe(false);
	});

	it("sign a directory response that verifyDirectoryResponse accepts for the served authority only", async () => {
		const { keyPair, thumbprint: keyid } = await generateKey();
		const doc = await served(await directoryDocument([keyPair.publicKey]), [{ privKey: keyPair.privateKey, keyid }]);
		const body = new TextEncoder().encode(doc.body) as Uint8Array<ArrayBuffer>;
		const x = (JSON.parse(doc.body) as WBAFile).keys?.[0]?.x ?? "";
		const pub = decodeBase64Url(x) as Uint8Array<ArrayBuffer>;
		const now = Math.floor(Date.now() / 1000);
		expect(await verifyDirectoryResponse("agent.example", doc.headers, body, [pub], now)).toEqual(new Set([keyid]));
		expect(await verifyDirectoryResponse("other.example", doc.headers, body, [pub], now)).toEqual(new Set());
	});

	it("drive the client as the minted agent", async () => {
		const { keyPair, thumbprint: keyid } = await generateKey();
		const documents = {
			[DIRECTORY_URL]: await served(await directoryDocument([keyPair.publicKey]), [{ privKey: keyPair.privateKey, keyid }]),
		};
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
