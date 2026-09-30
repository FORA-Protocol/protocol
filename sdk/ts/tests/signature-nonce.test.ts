// The signing transport stamps a fresh RFC 9421 nonce on every signature.
//
// Ed25519 is deterministic and created/expires have one-second resolution, so
// without the nonce two identical requests in the same second sign to the same
// bytes and the replay store refuses the second one. These tests pin that the
// nonce removes that collision and that replay protection still holds.

import { describe, expect, it } from "vitest";
import { signRequest } from "../core/sign-request.ts";
import { createSigningTransport, type OutboundInit } from "../core/signing-transport.ts";
import {
	type ReplayStore,
	type VerifyRequestHeaders,
	verifyRequestServer,
} from "../core/verify-request.ts";
import { decodeBase64Url } from "../src/base64url.ts";

const URL = "https://exchange.example/fora.v1.ExchangeService/DiscoverResources";
const BODY = new Uint8Array(new TextEncoder().encode('{"ver":"1"}')) as Uint8Array<ArrayBuffer>;
const CREATED = 1_700_000_000;
const EXPIRES = 1_700_000_300;
const NONCE = /;nonce="([^"]*)"/;

function memoryReplayStore(): ReplayStore {
	const seen = new Set<string>();
	return {
		seenNonce: async (n) => seen.has(n),
		seenOrAdd: async (n) => {
			if (seen.has(n)) return true;
			seen.add(n);
			return false;
		},
	};
}

async function fixture() {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	const keyid = "agent.test.v1";
	const store = memoryReplayStore();
	const verify = (headers: Record<string, string>) =>
		verifyRequestServer({
			method: "POST",
			url: URL,
			body: BODY,
			headers: headers as VerifyRequestHeaders,
			resolve: { resolve: (k) => (k === keyid ? pub : undefined) },
			replayStore: store,
			now: () => CREATED + 10,
			maxSignatureAge: EXPIRES - CREATED,
		});
	const sent: Record<string, string>[] = [];
	const send = async (_url: string, init: OutboundInit) => {
		sent.push(init.headers ?? {});
	};
	// A fixed window: created/expires are identical on every signature, the
	// collision condition.
	const window = () => [CREATED, EXPIRES] as [number, number];
	return { privKey: kp.privateKey, keyid, verify, sent, send, window };
}

describe("signing transport nonce", () => {
	it("gives identical requests unique signatures that both pass", async () => {
		const f = await fixture();
		const signing = createSigningTransport(f.send, { privKey: f.privKey, keyid: f.keyid, window: f.window });
		await signing(URL, { method: "POST", body: BODY });
		await signing(URL, { method: "POST", body: BODY });
		const [first, second] = f.sent as [Record<string, string>, Record<string, string>];

		const n1 = NONCE.exec(first["signature-input"] ?? "")?.[1];
		const n2 = NONCE.exec(second["signature-input"] ?? "")?.[1];
		expect(n1).toBeDefined();
		expect(decodeBase64Url(n1 ?? "")?.length).toBe(16);
		expect(n1).not.toBe(n2);
		expect(first.signature).not.toBe(second.signature);
		// Only the nonce differs: created/expires are unchanged.
		expect(first["signature-input"]?.replace(NONCE, "")).toBe(second["signature-input"]?.replace(NONCE, ""));

		expect(await f.verify(first)).toEqual({ valid: true });
		expect(await f.verify(second)).toEqual({ valid: true });
	});

	it("rejects an exact replay", async () => {
		const f = await fixture();
		const signing = createSigningTransport(f.send, { privKey: f.privKey, keyid: f.keyid, window: f.window });
		await signing(URL, { method: "POST", body: BODY });
		const headers = f.sent[0] as Record<string, string>;
		expect(await f.verify(headers)).toEqual({ valid: true });
		expect(await f.verify({ ...headers })).toMatchObject({ valid: false, reason: "replay" });
	});

	it.each([
		["changed", (s: string) => s.replace(NONCE, ';nonce="AAAAAAAAAAAAAAAAAAAAAA"')],
		["removed", (s: string) => s.replace(NONCE, "")],
	])("fails verification when the nonce is %s", async (_name, edit) => {
		const f = await fixture();
		const signing = createSigningTransport(f.send, { privKey: f.privKey, keyid: f.keyid, window: f.window });
		await signing(URL, { method: "POST", body: BODY });
		const headers = { ...(f.sent[0] as Record<string, string>) };
		headers["signature-input"] = edit(headers["signature-input"] ?? "");
		expect(await f.verify(headers)).toMatchObject({ valid: false, reason: "signature" });
	});

	it("accepts a legacy signature without a nonce", async () => {
		const f = await fixture();
		const signed = await signRequest(f.privKey, {
			method: "POST",
			url: URL,
			body: BODY,
			authorization: "",
			signatureAgent: "",
			keyid: f.keyid,
			created: CREATED,
			expires: EXPIRES,
		});
		expect(signed.signatureInput).not.toContain("nonce");
		expect(
			await f.verify({
				"content-digest": signed.contentDigest,
				"signature-input": signed.signatureInput,
				signature: signed.signature,
				authorization: "",
				"signature-agent": "",
			}),
		).toEqual({ valid: true });
	});

	it("rejects and sends nothing when random generation fails", async () => {
		const f = await fixture();
		const signing = createSigningTransport(f.send, {
			privKey: f.privKey,
			keyid: f.keyid,
			window: f.window,
			nonce: () => {
				throw new Error("entropy source unavailable");
			},
		});
		await expect(signing(URL, { method: "POST", body: BODY })).rejects.toThrow("entropy");
		expect(f.sent).toHaveLength(0);
	});
});
