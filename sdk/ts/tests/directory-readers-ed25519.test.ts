// The directory readers check response signatures through an injected Ed25519 primitive.
//
// A runtime without WebCrypto Ed25519, such as Fastly Compute, supplies its own verify
// primitive. readWBADirectory, the WBA key resolver and the offer-directory fetch each
// take it as `verifyEd25519` and hand it to verifyDirectoryResponse; before they did,
// every listed key read as unsigned on such a runtime. Each case shows the injected
// primitive decides the verdict both ways: one that refuses everything drops a genuinely
// signed key, and one that accepts everything keeps a key whose signature is corrupted,
// which the WebCrypto default refuses.

import { describe, expect, it } from "vitest";
import {
	createWBAKeyResolver,
	createWBAOfferDirectoryFetch,
	DirectoryResponseUnsigned,
	type FetchLike,
	readWBADirectory,
} from "../resolvers/edge.ts";
import type { Ed25519Verify } from "../src/pop.ts";
import { iso, HOUR_MS, makeKey, signedDirectoryHeaders, type TestKey, wbaFileJson, wbaJwk } from "./resolvers-harness.ts";

const AUTHORITY = "pub.example";
const ORIGIN = `https://${AUTHORITY}`;
const DIRECTORY_URL = `${ORIGIN}/.well-known/http-message-signatures-directory`;

interface Served {
	key: TestKey;
	fetch: FetchLike;
}

// serve answers the directory URL with a directory listing one fresh key, signed by it;
// `corrupt` flips the first byte of the signature so the WebCrypto default refuses it.
async function serve(corrupt: boolean): Promise<Served> {
	const key = await makeKey();
	const now = Date.now();
	const body = wbaFileJson([wbaJwk(key.x, iso(now - HOUR_MS), iso(now + HOUR_MS))]);
	const headers = await signedDirectoryHeaders(AUTHORITY, body);
	if (corrupt) {
		const sig = headers.signature as string;
		headers.signature = sig.replace(/:([^:]+):/, (_m, b64: string) => `:${b64.startsWith("A") ? "B" : "A"}${b64.slice(1)}:`);
	}
	const fetch: FetchLike = async (url) =>
		url === DIRECTORY_URL ? new Response(body, { headers }) : new Response("", { status: 404 });
	return { key, fetch };
}

function recording(answer: boolean): { verify: Ed25519Verify; calls: () => number } {
	let calls = 0;
	return {
		verify: async () => {
			calls += 1;
			return answer;
		},
		calls: () => calls,
	};
}

describe("readWBADirectory", () => {
	it("an injected primitive that refuses every signature leaves the directory unsigned", async () => {
		const { fetch } = await serve(false);
		await expect(readWBADirectory(AUTHORITY, { fetch })).resolves.toBeDefined();
		const refuse = recording(false);
		await expect(readWBADirectory(AUTHORITY, { fetch, verifyEd25519: refuse.verify })).rejects.toBeInstanceOf(
			DirectoryResponseUnsigned,
		);
		expect(refuse.calls()).toBeGreaterThan(0);
	});

	it("an injected primitive that accepts every signature reads a directory the default refuses", async () => {
		const { fetch } = await serve(true);
		await expect(readWBADirectory(AUTHORITY, { fetch })).rejects.toBeInstanceOf(DirectoryResponseUnsigned);
		const accept = recording(true);
		const doc = await readWBADirectory(AUTHORITY, { fetch, verifyEd25519: accept.verify });
		expect(doc.message.keys).toHaveLength(1);
		expect(accept.calls()).toBeGreaterThan(0);
	});
});

describe("createWBAKeyResolver", () => {
	it("hands out no key when the injected primitive refuses every signature", async () => {
		const { key, fetch } = await serve(false);
		expect(await createWBAKeyResolver({ fetch }).resolve(key.tp, ORIGIN)).toEqual(key.rawPub);
		const refuse = recording(false);
		expect(await createWBAKeyResolver({ fetch, verifyEd25519: refuse.verify }).resolve(key.tp, ORIGIN)).toBeUndefined();
		expect(refuse.calls()).toBeGreaterThan(0);
	});

	it("hands out the key when the injected primitive accepts a signature the default refuses", async () => {
		const { key, fetch } = await serve(true);
		expect(await createWBAKeyResolver({ fetch }).resolve(key.tp, ORIGIN)).toBeUndefined();
		const accept = recording(true);
		expect(await createWBAKeyResolver({ fetch, verifyEd25519: accept.verify }).resolve(key.tp, ORIGIN)).toEqual(
			key.rawPub,
		);
	});
});

describe("createWBAOfferDirectoryFetch", () => {
	it("lists no key when the injected primitive refuses every signature", async () => {
		const { fetch } = await serve(false);
		expect((await createWBAOfferDirectoryFetch({ fetch })(AUTHORITY))?.keys).toHaveLength(1);
		const refuse = recording(false);
		expect((await createWBAOfferDirectoryFetch({ fetch, verifyEd25519: refuse.verify })(AUTHORITY))?.keys).toHaveLength(0);
		expect(refuse.calls()).toBeGreaterThan(0);
	});

	it("lists the key when the injected primitive accepts a signature the default refuses", async () => {
		const { fetch } = await serve(true);
		expect((await createWBAOfferDirectoryFetch({ fetch })(AUTHORITY))?.keys).toHaveLength(0);
		const accept = recording(true);
		expect((await createWBAOfferDirectoryFetch({ fetch, verifyEd25519: accept.verify })(AUTHORITY))?.keys).toHaveLength(1);
	});
});
