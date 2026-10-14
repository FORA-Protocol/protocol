// The edge entry where only the globals of Fastly Compute's JavaScript runtime exist.
//
// Fastly Compute has no AbortController and no AbortSignal: neither is in its runtime
// (@fastly/js-compute 3.43.1), its typings declare neither, and its RequestInit takes no
// signal. A document read that built an AbortController threw there before it fetched
// anything, so a Fastly edge could read no key directory at all. The Workers types
// (tsconfig.workers.json) and the Workers context of edge-no-eval.test.ts both declare
// AbortController, so only a context holding Fastly's globals notices.
//
// This test bundles the edge entry as a Fastly Compute build resolves it and drives it in
// such a context: every reader, a key directory signed in the same context through the
// identity helpers and read through createWBAOfferDirectoryFetch and createWBAKeyResolver,
// every bound of the read, and its deadline. Each refusal is counted only once its
// transport answered and, where a reader answers absent rather than refusing, after a
// control read in the same context succeeded.

import vm from "node:vm";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { DOCUMENT_READ_TIMEOUT_MS, MAX_DOC_BYTES } from "../resolvers/fetch.ts";
import { MAX_REDIRECTS } from "../resolvers/ssrf.ts";
import { bundleProbe, FASTLY_CONDITIONS, fastlyGlobals, here, sandbox } from "./edge-sandbox.ts";
import { stalledBody } from "./resolvers-harness.ts";

const PROBE = `
import {
	createWBAKeyResolver,
	createWBAOfferDirectoryFetch,
	readLicenseDocument,
	readManifest,
	readRevocationList,
	readWBADirectory,
	WBA_DIRECTORY_MEDIA_TYPE,
	WBA_DIRECTORY_PATH,
} from ${JSON.stringify(here("../resolvers/edge.ts"))};
import { directoryDocument, generateKey, signDirectoryResponse } from ${JSON.stringify(here("../core/identity.ts"))};

const REVOCATIONS = '{"as_of":"2026-05-01T12:00:00Z","revoked":[]}';
const LICENSE = "Licensed for retrieval-augmented answers.\\n";

// A fetch answering from route, recording the members of every init it was handed.
function recording(route) {
	const inits = [];
	const fetch = async (url, init) => {
		inits.push(init === undefined ? "" : Object.keys(init).sort().join(","));
		return route(url);
	};
	return { fetch, inits };
}

async function outcome(run) {
	try {
		return (await run()) === undefined ? "absent" : "ok";
	} catch (e) {
		return (e?.name ?? "error") + ": " + (e?.message ?? String(e));
	}
}

// The key directory of pub.example, publishing one key and signed by it, built here.
async function signedDirectory() {
	const { keyPair, thumbprint } = await generateKey();
	const body = JSON.stringify(await directoryDocument([keyPair.publicKey]));
	const now = Math.floor(Date.now() / 1000);
	const sig = await signDirectoryResponse(
		"pub.example",
		new TextEncoder().encode(body),
		[{ privKey: keyPair.privateKey, keyid: thumbprint }],
		now - 60,
		now + 3600,
	);
	const headers = {
		"content-type": WBA_DIRECTORY_MEDIA_TYPE,
		"content-digest": sig.contentDigest,
		"signature-input": sig.signatureInput,
		signature: sig.signature,
	};
	const url = "https://pub.example" + WBA_DIRECTORY_PATH;
	return {
		thumbprint,
		answer: (at) => (at === url ? new Response(body, { headers }) : new Response("", { status: 404 })),
	};
}

async function sha256(text) {
	const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
	return "sha256:" + Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

globalThis.readers = async () => {
	const directory = await signedDirectory();
	const keys = recording(directory.answer);
	const file = await createWBAOfferDirectoryFetch({ fetch: keys.fetch })("pub.example");
	const key = await createWBAKeyResolver({ fetch: keys.fetch }).resolve(directory.thumbprint, "https://pub.example");
	const manifest = JSON.stringify({
		ver: "1.0",
		role: "ROLE_PUBLISHER",
		domain: "pub.example",
		exchanges: [{ domain: "x.example", endpoint: "https://x.example", relationship: "PROVIDER_RELATIONSHIP_DIRECT" }],
	});
	const documents = recording((url) =>
		url.endsWith("/terms.txt")
			? new Response(LICENSE)
			: url.endsWith("/revoked.json")
				? new Response(REVOCATIONS)
				: new Response(manifest, { headers: { "content-type": "application/json" } }),
	);
	return {
		directory: await outcome(() => readWBADirectory("pub.example", { fetch: keys.fetch })),
		offerDirectoryKeys: file?.keys?.length ?? "absent",
		resolvedKeyBytes: key?.byteLength ?? "absent",
		manifest: await outcome(() => readManifest("pub.example", { fetch: documents.fetch })),
		revocations: await outcome(() => readRevocationList("https://pub.example/revoked.json", { fetch: documents.fetch })),
		license: await outcome(async () =>
			readLicenseDocument({ uri: "https://pub.example/terms.txt", uri_digest: await sha256(LICENSE) }, { fetch: documents.fetch }),
		),
		inits: [...new Set([...keys.inits, ...documents.inits])],
	};
};

globalThis.bounds = async () => {
	const elsewhere = () =>
		new Response(null, { status: 302, headers: { location: "https://elsewhere.example" + WBA_DIRECTORY_PATH } });
	const chain = (url) => {
		const n = Number.parseInt(new URL(url).pathname.slice(1), 10);
		return n > 0 ? new Response(null, { status: 302, headers: { location: "/" + (n - 1) } }) : new Response(REVOCATIONS);
	};
	const directory = await signedDirectory();
	const control = recording(directory.answer);
	const overCap = recording(() => new Response(new Uint8Array(${MAX_DOC_BYTES} + 1)));
	const downgrade = recording(() => new Response(null, { status: 302, headers: { location: "http://pub.example/revoked.json" } }));
	const keyDirectory = recording(elsewhere);
	const offerDirectory = recording(elsewhere);
	const atCap = recording(chain);
	const pastCap = recording(chain);
	return {
		overCap: await outcome(() => readRevocationList("https://pub.example/revoked.json", { fetch: overCap.fetch })),
		overCapCalls: overCap.inits.length,
		downgrade: await outcome(() => readRevocationList("https://pub.example/revoked.json", { fetch: downgrade.fetch })),
		downgradeCalls: downgrade.inits.length,
		keyDirectoryRedirect: await outcome(() => readWBADirectory("pub.example", { fetch: keyDirectory.fetch })),
		keyDirectoryRedirectCalls: keyDirectory.inits.length,
		offerDirectoryControl: await outcome(() => createWBAOfferDirectoryFetch({ fetch: control.fetch })("pub.example")),
		offerDirectoryRedirect: await outcome(() => createWBAOfferDirectoryFetch({ fetch: offerDirectory.fetch })("pub.example")),
		offerDirectoryRedirectCalls: offerDirectory.inits.length,
		redirectsAtCap: await outcome(() => readRevocationList("https://pub.example/${MAX_REDIRECTS}", { fetch: atCap.fetch })),
		redirectsPastCap: await outcome(() => readRevocationList("https://pub.example/${MAX_REDIRECTS + 1}", { fetch: pastCap.fetch })),
		redirectsPastCapCalls: pastCap.inits.length,
	};
};

// One read through the transport the test hands in, settled to its outcome; the test moves
// the clock.
globalThis.readThrough = (fetch) => outcome(() => readRevocationList("https://pub.example/revoked.json", { fetch }));
`;

interface FastlyProbe {
	readers(): Promise<Record<string, unknown>>;
	bounds(): Promise<Record<string, unknown>>;
	readThrough(fetch: (url: string, init?: unknown) => Promise<Response>): Promise<string>;
}

/** A transport the test hands the context, counting the calls it answered. */
function counted(route: () => Promise<Response>): {
	fetch: (url: string, init?: unknown) => Promise<Response>;
	calls: () => number;
} {
	let calls = 0;
	return {
		fetch: () => {
			calls += 1;
			return route();
		},
		calls: () => calls,
	};
}

describe("the edge entry where only Fastly Compute's globals exist", () => {
	let bundle = "";
	beforeAll(async () => {
		bundle = await bundleProbe(PROBE, FASTLY_CONDITIONS);
	}, 60_000);
	afterEach(() => {
		vi.useRealTimers();
	});

	// A fresh context per test, made at the call: one made after vi.useFakeTimers() runs on
	// the fake timers.
	function fastly(): FastlyProbe {
		const context = sandbox(fastlyGlobals());
		vm.runInContext(bundle, context);
		return context as unknown as FastlyProbe;
	}

	it("has no AbortController and no AbortSignal, as Fastly Compute has neither", () => {
		const context = sandbox(fastlyGlobals());
		expect(vm.runInContext("[typeof AbortController, typeof AbortSignal, typeof ReadableStream].join()", context)).toBe(
			"undefined,undefined,function",
		);
	});

	it("reads every document, a signed key directory included, and hands the transport no signal", async () => {
		expect(await fastly().readers()).toEqual({
			directory: "ok",
			offerDirectoryKeys: 1,
			resolvedKeyBytes: 32,
			manifest: "ok",
			revocations: "ok",
			license: "ok",
			inits: ["redirect"],
		});
	});

	it("keeps the cap, the redirect rules and a key directory's no-redirect rule", async () => {
		expect(await fastly().bounds()).toEqual({
			overCap: expect.stringMatching(/^DirectoryUnavailable: a document over the /),
			overCapCalls: 1,
			downgrade: expect.stringMatching(/^DirectoryUnavailable: a redirect from https to plaintext http /),
			downgradeCalls: 1,
			keyDirectoryRedirect: expect.stringMatching(/^DirectoryUnavailable: a key directory is never fetched through a redirect/),
			keyDirectoryRedirectCalls: 1,
			offerDirectoryControl: "ok",
			offerDirectoryRedirect: "absent",
			offerDirectoryRedirectCalls: 1,
			redirectsAtCap: "ok",
			redirectsPastCap: expect.stringMatching(/^DirectoryUnavailable: more than /),
			redirectsPastCapCalls: MAX_REDIRECTS + 1,
		});
	});

	it("ends a read at its deadline with no AbortController, and stops what it was reading", async () => {
		// Only the timers are faked: the context keeps the real Date, performance and
		// queueMicrotask, as Fastly's runtime would.
		vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
		const context = fastly();
		const stalled = stalledBody();
		const cutOff = stalledBody(new Uint8Array(10));
		const late = stalledBody();
		let answerLate: ((resp: Response) => void) | undefined;
		const transports = [
			counted(() => new Promise<Response>(() => undefined)),
			counted(async () => new Response(stalled.stream)),
			counted(async () => new Response(cutOff.stream)),
			counted(
				() =>
					new Promise<Response>((resolve) => {
						answerLate = resolve;
					}),
			),
		];
		const reads = Promise.all(transports.map((t) => context.readThrough(t.fetch)));
		await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
		const deadline = `DirectoryUnavailable: no complete answer for https://pub.example/revoked.json within ${DOCUMENT_READ_TIMEOUT_MS} ms`;
		expect(await reads).toEqual([deadline, deadline, deadline, deadline]);
		expect(transports.map((t) => t.calls())).toEqual([1, 1, 1, 1]);

		answerLate?.(new Response(late.stream));
		await vi.advanceTimersByTimeAsync(0);
		expect([stalled, cutOff, late].map((body) => body.cancelled())).toEqual([true, true, true]);
	});
});
