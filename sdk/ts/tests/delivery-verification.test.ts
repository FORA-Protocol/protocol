// Delivery verification: execute, BrokerClient.execute and fetch check a retrieval URL's
// signature, its agent binding and its expiry before handing it back or dialling it.
//
// The Exchange's URL-signing key is resolved from its Web Bot Auth key directory by the
// SDK's own WBA resolver, over an injected fetch that serves the directory this test
// builds with directoryDocument. The purchase verbs run through the injected send, as the
// other execute tests do; fetch dials a real loopback server.
import { createServer } from "node:http";
import { describe, expect, it } from "vitest";

import {
	createBrokerClient,
	createClient,
	ForaCallError,
	type ClientOptions,
	type Delivery,
} from "../client/index.ts";
import { directoryDocument } from "../core/identity.ts";
import { createVerifier, type VerifiedOffer } from "../core/verifier.ts";
import { reason } from "../src/errordetail.ts";
import { signOffer } from "../src/offer-sign.ts";
import { signEd25519SignedUrl } from "../src/signurl.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { createWBAKeyResolver } from "../resolvers/index.ts";
import { WBA_DIRECTORY_PATH } from "../resolvers/wba.ts";

const REQUESTER = { id: "agent-1", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" };
const HOUR = 3600;

async function keyPair(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

async function thumbprintOf(key: CryptoKey): Promise<string> {
	return thumbprint(new Uint8Array(await crypto.subtle.exportKey("raw", key)));
}

/** An Exchange: its offer key, its URL-signing key published in its directory. */
async function exchangeAt(domain: string) {
	const urlKey = await keyPair();
	return { domain, urlKey, kid: await thumbprintOf(urlKey.publicKey) };
}
type Exchange = Awaited<ReturnType<typeof exchangeAt>>;

/** The key resolver a client uses: the SDK's WBA resolver over directories served here. */
function keysFor(exchanges: Exchange[], status = 200) {
	return createWBAKeyResolver({
		scheme: "https",
		fetch: async (url) => {
			const ex = exchanges.find((e) => url === `https://${e.domain}${WBA_DIRECTORY_PATH}`);
			const body = ex === undefined ? "" : JSON.stringify(await directoryDocument([ex.urlKey.publicKey]));
			return { status: ex === undefined ? 404 : status, text: async () => body };
		},
	});
}

async function offerAt(id: string, exchange: string): Promise<VerifiedOffer> {
	const kp = await keyPair();
	const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey)) as Uint8Array<ArrayBuffer>;
	const unsigned: Record<string, unknown> = { offer_id: id, exchange, expires_at: "2099-01-01T00:00:00Z" };
	const offer = { ...unsigned, signature: await signOffer(unsigned, kp.privateKey), signature_algorithm: "EdDSA" };
	const sorted = await createVerifier("strict", {
		resolve: async () => publicKey,
		now: () => Date.parse("2024-01-01T00:00:00Z"),
	}).sort([offer]);
	const verified = sorted.verified[0];
	if (verified === undefined) throw new Error("fixture offer did not verify");
	return verified;
}

/** A retrieval URL the Exchange signed, bound to `agentId` ("" for bearer). */
async function signedURL(
	ex: Exchange,
	agentId: string,
	opts: { base?: string; expUnix?: number; key?: CryptoKey; kid?: string } = {},
): Promise<string> {
	return signEd25519SignedUrl(
		opts.base ?? "https://edge.test/content/1",
		{
			kid: opts.kid ?? ex.kid,
			agentId,
			expUnix: opts.expUnix ?? Math.floor(Date.now() / 1000) + HOUR,
		},
		opts.key ?? ex.urlKey.privateKey,
	);
}

async function agent() {
	const keys = await keyPair();
	return { keys, id: await thumbprintOf(keys.publicKey) };
}
type Agent = Awaited<ReturnType<typeof agent>>;

function options(a: Agent, answer: unknown, extra: ClientOptions = {}): ClientOptions {
	return {
		requester: REQUESTER,
		signer: { privKey: a.keys.privateKey, keyid: "agent.v1" },
		agentPublicKey: a.keys.publicKey,
		signatureAgent: "https://agent.test",
		send: async () => ({ status: 200, body: JSON.stringify(answer) }),
		...extra,
	};
}

function answerWith(url: string | undefined, hash: string, extra: Record<string, unknown> = {}) {
	return {
		ver: "1.0",
		agent_identity_hash: hash,
		items: [
			{
				offer_id: "offer-1",
				transaction_id: "tx-1",
				...(url === undefined ? {} : { retrieval_endpoint: url }),
				...extra,
			},
		],
	};
}

async function refusal(p: Promise<unknown>): Promise<ForaCallError> {
	try {
		await p;
	} catch (e) {
		expect(e).toBeInstanceOf(ForaCallError);
		return e as ForaCallError;
	}
	throw new Error("the call did not fail");
}

function reasonOf(f: ForaCallError): string | undefined {
	return f.detail === undefined ? undefined : reason(f.detail)?.value;
}

describe("execute verifies every retrieval URL", () => {
	it("returns the verified binding beside the answer, outside the wire message", async () => {
		const ex = await exchangeAt("exchange-a.test");
		const a = await agent();
		const url = await signedURL(ex, a.id);
		const offer = await offerAt("offer-1", ex.domain);
		const client = createClient("https://exchange-a.test", options(a, answerWith(url, a.id), { deliveryKeys: keysFor([ex]) }));
		const result = await client.execute(offer);
		const d = result.deliveries[0] as Delivery;
		expect(d.url).toBe(url);
		expect(d.exchange).toBe(ex.domain);
		expect(d.agentId).toBe(a.id);
		expect(d.keyId).toBe(ex.kid);
		expect(d.expiresAt.getTime()).toBe(Number(new URL(url).searchParams.get("exp")) * 1000);
		expect(JSON.stringify(result)).not.toContain("deliveries");
		expect(result.items?.[0]?.retrieval_endpoint).toBe(url);
	});

	it("verifies a bearer URL from an answer that stated no binding", async () => {
		const ex = await exchangeAt("exchange-a.test");
		const a = await agent();
		const url = await signedURL(ex, "");
		const client = createClient("https://exchange-a.test", options(a, answerWith(url, ""), { deliveryKeys: keysFor([ex]) }));
		const result = await client.execute(await offerAt("offer-1", ex.domain));
		expect(result.deliveries[0]?.agentId).toBe("");
	});

	it("leaves an item without a retrieval URL unverified", async () => {
		const ex = await exchangeAt("exchange-a.test");
		const a = await agent();
		const client = createClient(
			"https://exchange-a.test",
			options(a, answerWith(undefined, a.id, { denial_reason: "DENIAL_REASON_RATE_LIMITED" }), {
				deliveryKeys: keysFor([ex]),
			}),
		);
		const result = await client.execute(await offerAt("offer-1", ex.domain));
		expect(result.deliveries).toEqual([undefined]);
	});

	const refused: [string, (ex: Exchange, a: Agent, other: Exchange) => Promise<{ url: string; hash: string }>, string][] = [
		[
			"a signature another key made",
			async (ex, a, other) => ({ url: await signedURL(ex, a.id, { key: other.urlKey.privateKey }), hash: a.id }),
			"RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH",
		],
		[
			"a key the Exchange's directory does not publish",
			async (ex, a, other) => ({ url: await signedURL(ex, a.id, { key: other.urlKey.privateKey, kid: other.kid }), hash: a.id }),
			"RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH",
		],
		[
			"a URL bound to another agent",
			async (ex) => {
				const other = await agent();
				return { url: await signedURL(ex, other.id), hash: other.id };
			},
			"RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
		],
		[
			"a bearer URL from an answer that stated a binding",
			async (ex, a) => ({ url: await signedURL(ex, ""), hash: a.id }),
			"RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
		],
		[
			"a URL bound to this agent while the answer stated another",
			async (ex, a) => ({ url: await signedURL(ex, a.id), hash: (await agent()).id }),
			"RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH",
		],
		[
			"an expired URL",
			async (ex, a) => ({ url: await signedURL(ex, a.id, { expUnix: Math.floor(Date.now() / 1000) - 10 }), hash: a.id }),
			"RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED",
		],
		[
			"a URL with no signature",
			async () => ({ url: "https://edge.test/content/1?exp=99999999999", hash: "" }),
			"RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING",
		],
		[
			"a URL with no expiry",
			async (ex, a) => {
				const url = new URL(await signedURL(ex, a.id));
				url.searchParams.delete("exp");
				return { url: url.toString(), hash: a.id };
			},
			"RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING",
		],
	];
	for (const [label, build, want] of refused) {
		it(`refuses ${label}`, async () => {
			const ex = await exchangeAt("exchange-a.test");
			const other = await exchangeAt("exchange-b.test");
			const a = await agent();
			const { url, hash } = await build(ex, a, other);
			const client = createClient("https://exchange-a.test", options(a, answerWith(url, hash), { deliveryKeys: keysFor([ex, other]) }));
			const f = await refusal(client.execute(await offerAt("offer-1", ex.domain)));
			expect(f.kind).toBe("malformed");
			expect(reasonOf(f)).toBe(want);
			expect(f.detail?.domain).toBe("fora.v1.Client");
			expect(f.message).toContain("tx-1");
		});
	}

	it("reports a directory it cannot read as unreachable", async () => {
		const ex = await exchangeAt("exchange-a.test");
		const a = await agent();
		const url = await signedURL(ex, a.id);
		const client = createClient("https://exchange-a.test", options(a, answerWith(url, a.id), { deliveryKeys: keysFor([ex], 503) }));
		const f = await refusal(client.execute(await offerAt("offer-1", ex.domain)));
		expect(f.kind).toBe("unreachable");
	});

	it("skips verification under deliveryVerification: off", async () => {
		const a = await agent();
		const client = createClient(
			"https://exchange-a.test",
			options(a, answerWith("https://edge.test/not-signed", a.id), { deliveryVerification: "off" }),
		);
		const result = await client.execute(await offerAt("offer-1", "exchange-a.test"));
		expect(result.deliveries).toEqual([]);
	});
});

describe("BrokerClient.execute verifies each URL against the Exchange that issued it", () => {
	async function broker(badSecond: boolean) {
		const exA = await exchangeAt("exchange-a.test");
		const exB = await exchangeAt("exchange-b.test");
		const a = await agent();
		const answer = {
			ver: "1.0",
			items: [
				{ offer_id: "offer-a", transaction_id: "tx-a", retrieval_endpoint: await signedURL(exA, a.id) },
				{
					offer_id: "offer-b",
					transaction_id: "tx-b",
					// Signed with exchange A's key: valid for A, not for B, which issued the offer.
					retrieval_endpoint: await signedURL(badSecond ? exA : exB, a.id, badSecond ? { kid: exB.kid } : {}),
				},
			],
			exchanges: [
				{ exchange: exA.domain, offer_ids: ["offer-a"], agent_identity_hash: a.id },
				{ exchange: exB.domain, offer_ids: ["offer-b"], agent_identity_hash: a.id },
			],
		};
		const client = createBrokerClient("https://broker.test", options(a, answer, { deliveryKeys: keysFor([exA, exB]) }));
		const offers = [await offerAt("offer-a", exA.domain), await offerAt("offer-b", exB.domain)];
		return { client, offers, exA, exB };
	}

	it("verifies each item against its own Exchange's key", async () => {
		const { client, offers, exA, exB } = await broker(false);
		const result = await client.execute(offers);
		expect(result.deliveries.map((d) => d?.exchange)).toEqual([exA.domain, exB.domain]);
		expect(result.deliveries.map((d) => d?.keyId)).toEqual([exA.kid, exB.kid]);
	});

	it("refuses a URL another Exchange's key signed", async () => {
		const { client, offers } = await broker(true);
		const f = await refusal(client.execute(offers));
		expect(reasonOf(f)).toBe("RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH");
		expect(f.message).toContain("tx-b");
	});
});

describe("fetch verifies the URL when it knows the Exchange", () => {
	async function withEdge<T>(run: (origin: string, hits: () => number) => Promise<T>): Promise<T> {
		let hits = 0;
		const server = createServer((_req, res) => {
			hits++;
			res.writeHead(200, { "content-type": "text/plain" });
			res.end("body");
		});
		await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
		const port = (server.address() as { port: number }).port;
		const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
		process.env["SKIP_SSRF"] = "true";
		process.env["ALLOW_INSECURE"] = "true";
		try {
			return await run(`http://127.0.0.1:${port}`, () => hits);
		} finally {
			if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
			else process.env["SKIP_SSRF"] = saved[0];
			if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
			else process.env["ALLOW_INSECURE"] = saved[1];
			server.close();
		}
	}

	it("verifies a Delivery and returns its binding with the content", async () => {
		const ex = await exchangeAt("exchange-a.test");
		const a = await agent();
		await withEdge(async (origin) => {
			const url = await signedURL(ex, a.id, { base: `${origin}/content/1` });
			const client = createClient("https://exchange-a.test", options(a, {}, { deliveryKeys: keysFor([ex]) }));
			const delivery: Delivery = { url, exchange: ex.domain, agentId: a.id, keyId: ex.kid, expiresAt: new Date() };
			const content = await client.fetch(delivery);
			expect(new TextDecoder().decode(content.body)).toBe("body");
			expect(content.binding?.agentId).toBe(a.id);
			expect(content.binding?.exchange).toBe(ex.domain);
		});
	});

	it("refuses a URL bound to another agent without dialling it", async () => {
		const ex = await exchangeAt("exchange-a.test");
		const a = await agent();
		await withEdge(async (origin, hits) => {
			const url = await signedURL(ex, (await agent()).id, { base: `${origin}/content/1` });
			const client = createClient("https://exchange-a.test", options(a, {}, { deliveryKeys: keysFor([ex]) }));
			const f = await refusal(client.fetch(url, { exchange: ex.domain }));
			expect(f.kind).toBe("malformed");
			expect(reasonOf(f)).toBe("RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH");
			expect(hits()).toBe(0);
		});
	});

	it("fetches a bare URL as given, with no binding", async () => {
		const a = await agent();
		await withEdge(async (origin, hits) => {
			const client = createClient("https://exchange-a.test", options(a, {}));
			const content = await client.fetch(`${origin}/content/unsigned`);
			expect(content.binding).toBeUndefined();
			expect(hits()).toBe(1);
		});
	});
});
