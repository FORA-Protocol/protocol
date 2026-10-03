// Raw mode: a RawBody passed in place of a verb's request is sent exactly as given.
//
// Nothing is stamped, nothing is validated, none of the local refusals about the message
// run — and the body is still signed, still subject to the pre-signing hook, and its
// answer is still decoded into the verb's response schema. Driven through the injected
// send against a peer that verifies the signature, so "signed" means a server accepted it.
import { describe, expect, it } from "vitest";

import {
	createBrokerClient,
	createCatalogClient,
	createClient,
	ForaCallError,
	RawBody,
	type ClientOptions,
	type ResourceQuery,
	type UnaryResponse,
} from "../client/index.ts";
import { agentKeys, signedPeer } from "./signed-peer.ts";

const KEYID = "agent.v1";
const ENDPOINTS = { resolveEndpoint: async (host: string) => `https://${host}` };

async function fixture(answer: () => UnaryResponse, opts: ClientOptions = {}) {
	const { keys, pub } = await agentKeys();
	const peer = signedPeer(KEYID, pub, answer);
	const options: ClientOptions = {
		signer: { privKey: keys.privateKey, keyid: KEYID },
		send: peer.send,
		guardedSend: peer.send,
		endpointResolver: ENDPOINTS,
		...opts,
	};
	return { peer, options };
}

const ok = (body: unknown) => () => ({ status: 200, body: JSON.stringify(body) });

describe("RawBody", () => {
	it("sends bytes verbatim, signed, and decodes the answer", async () => {
		// Not canonical JSON and missing everything the client would stamp.
		const bytes = new TextEncoder().encode('{ "uris" : ["https://site.test/a"] }');
		const { peer, options } = await fixture(ok({ ver: "1.0", exchange: "exchange.test" }));
		const result = await createClient("https://exchange.test", options).discover(new RawBody(bytes));
		const received = peer.only();
		expect(Array.from(received.request.body)).toEqual(Array.from(bytes));
		expect(received.valid).toBe(true);
		expect(result.exchange).toBe("exchange.test");
	});

	it("sends a string as its UTF-8 bytes and any other value as one JSON serialization", async () => {
		const { peer, options } = await fixture(ok({}));
		const catalog = createCatalogClient("https://exchange.test", options);
		await catalog.pushResources(new RawBody("not json at all"));
		await catalog.removeResources(new RawBody({ paths: ["/x"] }));
		expect(peer.seen.map((s) => s.body)).toEqual(["not json at all", '{"paths":["/x"]}']);
	});

	it("skips the validation and the local refusals a built request gets", async () => {
		const { peer, options } = await fixture(ok({ ver: "1.0" }));
		const client = createCatalogClient("https://exchange.test", options);
		// No exchange: built, this is refused as not_sent before anything is signed.
		await expect(client.refreshCatalog({ tenant_id: "t" })).rejects.toMatchObject({ kind: "not_sent" });
		expect(peer.seen).toHaveLength(0);
		await client.refreshCatalog(new RawBody({ tenant_id: "t" }));
		expect(JSON.parse(peer.only().body)).toEqual({ tenant_id: "t" });
	});

	it("does not stamp ver, idempotency_key or requester", async () => {
		const { peer, options } = await fixture(ok({ ver: "1.0", report_id: "r-1" }), {
			requester: { id: "agent-1", domain: "agent.test" },
		});
		const client = createClient("https://exchange.test", options);
		const answer = await client.reportUsage(new RawBody({ exchange: "exchange.test" }));
		expect(JSON.parse(peer.only().body)).toEqual({ exchange: "exchange.test" });
		expect(answer.report_id).toBe("r-1");
	});

	it("still routes a manifest-addressed verb by the body's exchange", async () => {
		const dialled: string[] = [];
		const { options } = await fixture(ok({ ver: "1.0" }), {
			endpointResolver: {
				resolveEndpoint: async (host) => {
					dialled.push(host);
					return `https://${host}`;
				},
			},
		});
		const client = createClient("https://home.test", options);
		await client.getAccountStatus(new RawBody('{"exchange":"other.test"}'));
		expect(dialled).toEqual(["other.test"]);
		const failure = await client.register(new RawBody("{}")).catch((e: unknown) => e);
		expect(failure).toBeInstanceOf(ForaCallError);
		expect((failure as ForaCallError).kind).toBe("not_sent");
	});

	it("replaces the offers of a purchase, and verifies no delivery", async () => {
		const answer = {
			ver: "1.0",
			items: [{ offer_id: "o-1", transaction_id: "tx-1", retrieval_endpoint: "https://edge.test/x" }],
		};
		const { peer, options } = await fixture(ok(answer), {
			requester: { id: "agent-1", domain: "agent.test" },
		});
		const result = await createClient("https://exchange.test", options).execute(
			new RawBody({ items: [] }),
		);
		expect(peer.only().body).toBe('{"items":[]}');
		expect(result.items?.[0]?.transaction_id).toBe("tx-1");
		expect(result.deliveries).toEqual([]);
		const broker = await createBrokerClient("https://broker.test", options).execute(
			new RawBody("{}"),
		);
		expect(broker.deliveries).toEqual([]);
	});

	it("passes through the pre-signing hook", async () => {
		const { peer, options } = await fixture(ok({}), {
			beforeSign: async (req) => new Request(req.url, { method: "POST", headers: req.headers, body: `${await req.text()} ` }),
		});
		await createCatalogClient("https://exchange.test", options).pushResources(new RawBody("x"));
		expect(peer.only().body).toBe("x ");
		expect(peer.only().valid).toBe(true);
	});

	it("is decoded under strict decoding like any answer", async () => {
		const { options } = await fixture(ok({ ver: "1.0", surprise: 1 }), { strict: true });
		await expect(
			createCatalogClient("https://exchange.test", options).pushResources(new RawBody("{}")),
		).rejects.toMatchObject({ kind: "malformed" });
	});
});

describe("typed request inputs", () => {
	it("accept the generated request type as well as a plain record", async () => {
		const { peer, options } = await fixture(ok({ ver: "1.0", exchange: "exchange.test" }));
		const client = createClient("https://exchange.test", options);
		const typed: ResourceQuery = { exchange: "exchange.test", uris: ["https://site.test/a"] };
		const loose: Record<string, unknown> = { exchange: "exchange.test", uris: ["https://site.test/a"] };
		await client.discover(typed);
		await client.discover(loose);
		const [a, b] = peer.seen;
		expect(a?.body).toBe(b?.body);
	});
});
