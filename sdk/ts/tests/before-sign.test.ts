// The pre-signing hook: ClientOptions.beforeSign.
//
// A caller that needs to send a request the SDK would not build on its own (a harness
// probing how a server refuses a malformed message) gets ONE supported seam: a function
// that receives the stamped, validated request as a Fetch API Request just before it is
// signed, and returns the request to sign instead. The SDK still signs exactly the bytes
// it sends and decodes the reply with its own decoder.
//
// Every case drives the real client through its injected send, against a peer that
// verifies the RFC 9421 signature with the SDK's own server-side verifier — which is what
// proves the signature covers the PATCHED bytes. The refusals are local and nothing is
// sent for any of them.
import { describe, expect, it } from "vitest";

import { createCatalogClient, ForaCallError, type ClientOptions } from "../client/index.ts";
import { reason } from "../src/errordetail.ts";
import vectorsFile from "../../go/connect/testdata/connect-error-vectors.json";
import { agentKeys, signedPeer } from "./signed-peer.ts";

const KEYID = "agent.v1";
const PUSH_URL = "https://exchange.test/fora.v1.CatalogService/PushResources";

const CATALOG_REJECTION = (
	vectorsFile as { vectors: { name: string; http_status: number; envelope: unknown }[] }
).vectors.find((v) => v.name === "catalog_rejection");
if (CATALOG_REJECTION === undefined) throw new Error("corpus has no catalog_rejection row");

function push(): Record<string, unknown> {
	return {
		exchange: "exchange.test",
		tenant_id: "tenant-1",
		caller_id: "publisher.test",
		entries: [
			{
				domain: "publisher.test",
				path: "/x",
				terms: [
					{
						semantics: "TERM_SEMANTICS_ENUMERATED",
						pricing: { model: "PRICING_MODEL_FREE", rate: "0" },
					},
				],
			},
		],
	};
}

async function fixture(answer?: Parameters<typeof signedPeer>[2]) {
	const { keys, pub } = await agentKeys();
	const peer = signedPeer(KEYID, pub, answer);
	const client = (opts: ClientOptions = {}) =>
		createCatalogClient("https://exchange.test", {
			signer: { privKey: keys.privateKey, keyid: KEYID },
			send: peer.send,
			...opts,
		});
	return { peer, client };
}

/** A request like `req` with its body replaced, headers carried over verbatim. */
async function withBody(req: Request, body: string): Promise<Request> {
	return new Request(req.url, { method: req.method, headers: req.headers, body });
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

describe("beforeSign", () => {
	it("is handed the stamped request, before it is signed", async () => {
		const { peer, client } = await fixture();
		let seen: Request | undefined;
		await client({
			beforeSign: (req) => {
				seen = req;
				return req;
			},
		}).pushResources(push());
		expect(seen?.method).toBe("POST");
		expect(seen?.url).toBe(PUSH_URL);
		expect(seen?.headers.get("signature")).toBeNull();
		const sent = JSON.parse(peer.only().body) as Record<string, unknown>;
		expect(sent["ver"]).toBe("1.0");
		expect(peer.only().valid).toBe(true);
	});

	it("signs the patched bytes, and a malformed patch comes back as the typed refusal", async () => {
		const { peer, client } = await fixture(() => ({
			status: CATALOG_REJECTION.http_status,
			body: JSON.stringify(CATALOG_REJECTION.envelope),
		}));
		// A valid push, made malformed after validation: the recipient is removed, which the
		// client itself would have refused to send.
		const failure = await refusal(
			client({
				beforeSign: async (req) => {
					const body = JSON.parse(await req.text()) as Record<string, unknown>;
					delete body["exchange"];
					return withBody(req, JSON.stringify(body));
				},
			}).pushResources(push()),
		);
		const received = peer.only();
		expect(received.valid, "the signature does not cover the patched body").toBe(true);
		expect(JSON.parse(received.body)).not.toHaveProperty("exchange");
		expect(failure.kind).toBe("refused");
		expect(failure.code).toBe("invalid_argument");
		expect(failure.status).toBe(400);
		expect(failure.detail).toBeDefined();
		expect(reason(failure.detail as NonNullable<typeof failure.detail>)).toEqual({
			field: "catalog_rejection",
			value: "CATALOG_REJECTION_REASON_MALFORMED_ENTRY",
		});
	});

	it("drops host and content-length from the returned request", async () => {
		const { peer, client } = await fixture();
		await client({
			beforeSign: (req) => {
				const headers = new Headers(req.headers);
				headers.set("content-length", "3");
				return new Request(req.url, { method: "POST", headers, body: '{"exchange":"exchange.test"}' });
			},
		}).pushResources(push());
		const names = Object.keys(peer.only().request.headers).map((n) => n.toLowerCase());
		expect(names).not.toContain("content-length");
		expect(names).not.toContain("host");
		expect(peer.only().valid).toBe(true);
	});

	it("keeps a header the hook adds, outside the signature", async () => {
		const { peer, client } = await fixture();
		await client({
			beforeSign: (req) => {
				const headers = new Headers(req.headers);
				headers.set("x-probe", "1");
				return new Request(req.url, { method: "POST", headers, body: req.body, duplex: "half" } as RequestInit);
			},
		}).pushResources(push());
		expect(peer.only().request.headers["x-probe"]).toBe("1");
		expect(peer.only().valid).toBe(true);
	});

	describe("refuses locally, with nothing sent", () => {
		const cases: [string, ClientOptions["beforeSign"]][] = [
			[
				"a hook that throws",
				() => {
					throw new Error("boom");
				},
			],
			["a hook that returns something else", () => ({}) as Request],
			["a hook that changes the method", (req) => new Request(req.url, { method: "PUT", headers: req.headers })],
			[
				"a hook that changes the URL",
				async (req) => new Request("https://elsewhere.test/x", { method: "POST", body: await req.text() }),
			],
		];
		for (const name of ["Signature", "signature-input", "Content-Digest", "Signature-Agent", "AUTHORIZATION"]) {
			cases.push([
				`a hook that sets ${name}`,
				async (req) => {
					const headers = new Headers(req.headers);
					headers.set(name, "forged");
					return new Request(req.url, { method: "POST", headers, body: await req.text() });
				},
			]);
		}
		for (const [label, hook] of cases) {
			it(label, async () => {
				const { peer, client } = await fixture();
				const failure = await refusal(
					client(hook === undefined ? {} : { beforeSign: hook }).pushResources(push()),
				);
				expect(failure.kind).toBe("malformed");
				expect(failure.code).toBeUndefined();
				expect(peer.seen).toHaveLength(0);
			});
		}
	});

	it("runs without a signer, and the patched body is what goes out", async () => {
		const sent: string[] = [];
		const client = createCatalogClient("https://exchange.test", {
			send: async (req) => {
				sent.push(new TextDecoder().decode(req.body));
				return { status: 200, body: "{}" };
			},
			beforeSign: (req) => withBody(req, '{"patched":true}'),
		});
		await client.pushResources(push());
		expect(sent).toEqual(['{"patched":true}']);
	});
});
