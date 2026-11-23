// The client negotiates identity encoding, and refuses a coding it did not ask for.
//
// Mirrors sdk/python/tests/test_client_bounds.py's encoding cases.
//
// Streaming under a running total is not by itself a bound. A decoder expands a whole raw
// read at once, so one decoded chunk can be far past the cap before the total can refuse
// it — measured in Python at 70 MiB of growth against a 1 MiB cap. Refusing a coding the
// client never negotiated is the check that holds at any chunk size.
//
// TypeScript has the same exposure from the other direction: undici does NOT decode a
// content coding, and per RFC 9110 §12.5.3 an absent Accept-Encoding means any coding is
// acceptable — so a client that sent nothing would be handed gzip octets, fail to parse
// them, and report the peer's fault for something the peer was entitled to do.

import { createServer, type Server } from "node:http";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { fetchContent } from "../client/content.ts";
import { ForaCallError } from "../client/errors.ts";
import { createUnarySend } from "../client/send.ts";
import { type UnaryRequest, unaryCall } from "../client/transport.ts";
import { httpsLoopback, listenLoopback, loopbackDispatcher } from "./loopback-harness.ts";

/** Serves what the test asks for, and records what the client negotiated. */
async function serving(
	body: Buffer,
	headers: Record<string, string>,
): Promise<[Server, number, () => string | undefined]> {
	let negotiated: string | undefined;
	const server = createServer((req, res) => {
		negotiated = req.headers["accept-encoding"] as string | undefined;
		res.writeHead(200, { "content-type": "application/json", ...headers });
		res.end(body);
	});
	return [server, await listenLoopback(server), () => negotiated];
}

function unaryRequest(url: string): UnaryRequest {
	return {
		url,
		op: "discover",
		headers: { "content-type": "application/json" },
		body: new TextEncoder().encode("{}"),
		signal: new AbortController().signal,
		maxBytes: 1 << 20,
	};
}

// The RPC cases dial through the configured leg's default send, which reaches the loopback
// listener as given; the delivery cases address it over https and inject the routing
// dispatcher, the way a deployment reaches a private edge.
async function fetchFrom(port: number): Promise<unknown> {
	const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	return fetchContent(httpsLoopback(port, "/x"), {
		keyPair: keys,
		signatureAgent: "https://agent.test",
		dispatcher: loopbackDispatcher(),
	}).catch((e: unknown) => e);
}

/** A coding the client did not negotiate is refused as malformed, and says so. */
function expectCodingRefused(failure: unknown): void {
	expect(failure).toBeInstanceOf(ForaCallError);
	expect((failure as ForaCallError).kind).toBe("malformed");
	expect(String((failure as ForaCallError).cause ?? "")).toContain("content-encoding");
}

describe("content coding", () => {
	// Driven through unaryCall, which owns the header set: an injected send is handed the
	// headers this tier built, so the negotiation reaches the wire either way.
	it("the client asks for identity rather than sending nothing", async () => {
		const [server, port, negotiated] = await serving(Buffer.from("{}"), {});
		await unaryCall({
			op: "discover",
			target: {
				baseURL: `http://127.0.0.1:${port}`,
				service: "fora.v1.ExchangeService",
				method: "DiscoverResources",
			},
			message: {},
			send: createUnarySend({ guarded: false }),
		});
		expect(negotiated()).toBe("identity");
		server.close();
	});

	// The delivery leg builds its own header set, so it is asserted separately.
	it("the delivery leg asks for identity too", async () => {
		const [server, port, negotiated] = await serving(Buffer.from("body"), {});
		await fetchFrom(port);
		expect(negotiated()).toBe("identity");
		server.close();
	});

	it("a coding the client did not negotiate is refused", async () => {
		// 200 MiB of gzip: undici would hand this back as raw octets, and no running total
		// over them would say anything useful about the answer.
		const bomb = gzipSync(Buffer.alloc(200 * 1024 * 1024, 0x41));
		const [server, port] = await serving(bomb, { "content-encoding": "gzip" });
		const failure = await createUnarySend({ guarded: false })(unaryRequest(`http://127.0.0.1:${port}/x`)).catch(
			(e: unknown) => e,
		);
		expectCodingRefused(failure);
		server.close();
	});

	// The DELIVERY leg, which the cases above do not reach. Its refusal path carries the
	// tightest bound in the client — 4 KiB — so it is the site an unnegotiated coding
	// overshoots furthest, and it was the one with no test at all.
	it("the delivery leg refuses one too", async () => {
		const bomb = gzipSync(Buffer.alloc(64 * 1024 * 1024, 0x41));
		const [server, port] = await serving(bomb, { "content-encoding": "gzip" });
		const failure = await fetchFrom(port);
		expectCodingRefused(failure);
		server.close();
	});

	it("an identity coding, and no coding at all, are both fine", async () => {
		for (const headers of [{ "content-encoding": "identity" }, {}]) {
			const [server, port] = await serving(Buffer.from('{"ver":"1.0"}'), headers);
			const response = await createUnarySend({ guarded: false })(unaryRequest(`http://127.0.0.1:${port}/x`));
			expect(response.status).toBe(200);
			server.close();
		}
	});
});
