// ForaCallError.headers: the header fields of a refusal, and only of a refusal.
//
// A peer's error answer says what it wants next in its header fields: a Web Bot Auth
// verifier names the signature it requires in Accept-Signature, a draining gateway sets
// Retry-After, a delivery edge's 403 carries the discovery headers. `headers` carries them
// for an answer of status 400 or above, on both legs. Every other failure carries none: a
// local one, a transport one, a 2xx this client could not read, and a refused redirect,
// whose Location names a URL the peer chose.
//
// The constructor owns the rule, so every case below is the same rule seen from a different
// site that builds the failure. Mirrors sdk/python/tests/test_call_error_headers.py.
import { createServer, type OutgoingHttpHeaders, type Server } from "node:http";
import { describe, expect, it } from "vitest";

import { fetchContent } from "../client/content.ts";
import { ForaCallError } from "../client/errors.ts";
import { createUnarySend } from "../client/send.ts";
import { answerHeaders, decodeResponse, unaryCall, type UnaryResponse } from "../client/transport.ts";
import { acceptSignature } from "../core/wba.ts";
import { parseDiscoveryHint } from "../src/discovery-hint.ts";
import { POP_ACCEPT_SIGNATURE } from "../src/pop.ts";
import { AcceptSignatureHeader, ContentRulesHeader, ExchangeHeader } from "../src/wire.ts";

const UNAUTHENTICATED = JSON.stringify({ code: "unauthenticated", message: "the request is not signed" });
// A value no message carries by accident, so its absence from `message` is evidence.
const PROBE = "probe-6c1f0e";

function caught(run: () => unknown): ForaCallError {
	try {
		run();
	} catch (err) {
		expect(err).toBeInstanceOf(ForaCallError);
		return err as ForaCallError;
	}
	throw new Error("expected a ForaCallError");
}

async function caughtAsync(run: () => Promise<unknown>): Promise<ForaCallError> {
	const err = await run().then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(ForaCallError);
	return err as ForaCallError;
}

function expectNotRendered(err: ForaCallError): void {
	for (const [name, value] of err.headers) {
		expect(err.message, `the message renders ${name}`).not.toContain(value);
	}
}

function answer(status: number, body: string, fields: Record<string, string> = {}): UnaryResponse {
	return { status, body, headers: new Headers(fields) };
}

describe("the rule, at the constructor", () => {
	for (const status of [undefined, 200, 204, 302, 304, 399]) {
		it(`status ${String(status)} carries no fields`, () => {
			const err = new ForaCallError({
				kind: "refused",
				op: "op",
				...(status !== undefined ? { status } : {}),
				headers: new Headers({ "X-Probe": PROBE }),
			});
			expect([...err.headers]).toEqual([]);
		});
	}

	for (const status of [400, 401, 403, 429, 503]) {
		it(`status ${status} carries a copy of its fields`, () => {
			const fields = new Headers({ "X-Probe": PROBE });
			const err = new ForaCallError({ kind: "refused", op: "op", status, headers: fields });
			fields.set("X-Probe", "changed");
			expect(err.headers.get("X-Probe")).toBe(PROBE);
			// Read case-insensitively, as HTTP header fields are.
			expect(err.headers.get("x-probe")).toBe(PROBE);
		});
	}

	it("no fields given carries none", () => {
		expect([...new ForaCallError({ kind: "refused", op: "op", status: 401 }).headers]).toEqual([]);
	});

	it("the fields are never rendered", () => {
		const err = new ForaCallError({
			kind: "refused",
			op: "op",
			status: 401,
			headers: new Headers({ "X-Probe": PROBE }),
		});
		expectNotRendered(err);
	});
});

describe("answerHeaders", () => {
	it("reads a field sent on several lines as one joined value", () => {
		const headers = answerHeaders({ "x-probe": [`${PROBE}-first`, `${PROBE}-second`] });
		expect(headers.get("X-Probe")).toBe(`${PROBE}-first, ${PROBE}-second`);
	});

	it("leaves out a value the Headers type cannot hold, and keeps the rest", () => {
		// undici decodes values as UTF-8; Headers refuses a character above U+00FF.
		const headers = answerHeaders({ "x-euro": "price €", "x-probe": PROBE, "x-absent": undefined });
		expect(headers.get("x-euro")).toBeNull();
		expect(headers.get("x-absent")).toBeNull();
		expect(headers.get("x-probe")).toBe(PROBE);
	});
});

describe("every site that builds a failure from an RPC answer", () => {
	it("an envelope refusal names what the verifier requires", () => {
		const err = caught(() =>
			decodeResponse("discover", answer(401, UNAUTHENTICATED, { [AcceptSignatureHeader]: acceptSignature(false) })),
		);
		expect(err.kind).toBe("refused");
		expect(err.status).toBe(401);
		expect(err.headers.get(AcceptSignatureHeader)).toBe(acceptSignature(false));
		expectNotRendered(err);
	});

	it("a draining gateway says when to come back", () => {
		const err = caught(() => decodeResponse("discover", answer(503, "draining", { "retry-after": "86400" })));
		expect(err.kind).toBe("unreachable");
		expect(err.headers.get("Retry-After")).toBe("86400");
	});

	it("a strictly refused envelope keeps its fields", () => {
		const envelope = JSON.stringify({ code: "unauthenticated", message: "not signed", bogus: true });
		const err = caught(() =>
			decodeResponse("discover", answer(401, envelope, { [AcceptSignatureHeader]: acceptSignature(false) }), true),
		);
		expect(err.kind).toBe("malformed");
		expect(err.code).toBe("unauthenticated");
		expect(err.status).toBe(401);
		expect(err.headers.get(AcceptSignatureHeader)).toBe(acceptSignature(false));
	});

	it("a refusal nested too deep keeps its fields", () => {
		const err = caught(() => decodeResponse("discover", answer(400, "[".repeat(40) + "]".repeat(40), { "x-probe": PROBE })));
		expect(err.kind).toBe("malformed");
		expect(err.status).toBe(400);
		expect(err.headers.get("x-probe")).toBe(PROBE);
	});

	it("a refused redirect carries no fields", () => {
		const err = caught(() =>
			decodeResponse(
				"discover",
				answer(302, "", { location: `https://elsewhere.test/next?token=${PROBE}`, "x-probe": PROBE }),
			),
		);
		expect(err.kind).toBe("unreachable");
		expect(err.status).toBe(302);
		expect([...err.headers]).toEqual([]);
	});

	it("a 2xx that is not JSON carries no fields", () => {
		const err = caught(() => decodeResponse("discover", answer(200, "<html></html>", { "x-probe": PROBE })));
		expect(err.kind).toBe("malformed");
		expect([...err.headers]).toEqual([]);
	});

	it("a send that returns no fields yields a refusal carrying none", () => {
		const err = caught(() => decodeResponse("discover", { status: 401, body: UNAUTHENTICATED }));
		expect(err.status).toBe(401);
		expect([...err.headers]).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// Over a real socket, through the default send
// ---------------------------------------------------------------------------

async function serving(status: number, body: string, headers: OutgoingHttpHeaders): Promise<[Server, number]> {
	const server = createServer((_req, res) => {
		for (const [name, value] of Object.entries(headers)) {
			if (value !== undefined) res.setHeader(name, value);
		}
		res.writeHead(status);
		res.end(body);
	});
	await new Promise<void>((done) => server.listen(0, "127.0.0.1", () => done()));
	return [server, (server.address() as { port: number }).port];
}

async function withLoopback<T>(run: () => Promise<T>): Promise<T> {
	const saved = [process.env["SKIP_SSRF"], process.env["ALLOW_INSECURE"]];
	process.env["SKIP_SSRF"] = "true";
	process.env["ALLOW_INSECURE"] = "true";
	try {
		return await run();
	} finally {
		if (saved[0] === undefined) delete process.env["SKIP_SSRF"];
		else process.env["SKIP_SSRF"] = saved[0];
		if (saved[1] === undefined) delete process.env["ALLOW_INSECURE"];
		else process.env["ALLOW_INSECURE"] = saved[1];
	}
}

function discoverAt(port: number): Promise<unknown> {
	return withLoopback(() =>
		unaryCall({
			op: "discover",
			target: { baseURL: `http://127.0.0.1:${port}`, service: "fora.v1.ExchangeService", method: "DiscoverResources" },
			message: {},
			send: createUnarySend({ guarded: true }),
		}),
	);
}

describe("the RPC leg, over a socket", () => {
	it("a refusal carries its Accept-Signature", async () => {
		const [server, port] = await serving(401, UNAUTHENTICATED, {
			"content-type": "application/json",
			[AcceptSignatureHeader]: acceptSignature(false),
		});
		const err = await caughtAsync(() => discoverAt(port));
		server.close();
		expect(err.status).toBe(401);
		expect(err.headers.get(AcceptSignatureHeader)).toBe(acceptSignature(false));
	});

	it("a field sent on two lines reads as one joined value", async () => {
		const [server, port] = await serving(400, JSON.stringify({ code: "invalid_argument", message: "no" }), {
			"content-type": "application/json",
			"x-probe": [`${PROBE}-first`, `${PROBE}-second`],
		});
		const err = await caughtAsync(() => discoverAt(port));
		server.close();
		expect(err.headers.get("X-Probe")).toBe(`${PROBE}-first, ${PROBE}-second`);
	});

	it("a refusal in a coding it was not asked for keeps its fields", async () => {
		const [server, port] = await serving(401, "\u001f\u008b", { "content-encoding": "gzip", "x-probe": PROBE });
		const err = await caughtAsync(() => discoverAt(port));
		server.close();
		expect(err.kind).toBe("malformed");
		expect(err.status).toBe(401);
		expect(err.headers.get("x-probe")).toBe(PROBE);
	});
});

describe("the delivery fetch, over a socket", () => {
	async function fetchFrom(port: number): Promise<ForaCallError> {
		const keyPair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
		return caughtAsync(() =>
			withLoopback(() =>
				fetchContent(`http://127.0.0.1:${port}/doc`, { keyPair, signatureAgent: "https://agent.test" }),
			),
		);
	}

	it("a refused proof is asked for again", async () => {
		const [server, port] = await serving(401, JSON.stringify({ error: "unauthorized", reason: "pop_sig_invalid" }), {
			"content-type": "application/json",
			[AcceptSignatureHeader]: POP_ACCEPT_SIGNATURE,
		});
		const err = await fetchFrom(port);
		server.close();
		expect(err.status).toBe(401);
		expect(err.headers.get(AcceptSignatureHeader)).toBe(POP_ACCEPT_SIGNATURE);
		expectNotRendered(err);
	});

	it("a 403 names where the terms are", async () => {
		const rules = "https://publisher.test/.well-known/fora.json";
		const [server, port] = await serving(403, JSON.stringify({ error: "forbidden" }), {
			"content-type": "application/json",
			[ContentRulesHeader]: rules,
			[ExchangeHeader]: "exchange.test",
		});
		const err = await fetchFrom(port);
		server.close();
		const hint = parseDiscoveryHint(err.status ?? 0, err.headers);
		expect([hint.contentRules, hint.contentRulesState]).toEqual([rules, "valid"]);
		expect([hint.exchange, hint.exchangeState]).toEqual(["exchange.test", "valid"]);
	});

	it("a redirect carries no fields", async () => {
		const [server, port] = await serving(302, "", {
			location: `https://elsewhere.test/doc?token=${PROBE}`,
			"x-probe": PROBE,
		});
		const err = await fetchFrom(port);
		server.close();
		expect(err.kind).toBe("unreachable");
		expect([...err.headers]).toEqual([]);
	});
});
