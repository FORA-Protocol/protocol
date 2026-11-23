// What the shared corpus does not carry about the endpoint resolver's DEFAULT transport.
// Which outcome the default gives for a loopback, private or link-local address and for
// plain http is pinned across the three languages by resolver-default-vectors.json
// (resolver-defaults.parity.test.ts). The cases here are the ones that corpus does not
// express: a host NAME that resolves to a reserved address, IPv4 and IPv6, rather than an
// IP literal, and an injected transport used exactly as given. Python pins the same cases
// in test_resolvers_wellknown_endpoint_guarded_default.py.
//
// Nothing in the SDK is mocked. Node's own node:dns/promises answers a few .example names
// with reserved addresses, so a private or link-local answer can be driven without a
// listener on that address.
import { createServer, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { dnsAnswers } = vi.hoisted(() => ({ dnsAnswers: new Map<string, string>() }));

vi.mock("node:dns/promises", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:dns/promises")>();
	const lookup = (async (host: string, opts?: unknown) => {
		const address = dnsAnswers.get(host);
		if (address === undefined) return actual.lookup(host, opts as never);
		return [{ address, family: address.includes(":") ? 6 : 4 }];
	}) as typeof actual.lookup;
	return { ...actual, lookup, default: { ...actual, lookup } };
});

import { createWellKnownEndpointResolver, DirectoryUnavailable, SsrfBlockedError } from "../resolvers/index.ts";
import { loopbackFetch } from "./resolvers-harness.ts";

const TOUCHED = ["SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"];
let saved: Record<string, string | undefined>;

beforeEach(() => {
	saved = {};
	for (const k of TOUCHED) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
	dnsAnswers.clear();
});

afterEach(() => {
	for (const k of TOUCHED) {
		if (saved[k] === undefined) delete process.env[k];
		else process.env[k] = saved[k];
	}
});

/** A loopback origin that serves a manifest naming itself, and counts the requests it answers. */
interface Origin {
	host: string;
	requests: () => number;
	close: () => Promise<void>;
}

async function startOrigin(): Promise<Origin> {
	let requests = 0;
	const sockets = new Set<Socket>();
	const server: Server = createServer((req, res) => {
		requests += 1;
		const host = req.headers.host ?? "";
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ ver: "1.0", role: "ROLE_EXCHANGE", endpoint: `http://${host}/fora.v1.ExchangeService` }));
	});
	server.on("connection", (socket) => {
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const { port } = server.address() as AddressInfo;
	return {
		host: `127.0.0.1:${port}`,
		requests: () => requests,
		close: async () => {
			for (const s of sockets) s.destroy();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}

/** The rejection a resolve ends in, asserted to be a guard refusal: a DirectoryUnavailable
 * (a failed read, the only retryable exit) caused by the guarded transport's
 * SsrfBlockedError, so a refusal for any other reason does not pass. */
async function expectGuardRefusal(resolve: Promise<unknown>): Promise<SsrfBlockedError> {
	const err = await resolve.then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err).toBeInstanceOf(DirectoryUnavailable);
	const cause = (err as { cause?: unknown }).cause;
	expect(cause).toBeInstanceOf(SsrfBlockedError);
	return cause as SsrfBlockedError;
}

describe("createWellKnownEndpointResolver default transport", () => {
	for (const [name, address] of [
		["private IPv4 (10/8)", "10.0.0.5"],
		["private IPv4 (192.168/16)", "192.168.1.10"],
		["link-local IPv4 (cloud metadata)", "169.254.169.254"],
		["unique-local IPv6", "fd00::1"],
		["link-local IPv6", "fe80::1"],
	] as const) {
		it(`refuses an Exchange whose name resolves to a ${name} address`, async () => {
			process.env.ALLOW_INSECURE = "1";
			dnsAnswers.set("exchange.example", address);
			const r = createWellKnownEndpointResolver({ scheme: "http" });
			const refusal = await expectGuardRefusal(r.resolveEndpoint("exchange.example"));
			// The generic refusal: it names the host, never the address it resolved to.
			expect(refusal.message).toBe("SSRF guard: refusing to dial exchange.example");
		});
	}

	it("uses an injected transport exactly as given, with no guard of its own", async () => {
		// No flags are set, so the guarded default would refuse this loopback origin: only
		// the injected transport, used as given, can reach it.
		const origin = await startOrigin();
		const asked: string[] = [];
		try {
			const r = createWellKnownEndpointResolver({
				scheme: "http",
				fetch: (url) => {
					asked.push(url);
					return loopbackFetch(url);
				},
			});
			expect(await r.resolveEndpoint(origin.host)).toBe(`http://${origin.host}/fora.v1.ExchangeService`);
			expect(asked).toEqual([`http://${origin.host}/.well-known/fora.json`]);
		} finally {
			await origin.close();
		}
	});
});
