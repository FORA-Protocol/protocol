// The guarded fetch's own redirect policy (followingRedirects in resolvers/http.ts), driven
// through an injected fetch against a real in-process origin.
//
// createGuardedFetch composes the address-pinning dispatcher, which follows nothing, with
// followingRedirects, which follows at most MAX_REDIRECTS hops and dials each one as its
// own request. The dispatcher refuses every loopback origin, so the policy is exercised
// here over a fetch that routes https://127.0.0.1 to the origin's plaintext listener, the
// way a deployment injects a transport to reach a private peer. The same function wraps the
// guarded dispatcher in production.

import { createServer, type Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import type { FetchLike } from "../resolvers/fetch.ts";
import { followingRedirects } from "../resolvers/http.ts";
import { MAX_REDIRECTS } from "../resolvers/ssrf.ts";
import { httpsLoopback, listenLoopback } from "./loopback-harness.ts";
import { httpsToLoopback } from "./resolvers-harness.ts";

let server: Server | undefined;

afterEach(async () => {
	await new Promise<void>((resolve) => (server ? server.close(() => resolve()) : resolve()));
	server = undefined;
});

/** An origin where /n redirects to /(n-1), relatively when `relative`, and /0 answers 200. */
async function redirectChain(relative: boolean): Promise<number> {
	let port = 0;
	server = createServer((req, res) => {
		const n = Number((req.url ?? "/0").slice(1));
		if (n <= 0) {
			res.writeHead(200).end("terminal");
			return;
		}
		const next = relative ? `/${n - 1}` : httpsLoopback(port, `/${n - 1}`);
		res.writeHead(302, { location: next }).end();
	});
	port = await listenLoopback(server);
	return port;
}

/** httpsToLoopback, counting the requests it is handed. */
function countingHop(): { hop: FetchLike; calls: () => number } {
	let count = 0;
	return {
		hop: (url, init) => {
			count += 1;
			return httpsToLoopback(url, init);
		},
		calls: () => count,
	};
}

describe("the guarded fetch's redirect policy", () => {
	it.each([false, true])("follows exactly MAX_REDIRECTS hops (relative Location: %s)", async (relative) => {
		const port = await redirectChain(relative);
		const { hop, calls } = countingHop();
		const resp = await followingRedirects(hop)(httpsLoopback(port, `/${MAX_REDIRECTS}`));
		expect(resp.status).toBe(200);
		expect(await resp.text()).toBe("terminal");
		expect(calls(), "each hop is its own request").toBe(MAX_REDIRECTS + 1);
	});

	it("answers with the 3xx past the cap and follows it no further", async () => {
		const port = await redirectChain(false);
		const { hop, calls } = countingHop();
		const resp = await followingRedirects(hop)(httpsLoopback(port, `/${MAX_REDIRECTS + 1}`));
		expect(resp.status).toBe(302);
		expect(calls()).toBe(MAX_REDIRECTS + 1);
	});

	it("is a single hop when the request asks for redirect: manual", async () => {
		const port = await redirectChain(false);
		const { hop, calls } = countingHop();
		const resp = await followingRedirects(hop)(httpsLoopback(port, "/3"), { redirect: "manual" });
		expect(resp.status).toBe(302);
		expect(calls()).toBe(1);
	});
});
