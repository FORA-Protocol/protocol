// The guarded fetch's own redirect policy (followingRedirects in resolvers/http.ts), driven
// through an injected fetch against a real in-process origin.
//
// createGuardedFetch composes the address-pinning dispatcher, which follows nothing, with
// followingRedirects, which follows at most MAX_REDIRECTS hops and dials each one as its
// own request. The dispatcher refuses every loopback origin, so the policy is exercised
// here over a fetch that routes https://127.0.0.1 to the origin's plaintext listener, the
// way a deployment injects a transport to reach a private peer. The same function wraps the
// guarded dispatcher in production, and the last cases drive createGuardedFetch() itself.

import { createServer, type Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import addressVectorsFile from "../../go/resolvers/testdata/ssrf-address-vectors.json";
import type { FetchLike } from "../resolvers/fetch.ts";
import { createGuardedFetch, followingRedirects, SsrfBlockedError } from "../resolvers/http.ts";
import { MAX_REDIRECTS } from "../resolvers/ssrf.ts";
import { httpsLoopback, listenLoopback, routeTlsDial } from "./loopback-harness.ts";
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

/** A public IPv4 row of the shared address corpus, which the guard dials. */
const PUBLIC = addressVectorsFile.vectors.find((v) => v.name === "public_v4_example");

/** An origin on a free loopback port where /n redirects to /(n-1) at `PUBLIC`, /0 answers
 * 200 and /plain redirects to the http URL of /0. Returns the port and the request count. */
async function publicRedirectChain(address: string): Promise<{ port: number; requests: () => number }> {
	let port = 0;
	let count = 0;
	server = createServer((req, res) => {
		count += 1;
		const path = req.url ?? "/0";
		const n = Number(path.slice(1));
		if (path === "/plain") res.writeHead(302, { location: `http://${address}:${port}/0` }).end();
		else if (n <= 0) res.writeHead(200).end("terminal");
		else res.writeHead(302, { location: `https://${address}:${port}/${n - 1}` }).end();
	});
	port = await listenLoopback(server);
	return { port, requests: () => count };
}

// createGuardedFetch() itself, with no injected fetch: the guard dials the corpus's public
// address, and routeTlsDial carries that dial to the in-process origin. So these cases fail
// if createGuardedFetch stops composing followingRedirects over its dispatcher.
describe("createGuardedFetch's own redirect policy", () => {
	it("follows MAX_REDIRECTS hops and answers with the 3xx past the cap", async () => {
		expect(PUBLIC?.blocked, "the corpus has no public row public_v4_example").toBe(false);
		const address = PUBLIC?.addr ?? "";
		const { port, requests } = await publicRedirectChain(address);
		const restore = routeTlsDial(address, port);
		try {
			const fetchFn = createGuardedFetch();
			const within = await fetchFn(`https://${address}:${port}/${MAX_REDIRECTS}`);
			expect(within.status).toBe(200);
			expect(requests(), "each hop is its own request").toBe(MAX_REDIRECTS + 1);
			const past = await fetchFn(`https://${address}:${port}/${MAX_REDIRECTS + 1}`);
			expect(past.status, "the hop past the cap is not followed").toBe(302);
			expect(requests()).toBe(2 * (MAX_REDIRECTS + 1));
		} finally {
			restore();
		}
	});

	it("refuses a redirect to http without dialing it", async () => {
		const address = PUBLIC?.addr ?? "";
		const { port, requests } = await publicRedirectChain(address);
		const restore = routeTlsDial(address, port);
		try {
			const outcome = await createGuardedFetch()(`https://${address}:${port}/plain`).catch((e: unknown) => e);
			expect(outcome).toBeInstanceOf(SsrfBlockedError);
			expect(String(outcome)).toMatch(/disallowed scheme http:/);
			expect(requests(), "only the redirecting hop reached the origin").toBe(1);
		} finally {
			restore();
		}
	});
});
