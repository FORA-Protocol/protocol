// The guarded fetch has no switch. SKIP_SSRF and ALLOW_INSECURE once turned its two checks
// off for a whole process; they are set here to prove nothing reads them any more. Every
// reserved address of the shared address corpus, and a plaintext URL, is refused by the
// guard, and a loopback listener standing in for the target records that no connection was
// made. Mirrors sdk/go/resolvers/guardedclient_test.go.

import { createServer, type Server } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import addressVectorsFile from "../../go/resolvers/testdata/ssrf-address-vectors.json";
import { DirectoryUnavailable } from "../resolvers/errors.ts";
import { createGuardedFetch, guardedFetch, guardedFetchFromEnv, SsrfBlockedError } from "../resolvers/http.ts";
import { createWBAKeyResolver } from "../resolvers/index.ts";
import { listenLoopback } from "./loopback-harness.ts";

/** The environment variables that used to relax the guard. */
const RETIRED_SWITCHES = ["SKIP_SSRF", "ALLOW_INSECURE"];

/** Every blocked row of the shared address corpus. */
const reserved = addressVectorsFile.vectors.filter((v) => v.blocked).map((v) => v.addr);

/** A loopback listener on a free port that counts the connections it accepts. */
async function countingListener(): Promise<{ server: Server; port: number; accepted: () => number }> {
	let count = 0;
	const server = createServer((socket) => {
		count += 1;
		socket.destroy();
	});
	const port = await listenLoopback(server);
	return { server, port, accepted: () => count };
}

/** The https URL of `addr` on `port`. An IPv6 literal is bracketed, and a zone in it is
 * written the RFC 6874 way, its "%" escaped as "%25". The WHATWG URL parser accepts no
 * zone, so for those rows the guard refuses the URL as unparseable, with the same
 * SsrfBlockedError and still before any connection. */
function urlFor(addr: string, port: number): string {
	return `https://${addr.includes(":") ? `[${addr.replaceAll("%", "%25")}]` : addr}:${port}/`;
}

describe("the guarded fetch, with the retired switches set", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
	});

	it("refuses every reserved address and every plaintext URL without a connection", async () => {
		expect(reserved.length, "the corpus has no reserved row").toBeGreaterThan(0);
		for (const name of RETIRED_SWITCHES) vi.stubEnv(name, "true");
		const { server, port, accepted } = await countingListener();
		const urls = [...reserved.map((addr) => urlFor(addr, port)), `http://127.0.0.1:${port}/`, "http://example.com/"];
		try {
			// The deprecated name and the module's shared instance are the same fetch, so they
			// are held to the same refusals.
			for (const fetchFn of [createGuardedFetch(), guardedFetchFromEnv(), guardedFetch]) {
				for (const url of urls) {
					const outcome = await fetchFn(url, { signal: AbortSignal.timeout(2000) }).catch((e: unknown) => e);
					expect(outcome, url).toBeInstanceOf(SsrfBlockedError);
				}
			}
			expect(accepted(), "a refused target is never dialed").toBe(0);
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	}, 60_000);

	// The key resolver's default is the module's shared guarded transport; this pins that
	// the resolver really dials through it: a plaintext directory is refused for its
	// scheme, before the address check would refuse the loopback host.
	it("the WBA key resolver's default refuses a plaintext directory for its scheme", async () => {
		for (const name of RETIRED_SWITCHES) vi.stubEnv(name, "true");
		const { server, port, accepted } = await countingListener();
		try {
			const err = await createWBAKeyResolver()
				.resolve("tp", `http://127.0.0.1:${port}`)
				.catch((e: unknown) => e);
			expect(err).toBeInstanceOf(DirectoryUnavailable);
			expect(String((err as Error).cause)).toMatch(/disallowed scheme/);
			expect(accepted(), "a refused directory is never dialed").toBe(0);
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});
});
