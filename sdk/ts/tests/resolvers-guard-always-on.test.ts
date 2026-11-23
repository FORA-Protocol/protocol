// The guarded fetch has no switch. SKIP_SSRF and ALLOW_INSECURE once turned its two checks
// off for a whole process; they are set here to prove nothing reads them any more. Every
// reserved address of the shared address corpus, and a plaintext URL, is refused by the
// guard, and a loopback listener standing in for the target records that no connection was
// made. Mirrors sdk/go/resolvers/guardedclient_test.go, with one documented divergence: the
// zoned rows are refused as unparseable URLs, not by the address check, as
// sdk/parity/corpus-row-divergences.json records.

import { createServer, type Server } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import addressVectorsFile from "../../go/resolvers/testdata/ssrf-address-vectors.json";
import rowDivergences from "../../parity/corpus-row-divergences.json";
import { DirectoryUnavailable } from "../resolvers/errors.ts";
import { createGuardedFetch, guardedFetch, guardedFetchFromEnv, SsrfBlockedError } from "../resolvers/http.ts";
import { createWBAKeyResolver } from "../resolvers/index.ts";
import { listenLoopback } from "./loopback-harness.ts";

/** The environment variables that used to relax the guard. */
const RETIRED_SWITCHES = ["SKIP_SSRF", "ALLOW_INSECURE"];

/** Every blocked row of the shared address corpus. */
const reservedRows = addressVectorsFile.vectors.filter((v) => v.blocked);
const reserved = reservedRows.map((v) => v.addr);

/** The rows this replay meets by another route than Go, as the shared divergence record
 * lists them: the zoned literals, which the WHATWG URL parser refuses, so the guarded
 * fetch refuses them as unparseable URLs and its address check never sees the zone. */
const PARSE_REFUSED = new Set(
	rowDivergences.divergences
		.filter((d) => d.port === "ts" && d.replay === "sdk/ts/tests/resolvers-guard-always-on.test.ts")
		.flatMap((d) => d.rows),
);
const ADDRESS_REFUSAL = /^SSRF guard: refusing to dial /;
const PARSE_REFUSAL = /^SSRF guard: unparseable url /;

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
 * written the RFC 6874 way, its "%" escaped as "%25". */
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

	// A set HTTP(S)_PROXY does not take a dial around the address guard. The proxy is a
	// loopback listener that counts connections. A guarded fetch that honoured the proxy
	// would dial it, so the refusal must name the target and the proxy see no connection.
	it("a set HTTP(S)_PROXY does not tunnel past the address guard", async () => {
		const proxy = await countingListener();
		for (const name of ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]) {
			vi.stubEnv(name, `http://127.0.0.1:${proxy.port}`);
		}
		try {
			const outcome = await createGuardedFetch()("https://10.0.0.1/", { signal: AbortSignal.timeout(2000) }).catch(
				(e: unknown) => e,
			);
			expect(outcome).toBeInstanceOf(SsrfBlockedError);
			expect(String(outcome)).toContain("10.0.0.1");
			expect(proxy.accepted(), "the guarded fetch must not dial the proxy").toBe(0);
		} finally {
			await new Promise<void>((resolve) => proxy.server.close(() => resolve()));
		}
	});

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

describe("the guarded fetch's refusal reason for each reserved row", () => {
	// Every reserved row is refused for its address, except the rows the divergence record
	// lists, which are refused as unparseable URLs. The set of rows refused that way must be
	// exactly the listed set, so the record cannot go stale and a parse refusal cannot hide
	// a row the address check should have refused.
	it("refuses every reserved row for its address, and the zoned rows as unparseable URLs", async () => {
		const { server, port, accepted } = await countingListener();
		const parseRefused: string[] = [];
		try {
			for (const row of reservedRows) {
				const outcome = await createGuardedFetch()(urlFor(row.addr, port), { signal: AbortSignal.timeout(2000) }).catch(
					(e: unknown) => e,
				);
				expect(outcome, row.name).toBeInstanceOf(SsrfBlockedError);
				const message = (outcome as Error).message;
				if (PARSE_REFUSAL.test(message)) parseRefused.push(`ssrf-address-vectors.json#${row.name}`);
				else expect(message, row.name).toMatch(ADDRESS_REFUSAL);
			}
			expect(PARSE_REFUSED.size, "the divergence record lists no row for this replay").toBeGreaterThan(0);
			expect(new Set(parseRefused)).toEqual(PARSE_REFUSED);
			expect(accepted(), "a refused target is never dialed").toBe(0);
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});
});
