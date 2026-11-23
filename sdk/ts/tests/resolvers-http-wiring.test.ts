// The read's wiring over a real socket, which the address corpus cannot express as data:
// a non-2xx is surfaced as a status rather than a crash, the redirect chain is bounded to the
// shared cap, and a redirect out of https is refused. Cross-language parity: sdk/go
// TestGuardedClientSurfacesNon2xx / TestGuardedClientRedirectDepthCap /
// TestGuardedClientRefusesRedirectScheme and sdk/python test_guarded_client_non_2xx… /
// …refuses_redirect_to_ftp.
//
// A document read asks the transport not to follow and follows redirects itself (fetch.ts),
// calling the transport once per hop, so the read's own cap and scheme checks apply whatever
// transport it is given. The in-process origin is a loopback listener, which the guarded
// default refuses with no switch to turn that off, so the suite reaches it through an
// injected transport (httpsToLoopback), the way a deployment reaches a private origin.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { describe, expect, it } from "vitest";

import { DirectoryUnavailable } from "../resolvers/errors.ts";
import { fetchSoft, fetchStrict } from "../resolvers/http.ts";
import { MAX_REDIRECTS } from "../resolvers/ssrf.ts";
import { httpsLoopback } from "./loopback-harness.ts";
import { httpsToLoopback } from "./resolvers-harness.ts";

async function listen(server: Server): Promise<string> {
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	return httpsLoopback((server.address() as AddressInfo).port);
}

async function close(server: Server): Promise<void> {
	await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** An origin that answers every request with a 302 to `location`. */
function redirectingTo(location: string): Server {
	return createServer((_req, res) => {
		res.writeHead(302, { location });
		res.end();
	});
}

describe("the read over a real socket", () => {
	it("surfaces a non-2xx as a status, and the taxonomy classifies it (no crash)", async () => {
		// Regression parity with Python's opener bug: a non-2xx must not throw an unmapped
		// error. fetchStrict maps it to a fail-closed outage; fetchSoft drops the refresh
		// (revocation poller safe).
		const server = createServer((_req, res) => {
			res.writeHead(404);
			res.end("nope");
		});
		const url = `${await listen(server)}/.well-known/x`;
		try {
			await expect(fetchStrict(httpsToLoopback, url)).rejects.toBeInstanceOf(DirectoryUnavailable);
			expect(await fetchSoft(httpsToLoopback, url)).toBeUndefined();
		} finally {
			await close(server);
		}
	});

	// A redirect to an internal address mid-chain is not replayed here: every redirect hop
	// dials through the same guarded connector, whose refusal of a reserved address the
	// shared address corpus pins through guardedFetchFromEnv (resolvers-guard-always-on).

	it("bounds the redirect chain to the shared cap (follows at the cap, refuses one over)", async () => {
		// /n redirects to /(n-1); /0 is the terminal 200.
		const server = createServer((req, res) => {
			const n = Number.parseInt((req.url ?? "/0").slice(1), 10) || 0;
			if (n <= 0) {
				res.writeHead(200);
				res.end("ok");
				return;
			}
			res.writeHead(302, { location: `/${n - 1}` });
			res.end();
		});
		const base = await listen(server);
		try {
			expect(await fetchStrict(httpsToLoopback, `${base}/${MAX_REDIRECTS}`)).toBe("ok");
			await expect(fetchStrict(httpsToLoopback, `${base}/${MAX_REDIRECTS + 1}`)).rejects.toBeInstanceOf(
				DirectoryUnavailable,
			);
		} finally {
			await close(server);
		}
	});

	it("refuses a redirect out of https (deny-by-default)", async () => {
		const refusals: [string, RegExp][] = [
			["ftp://ftp.example.com/secret", /a redirect to a ftp: URL/],
			["http://plain.example.com/secret", /a redirect from https to plaintext http/],
		];
		for (const [location, reason] of refusals) {
			const server = redirectingTo(location);
			const url = await listen(server);
			try {
				const err = await fetchStrict(httpsToLoopback, url).catch((e: unknown) => e);
				expect(err, location).toBeInstanceOf(DirectoryUnavailable);
				expect(String(err), location).toMatch(reason);
			} finally {
				await close(server);
			}
		}
	});
});
