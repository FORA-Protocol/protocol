import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createWBAOfferDirectoryFetch } from "../resolvers/index.ts";

// Which transport a resolver takes when the caller injects none, for the one face the
// shared corpus cannot carry.
//
// The rule is that a resolver's default follows its URL's PROVENANCE: a fixed,
// operator-chosen address takes the plain transport, a host another party named takes
// the guarded one (the Go oracle's WellKnownOptions.HTTP comment). Every face whose
// outcome reads the same through all three public surfaces is pinned by the shared
// corpus resolver-default-vectors.json, replayed in resolver-defaults.parity.test.ts.
//
// The offer-directory fetch is the exception. Its default is guarded in all three
// languages, but this seam contains every failure as "no directory" (undefined) where
// Go returns the error, so the refusal a corpus row records is not observable here.
// What every language can observe is the socket: the guarded default never connects
// to a loopback listener. Each language pins that in its own copy of this test.
//
// CHANGING THIS OBLIGES A CHECK OF THE License.uri SSRF GUARDS in
// proto/fora/v1/fora.proto and Licensing Terms
// (website/src/content/docs/protocol/licensing-terms.mdx), which say what a consumer
// must apply before it fetches a URL another party named.

const TOUCHED = ["SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"];
let saved: Record<string, string | undefined>;

// The flags are cleared rather than inherited from the shell, and ALLOW_INSECURE is set
// so the scheme guard is not what refuses the plaintext listener: the address guard must.
beforeEach(() => {
	saved = {};
	for (const k of TOUCHED) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
	process.env.ALLOW_INSECURE = "1";
});

afterEach(() => {
	for (const k of TOUCHED) {
		if (saved[k] === undefined) delete process.env[k];
		else process.env[k] = saved[k];
	}
});

describe("resolver transport defaults", () => {
	it("offer-directory fetch dials guarded", async () => {
		let connections = 0;
		const server: Server = createServer((_req, res) => {
			res.writeHead(404);
			res.end();
		});
		server.on("connection", () => {
			connections += 1;
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		const { port } = server.address() as AddressInfo;
		try {
			// The result is deliberately not read: the seam answers undefined for a refusal
			// and a failed read alike, and `connections` is what says which happened.
			await createWBAOfferDirectoryFetch({ scheme: "http" })(`127.0.0.1:${port}`);
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
		expect(
			connections,
			"the offer-directory fetch's default transport reached a loopback origin; its exchange " +
				"domain comes off an offer, so the default must be the guarded transport",
		).toBe(0);
	});
});
