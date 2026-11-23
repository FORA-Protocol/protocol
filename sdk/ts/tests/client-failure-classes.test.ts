// Two classifications the three languages have to agree on, and one value shape.
//
// Each was a place one language answered differently for a reason nobody chose, and each
// changes what a caller does next: a verdict is final and a transport failure is worth
// retrying, so collapsing them either strands a usage report or retries a refusal forever.

import { randomBytes } from "node:crypto";

import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { fetchContent } from "../client/content.ts";
import { ForaCallError } from "../client/errors.ts";
import { decodeResponse } from "../client/transport.ts";
import { httpsLoopback, listenLoopback, loopbackDispatcher } from "./loopback-harness.ts";

describe("a redirect this client refused to follow", () => {
	// Every leg refuses redirects, so a 3xx reaching the decode means the server did not
	// answer the call rather than declining it — which is what all three failure
	// taxonomies already document a redirect as. connect-go maps these to CodeUnknown but
	// never sees one, because its transport follows them.
	for (const status of [301, 302, 303, 307, 308]) {
		it(`${status} is unreachable, not refused`, () => {
			let thrown: unknown;
			try {
				decodeResponse("discover", { status, body: "" });
			} catch (e) {
				thrown = e;
			}
			expect(thrown).toBeInstanceOf(ForaCallError);
			expect((thrown as ForaCallError).kind).toBe("unreachable");
		});
	}
});

describe("the DELIVERY leg's own failures", () => {
	// The answer arrives and then goes wrong under the read — the deadline fires mid-body,
	// or the connection resets. Both raise the dialing library's own error, and this leg
	// used to have no catch, so it escaped past every caller branching on the contract this
	// package states. Measured before the fix: a bare DOMException.
	it("classify a mid-body deadline instead of raising the dialer's own error", async () => {
		const body = randomBytes(8 << 20);
		const server = createServer((_req, res) => {
			res.writeHead(200, {
				"content-type": "text/plain",
				"content-length": String(body.length),
			});
			// Headers and a first chunk, then nothing: the read is still open when the
			// client's own deadline fires.
			res.write(body.subarray(0, 1024));
		});
		const port = await listenLoopback(server);
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;

		let failure: unknown;
		try {
			failure = await fetchContent(httpsLoopback(port, "/x"), {
				keyPair: keys,
				signatureAgent: "https://agent.test",
				dispatcher: loopbackDispatcher(),
				timeoutMs: 400,
				maxBytes: 64 << 20,
			}).catch((e: unknown) => e);
		} finally {
			server.closeAllConnections();
			await new Promise<void>((done) => server.close(() => done()));
		}

		expect(
			failure,
			"the dialer's own error escaped a verb that promises ForaCallError and nothing else",
		).toBeInstanceOf(ForaCallError);
		expect((failure as ForaCallError).kind).toBe("unreachable");
		// The refusal reaches a log, and a delivery URL's query is the credential.
		expect(String((failure as ForaCallError).cause ?? "")).not.toContain("127.0.0.1");
	}, 20000);
});

describe("a redirect on the DELIVERY leg", () => {
	// The RPC leg was fixed and this one was not, in both ports. Worse than a wrong class:
	// the refusal reader ran first and promoted a token out of the redirect body, so a 302
	// carrying {"reason":"moved"} surfaced as though the edge had named a typed refusal.
	it("is unreachable, and no token is promoted out of its body", async () => {
		const server = createServer((_req, res) => {
			res.writeHead(302, {
				location: "https://elsewhere.test/x",
				"content-type": "application/json",
			});
			res.end('{"reason":"moved"}');
		});
		const port = await listenLoopback(server);
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;

		const failure = (await fetchContent(httpsLoopback(port, "/x"), {
			keyPair: keys,
			signatureAgent: "https://agent.test",
			dispatcher: loopbackDispatcher(),
		}).catch((e: unknown) => e)) as ForaCallError;
		server.close();

		expect(failure).toBeInstanceOf(ForaCallError);
		expect(failure.kind).toBe("unreachable");
		expect(failure.reason, "a token was promoted out of a redirect body").toBeUndefined();
	}, 20000);
});

describe("a dial the guard refused", () => {
	// It carries NO reason, which is what the shared corpus records and what Go and Python
	// already answered: `reason` holds the PEER's own refusal token, and a dial the guard
	// refused reached no peer. This leg used to mint "ssrf_guard" here.
	//
	// What that costs is worth stating where the assertion used to be: an address-pin
	// refusal is a verdict about where this URL points and will refuse identically forever,
	// while a momentary blip will not, and nothing in the failure now tells a caller which
	// it was. No SDK of the three distinguishes them, so the answer is the same everywhere
	// rather than better in one — telling them apart means adding a value to the shared
	// taxonomy, not a token in one language.
	it("is unreachable and carries no token, and still does not echo the credential", async () => {
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
		// Loopback is what the address pin refuses; the scheme gate is satisfied by https.
		const failure = (await fetchContent("https://localhost/a?token=live-credential-value", {
			keyPair: keys,
			signatureAgent: "https://agent.test",
		}).catch((e: unknown) => e)) as ForaCallError;

		expect(failure).toBeInstanceOf(ForaCallError);
		expect(failure.kind).toBe("unreachable");
		expect(failure.reason, "an SDK verdict was put in the field that carries the peer's token").toBeUndefined();
		expect(String(failure.cause ?? "")).not.toContain("live-credential-value");
	});
});
