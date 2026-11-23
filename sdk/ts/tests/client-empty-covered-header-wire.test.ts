// An empty covered header has to reach the WIRE, not just the header map.
//
// The whole point of binding `authorization` unconditionally, even empty, is that a
// verifier rebuilds the signature base from the request it RECEIVED. A value
// bound but never transmitted is not bound at all — the verifier reads the covered
// names off Signature-Input, finds nothing on the wire under one of them, and refuses.
//
// Every other assertion about the emitted set reads a captured object literal from an
// injected send, which proves what the SDK BUILT and says nothing about what left the
// socket. An empty header value is exactly the kind of thing a runtime may decide to
// drop, and if it does, every signed call becomes a rejection while the suite stays
// green. So this one goes through the real dialing seam into a real server and reads
// `req.rawHeaders` — the unparsed name/value pairs as received.
//
// Node only. The edge runtimes named in the docs (Workers, Fastly) host the signed-URL
// edge function, a different surface from the signing client, and cannot be exercised
// from here.
import { createServer, type Server } from "node:http";
import { describe, expect, it } from "vitest";

import { ForaCallError } from "../client/errors.ts";
import { createUnarySend } from "../client/send.ts";
import { unaryCall } from "../client/transport.ts";
import { SignatureAgentHeader } from "../src/wire.ts";
import { listenLoopback } from "./loopback-harness.ts";

const SIGNATURE_AGENT_LOWER = SignatureAgentHeader.toLowerCase();

/** Answers `{}` and records the raw name/value pairs exactly as received. */
async function recordingServer(): Promise<[Server, number, () => string[]]> {
	let raw: string[] = [];
	const server = createServer((req, res) => {
		raw = req.rawHeaders;
		res.writeHead(200, { "content-type": "application/json" });
		res.end("{}");
	});
	const port = await listenLoopback(server);
	return [server, port, () => raw];
}

/** rawHeaders is a flat [name, value, name, value, …] list; collect every line under one name. */
function linesFor(raw: string[], name: string): string[] {
	const out: string[] = [];
	for (let i = 0; i + 1 < raw.length; i += 2) {
		if ((raw[i] as string).toLowerCase() === name) out.push(raw[i + 1] as string);
	}
	return out;
}

describe("an empty covered header survives the transport", () => {
	it("the empty authorization arrives present-and-empty, and every covered name exactly once", async () => {
		const [server, port, raw] = await recordingServer();
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;

		try {
			// The configured leg's default send, which dials the loopback listener as given.
			await unaryCall({
				op: "discover",
				target: {
					baseURL: `http://127.0.0.1:${port}`,
					service: "fora.v1.ExchangeService",
					method: "DiscoverResources",
				},
				message: {},
				send: createUnarySend({ guarded: false }),
				// No bearer token, so the covered authorization value is empty: the shape
				// that never left the socket before.
				signer: { privKey: keys.privateKey, keyid: "agent.test.v1", signatureAgent: "https://agent.test" },
			});

			const received = raw();
			// PRESENT, and empty — not absent. An adapter that drops an empty value would
			// leave zero lines here and every signed call would be refused downstream.
			expect(linesFor(received, "authorization")).toEqual([""]);
			expect(linesFor(received, SIGNATURE_AGENT_LOWER)).toEqual(['sig1="https://agent.test"']);
			// And exactly ONE line per covered name: two lines under one name join with
			// ", " before the base is rebuilt, which breaks an otherwise valid signature.
			for (const name of ["authorization", SIGNATURE_AGENT_LOWER, "content-digest", "signature-input", "signature"]) {
				expect(linesFor(received, name), `field lines for ${name}`).toHaveLength(1);
			}
		} finally {
			server.close();
		}
	});

	it("a signer with no key directory is refused as malformed and nothing leaves the socket", async () => {
		const [server, port, raw] = await recordingServer();
		const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
		try {
			const err = await unaryCall({
				op: "discover",
				target: {
					baseURL: `http://127.0.0.1:${port}`,
					service: "fora.v1.ExchangeService",
					method: "DiscoverResources",
				},
				message: {},
				send: createUnarySend({ guarded: false }),
				signer: { privKey: keys.privateKey, keyid: "agent.test.v1" },
			}).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(ForaCallError);
			expect((err as ForaCallError).kind).toBe("malformed");
			expect(raw()).toEqual([]);
		} finally {
			server.close();
		}
	});
});
