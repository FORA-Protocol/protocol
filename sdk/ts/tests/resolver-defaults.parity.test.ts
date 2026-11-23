// Replays resolver-default-vectors.json: which transport each resolver face takes when
// the caller injects none, and what that default does with each target.
//
// The Go oracle (sdk/go/resolvers/gen_resolver_default_vectors_test.go) emits every row
// by driving its own face against a real listener, so the outcomes are Go's observed
// behaviour, not a table written by hand. This replay drives the same face through the
// Node entry, with no transport injected, against the same harness:
//
//  - one loopback listener that counts the TCP connections it accepts, so a refusal
//    before the dial is observable as zero connections;
//  - IP-literal hosts for the private and link-local targets, which have no listener.
//
// Nothing in the SDK is mocked: the transport under test is always the face's own default.
//
// The rule the rows pin is that a resolver's default follows its URL's provenance: a
// fixed, operator-chosen address takes the plain transport, a host another party named
// takes the guarded one. Changing a row obliges a check of the License.uri SSRF guards
// in proto/fora/v1/fora.proto and Licensing Terms (/protocol/licensing-terms/), which say
// what a consumer must apply before it fetches a URL another party named.
import { createServer, type Server } from "node:http";
import type { AddressInfo, Socket } from "node:net";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import vectorsFile from "../../go/resolvers/testdata/resolver-default-vectors.json";
import {
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
	createWellKnownRequirementsReader,
	readLicenseDocument,
	readManifest,
	readRevocationList,
	readWBADirectory,
	SsrfBlockedError,
} from "../resolvers/index.ts";

interface ResolverDefaultVector {
	name: string;
	face: string;
	target: string;
	allow_insecure: boolean;
	outcome: string;
}

const VECTORS = (vectorsFile as { resolver_defaults: ResolverDefaultVector[] }).resolver_defaults;

const PRIVATE = "10.0.0.5:9";
const LINK_LOCAL = "169.254.169.254:9";
const LISTENER = "127.0.0.1";
// Well-formed, so the License passes its strict check and the read reaches the transport.
const LICENSE_DIGEST = `sha256:${"0".repeat(64)}`;

const TOUCHED = ["SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"];
let saved: Record<string, string | undefined>;

beforeEach(() => {
	saved = {};
	for (const k of TOUCHED) {
		saved[k] = process.env[k];
		delete process.env[k];
	}
});

afterEach(() => {
	for (const k of TOUCHED) {
		if (saved[k] === undefined) delete process.env[k];
		else process.env[k] = saved[k];
	}
});

/** Run one face's DEFAULT construction against `host`, as a caller injecting nothing. */
function exercise(face: string, host: string): Promise<unknown> {
	switch (face) {
		case "wellknown_key_resolver":
			return createWellKnownKeyResolver(`http://${host}/.well-known/fora.json`).resolve("ex.v1");
		case "wellknown_endpoint_resolver":
			return createWellKnownEndpointResolver({ scheme: "http" }).resolveEndpoint(host);
		case "registration_requirements_reader":
			return createWellKnownRequirementsReader({ scheme: "http" }).resolveRegistrationRequirements(host);
		case "manifest_reader":
			return readManifest(host, { scheme: "http" });
		case "wba_directory_reader":
			return readWBADirectory(host, { scheme: "http" });
		case "revocation_list_reader":
			return readRevocationList(`http://${host}/revocation`);
		case "license_document_reader":
			return readLicenseDocument({ uri: `http://${host}/license`, uri_digest: LICENSE_DIGEST });
	}
	throw new Error(`unknown face ${face}`);
}

/** The error a face rejected with, or undefined when it resolved. */
async function run(face: string, host: string): Promise<unknown> {
	try {
		await exercise(face, host);
		return undefined;
	} catch (err) {
		return err;
	}
}

/** Which check refused, read from the rejection and its cause chain. */
function classify(err: unknown): string {
	if (err === undefined) return "no error";
	for (let cur: unknown = err; cur !== undefined && cur !== null; cur = (cur as { cause?: unknown }).cause) {
		if (cur instanceof SsrfBlockedError) {
			return cur.message.includes("scheme") ? "refused_scheme" : "refused_address";
		}
	}
	return `other: ${String(err)}`;
}

/** The loopback origin: serves a manifest naming itself and counts accepted connections. */
async function startListener() {
	let connections = 0;
	const sockets = new Set<Socket>();
	const server: Server = createServer((req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(
			JSON.stringify({
				ver: "1.0",
				role: "ROLE_EXCHANGE",
				endpoint: `http://${req.headers.host}/fora.v1.ExchangeService`,
				keys: [],
			}),
		);
	});
	server.on("connection", (socket) => {
		connections += 1;
		sockets.add(socket);
		socket.on("close", () => sockets.delete(socket));
	});
	await new Promise<void>((resolve) => server.listen(0, LISTENER, resolve));
	const { port } = server.address() as AddressInfo;
	return {
		host: `${LISTENER}:${port}`,
		connections: () => connections,
		close: async () => {
			for (const s of sockets) s.destroy();
			await new Promise<void>((resolve) => server.close(() => resolve()));
		},
	};
}

describe("resolver default transports match the Go oracle", () => {
	it("replays a non-empty corpus", () => {
		expect(VECTORS.length).toBeGreaterThan(0);
	});

	for (const v of VECTORS) {
		it(v.name, async () => {
			if (v.allow_insecure) process.env.ALLOW_INSECURE = "1";

			let got: string;
			if (v.target === "private") {
				got = classify(await run(v.face, PRIVATE));
			} else if (v.target === "link_local") {
				got = classify(await run(v.face, LINK_LOCAL));
			} else {
				const listener = await startListener();
				let err: unknown;
				try {
					err = await run(v.face, listener.host);
				} finally {
					await listener.close();
				}
				got = listener.connections() > 0 ? "reached" : classify(err);
			}

			expect(
				got,
				`${v.name}: this SDK's default transport gave ${got}, the Go oracle ${v.outcome}. ` +
					"If the change is intended, change the oracle and check it against the License.uri SSRF guards in proto/fora/v1/fora.proto.",
			).toBe(v.outcome);
		});
	}
});
