// Replays resolver-default-vectors.json: which transport each resolver face takes when
// the caller injects none, and what that default does with each target.
//
// The Go oracle (sdk/go/resolvers/gen_resolver_default_vectors_test.go) emits every row
// by driving its own face against a real listener, so the outcomes are Go's observed
// behaviour, not a table written by hand. This replay drives the same face through the
// Node entry, with no transport injected, against the same harness:
//
//  - one loopback origin (the shared harness's startOrigin) that counts the TCP
//    connections it accepts, so a refusal before the dial is observable as zero
//    connections;
//  - IP-literal hosts for the private and link-local targets, which have no listener.
//
// Nothing in the SDK is mocked: the transport under test is always the face's own default.
//
// The rule the rows pin is that a resolver's default follows its URL's provenance: a
// fixed, operator-chosen address takes the plain transport, a host another party named
// takes the guarded one. Changing a row obliges a check of the License.uri SSRF guards
// in proto/fora/v1/fora.proto and Licensing Terms (/protocol/licensing-terms/), which say
// what a consumer must apply before it fetches a URL another party named.
import { describe, expect, it, vi } from "vitest";

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
import { isolateSsrfEnv, startOrigin } from "./resolvers-harness.ts";

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
// Well-formed, so the License passes its strict check and the read reaches the transport.
const LICENSE_DIGEST = `sha256:${"0".repeat(64)}`;

isolateSsrfEnv();

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

describe("resolver default transports match the Go oracle", () => {
	it("replays a non-empty corpus", () => {
		expect(VECTORS.length).toBeGreaterThan(0);
	});

	for (const v of VECTORS) {
		it(v.name, async () => {
			if (v.allow_insecure) vi.stubEnv("ALLOW_INSECURE", "1");

			let got: string;
			if (v.target === "private") {
				got = classify(await run(v.face, PRIVATE));
			} else if (v.target === "link_local") {
				got = classify(await run(v.face, LINK_LOCAL));
			} else {
				const origin = await startOrigin();
				let err: unknown;
				try {
					err = await run(v.face, origin.host);
				} finally {
					await origin.close();
				}
				got = origin.connections() > 0 ? "reached" : classify(err);
			}

			expect(
				got,
				`${v.name}: this SDK's default transport gave ${got}, the Go oracle ${v.outcome}. ` +
					"If the change is intended, change the oracle and check it against the License.uri SSRF guards in proto/fora/v1/fora.proto.",
			).toBe(v.outcome);
		});
	}
});
