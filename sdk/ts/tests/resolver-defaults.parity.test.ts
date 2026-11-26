// Replays resolver-default-vectors.json: which transport each resolver face takes when
// the caller injects none, and what that default does with each target.
//
// The Go oracle (sdk/go/resolvers/gen_resolver_default_vectors_test.go) emits every row
// by driving its own face against a real listener, so the outcomes are Go's observed
// behaviour, not a table written by hand. Each row carries the scheme and host it dials,
// and the corpus carries the license digest, so this replay keeps no copy of either. It
// drives the same face through the Node entry against the same harness:
//
//  - one loopback origin (the shared harness's startOrigin) that counts the TCP
//    connections it accepts, so a refusal before the dial is observable as zero
//    connections; a row with an empty host dials it;
//  - the row's own host for the targets that have no listener.
//
// A refusal is classified by the oracle's own rule (classifyRefusal), so a face refused
// for another reason does not pass. Nothing in the SDK is mocked: the transport under test
// is the face's own default, except in a control row, which injects the harness's plain
// loopbackFetch.
//
// The rule the rows pin is that a resolver's default follows its URL's provenance: a
// fixed, operator-chosen address takes the plain transport, a host another party named
// takes the guarded one. Changing a row obliges a check of the License.uri SSRF guards
// in proto/fora/v1/fora.proto and Licensing Terms (/protocol/licensing-terms/), which say
// what a consumer must apply before it fetches a URL another party named.
import { describe, expect, it, vi } from "vitest";

import vectorsFile from "../../go/resolvers/testdata/resolver-default-vectors.json";
import type { FetchLike } from "../resolvers/fetch.ts";
import {
	createWBAKeyResolver,
	createWBAOfferDirectoryFetch,
	createWellKnownEndpointResolver,
	createWellKnownKeyResolver,
	createWellKnownRequirementsReader,
	readLicenseDocument,
	readManifest,
	readRevocationList,
	readWBADirectory,
} from "../resolvers/index.ts";
import { loopbackFetch, startOrigin } from "./harness/origin.ts";
import { isolateSsrfEnv } from "./harness/ssrf-env.ts";

interface ResolverDefaultVector {
	name: string;
	face: string;
	target: string;
	scheme: string;
	/** The address dialled; empty for the loopback listener. */
	host: string;
	allow_insecure: boolean;
	/** "default" runs the face's own transport; "plain" injects the harness's plain one. */
	transport: string;
	outcome: string;
}

const CORPUS = vectorsFile as { license_digest: string; resolver_defaults: ResolverDefaultVector[] };
const VECTORS = CORPUS.resolver_defaults;

isolateSsrfEnv();

/** Each face's DEFAULT construction, as a caller injecting nothing; `base` is scheme://host. */
const FACES: Record<string, (scheme: string, host: string, base: string) => Promise<unknown>> = {
	wellknown_key_resolver: (_s, _h, base) =>
		createWellKnownKeyResolver(`${base}/.well-known/fora.json`).resolve("ex.v1"),
	wellknown_endpoint_resolver: (scheme, host) => createWellKnownEndpointResolver({ scheme }).resolveEndpoint(host),
	registration_requirements_reader: (scheme, host) =>
		createWellKnownRequirementsReader({ scheme }).resolveRegistrationRequirements(host),
	manifest_reader: (scheme, host) => readManifest(host, { scheme }),
	wba_directory_reader: (scheme, host) => readWBADirectory(host, { scheme }),
	revocation_list_reader: (_s, _h, base) => readRevocationList(`${base}/revocation`),
	license_document_reader: (_s, _h, base) =>
		readLicenseDocument({ uri: `${base}/license`, uri_digest: CORPUS.license_digest }),
	wba_key_resolver: (_s, _h, base) => createWBAKeyResolver().resolve("ex.v1", base),
	offer_directory_fetch: (scheme, host) => createWBAOfferDirectoryFetch({ scheme })(host),
};

/** Run one face against `scheme://host` as a caller would: with its own default transport,
 * or with `fetch` injected. Only the offer-directory fetch has a control row. */
function exercise(face: string, scheme: string, host: string, fetch: FetchLike | undefined): Promise<unknown> {
	if (fetch === undefined) {
		const run = FACES[face];
		if (run === undefined) throw new Error(`unknown face ${face}`);
		return run(scheme, host, `${scheme}://${host}`);
	}
	if (face !== "offer_directory_fetch") throw new Error(`${face} takes no injected transport in this replay`);
	return createWBAOfferDirectoryFetch({ scheme, fetch })(host);
}

/** The error a face rejected with, or undefined when it resolved. */
async function run(v: ResolverDefaultVector, host: string): Promise<unknown> {
	try {
		await exercise(v.face, v.scheme, host, v.transport === "plain" ? loopbackFetch : undefined);
		return undefined;
	} catch (err) {
		return err;
	}
}

/** Which check refused, by the Go oracle's classifyRefusal rule applied to the rejection's
 * message and the messages of its cause chain, as Go applies it to a wrapped error. */
function classify(err: unknown): string {
	if (err === undefined) return "no error";
	const messages: string[] = [];
	for (let cur: unknown = err; cur !== undefined && cur !== null; cur = (cur as { cause?: unknown }).cause) {
		messages.push(cur instanceof Error ? cur.message : String(cur));
	}
	const text = messages.join(": ");
	if (text.includes("disallowed scheme") && text.includes("SSRF guard")) return "refused_scheme";
	if (text.includes("refusing to dial") && text.includes("SSRF guard")) return "refused_address";
	return `other: ${text}`;
}

/** The outcome of a row whose target is the loopback origin: "reached" when a connection
 * arrived, else the refusal. A face that contains its failures resolves with "no
 * directory", and with no connection made that is all its seam reports: "not_reached". */
async function runAgainstOrigin(v: ResolverDefaultVector): Promise<string> {
	const origin = await startOrigin();
	let err: unknown;
	try {
		err = await run(v, origin.host);
	} finally {
		await origin.close();
	}
	if (origin.connections() > 0) return "reached";
	return err === undefined ? "not_reached" : classify(err);
}

describe("resolver default transports match the Go oracle", () => {
	it("replays a non-empty corpus", () => {
		expect(VECTORS.length).toBeGreaterThan(0);
	});

	for (const v of VECTORS) {
		it(v.name, async () => {
			if (v.allow_insecure) vi.stubEnv("ALLOW_INSECURE", "1");

			const got = v.host !== "" ? classify(await run(v, v.host)) : await runAgainstOrigin(v);

			expect(
				got,
				`${v.name}: this SDK's default transport gave ${got}, the Go oracle ${v.outcome}. ` +
					"If the change is intended, change the oracle and check it against the License.uri SSRF " +
					"guards in proto/fora/v1/fora.proto.",
			).toBe(v.outcome);
		});
	}
});
