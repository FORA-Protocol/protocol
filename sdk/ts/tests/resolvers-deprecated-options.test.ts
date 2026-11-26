// The deprecated scheme and port options accept only https and its default port. Anything
// else is refused with the face's own failure before a request reaches the transport,
// injected or not, so no value of them reaches a plaintext peer. Mirrors
// sdk/go/resolvers/deprecated_options_test.go.

import { describe, expect, it } from "vitest";

import {
	createWBAOfferDirectoryFetch,
	createWellKnownEndpointResolver,
	createWellKnownRequirementsReader,
	DirectoryUnavailable,
	type FetchLike,
	readManifest,
	readWBADirectory,
	WBA_DIRECTORY_PATH,
} from "../resolvers/index.ts";

/** A transport that records every URL it is handed and answers an empty 200. */
function recording(): { fetch: FetchLike; dialled: string[] } {
	const dialled: string[] = [];
	const fetch: FetchLike = async (url) => {
		dialled.push(url);
		return { status: 200, text: async () => "" };
	};
	return { fetch, dialled };
}

/** Assert `run` is refused for its scheme or port, with nothing reaching the transport. */
async function refusedBeforeDialling(what: string, run: (fetch: FetchLike) => Promise<unknown>): Promise<void> {
	const { fetch, dialled } = recording();
	const err = await run(fetch).then(
		() => undefined,
		(e: unknown) => e,
	);
	expect(err, what).toBeInstanceOf(DirectoryUnavailable);
	expect(String(err), what).toMatch(/disallowed scheme|port option/);
	expect(dialled, `${what}: a refused option must reach no transport`).toEqual([]);
}

const HOST = "exchange.example";

describe("the deprecated scheme options", () => {
	for (const scheme of ["http", "ftp", "HTTP"]) {
		it(`refuse ${scheme} before anything is dialled`, async () => {
			await refusedBeforeDialling(`readManifest ${scheme}`, (fetch) => readManifest(HOST, { fetch, scheme }));
			await refusedBeforeDialling(`readWBADirectory ${scheme}`, (fetch) => readWBADirectory(HOST, { fetch, scheme }));
			await refusedBeforeDialling(`resolveEndpoint ${scheme}`, (fetch) =>
				createWellKnownEndpointResolver({ fetch, scheme }).resolveEndpoint(HOST),
			);
			await refusedBeforeDialling(`resolveRegistrationRequirements ${scheme}`, (fetch) =>
				createWellKnownRequirementsReader({ fetch, scheme }).resolveRegistrationRequirements(HOST),
			);
		});
	}

	it("still dial https", async () => {
		const { fetch, dialled } = recording();
		await readManifest(HOST, { fetch, scheme: "https" }).catch(() => undefined);
		await createWellKnownEndpointResolver({ fetch, scheme: "https" })
			.resolveEndpoint(HOST)
			.catch(() => undefined);
		expect(dialled).toEqual([`https://${HOST}/.well-known/fora.json`, `https://${HOST}/.well-known/fora.json`]);
	});
});

describe("the offer-directory fetch's deprecated scheme and port options", () => {
	// The fetch's contract is never to throw, so a refusal answers undefined.
	for (const opts of [{ scheme: "http" }, { port: "8443" }, { scheme: "https", port: "80" }]) {
		it(`refuse ${JSON.stringify(opts)} before anything is dialled`, async () => {
			const { fetch, dialled } = recording();
			expect(await createWBAOfferDirectoryFetch({ fetch, ...opts })(HOST)).toBeUndefined();
			expect(dialled).toEqual([]);
		});
	}

	it("still dial https and port 443", async () => {
		const { fetch, dialled } = recording();
		await createWBAOfferDirectoryFetch({ fetch, scheme: "https", port: "443" })(HOST);
		expect(dialled).toEqual([`https://${HOST}:443${WBA_DIRECTORY_PATH}`]);
	});
});

// readWBADirectory reads the scheme option only to build a bare host's URL. A full URL
// carries its own scheme, so a scheme other than https is not read for it, and a value that
// is neither a URL nor a bare host is the invalid-host error whatever the scheme. The Go and
// Python SDKs hold the same two cases.
describe("readWBADirectory's scheme option", () => {
	it("is not read for a full URL", async () => {
		const { fetch, dialled } = recording();
		const url = `https://${HOST}${WBA_DIRECTORY_PATH}`;
		const err = await readWBADirectory(url, { fetch, scheme: "http" }).catch((e: unknown) => e);
		expect(String(err)).not.toMatch(/disallowed scheme/);
		expect(dialled).toEqual([url]);
	});

	it("does not change the invalid-host error", async () => {
		const { fetch, dialled } = recording();
		const err = await readWBADirectory("not a host", { fetch, scheme: "http" }).catch((e: unknown) => e);
		expect(err).not.toBeInstanceOf(DirectoryUnavailable);
		expect(String(err)).toMatch(/not a usable host/);
		expect(dialled).toEqual([]);
	});
});
