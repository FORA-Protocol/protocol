// The edge resolvers entry (package export "./resolvers/edge") reads through the fetch a
// runtime passes, answered with plain WHATWG Responses as a Workers or Deno fetch answers,
// and carries none of the Node entry's transports. The Node entry ("./resolvers") is the
// same surface with the transport defaulted, and passes an injected fetch through
// unchanged.

import { describe, expect, it } from "vitest";
import * as edge from "../resolvers/edge.ts";
import * as node from "../resolvers/index.ts";

const MANIFEST = JSON.stringify({ ver: "1.0", role: "ROLE_EXCHANGE", endpoint: "https://exchange.example/rpc" });
const LICENSE_TEXT = "Licensed for retrieval-augmented answers, attribution required.\n";

async function sha256(text: string): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
	return `sha256:${Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}

// serving answers each URL in `docs` with its body and content type, records every URL
// asked for, and answers 404 for anything else.
function serving(docs: Record<string, { body: string; contentType?: string }>): {
	fetch: edge.FetchLike;
	seen: string[];
} {
	const seen: string[] = [];
	const fetch: edge.FetchLike = async (url) => {
		seen.push(url);
		const doc = docs[url];
		if (doc === undefined) return new Response("", { status: 404 });
		return new Response(doc.body, { headers: doc.contentType ? { "content-type": doc.contentType } : {} });
	};
	return { fetch, seen };
}

describe("the edge resolvers entry", () => {
	it("reads a manifest through the injected fetch", async () => {
		const { fetch, seen } = serving({
			"https://exchange.example/.well-known/fora.json": { body: MANIFEST, contentType: "application/json" },
		});
		const doc = await edge.readManifest("exchange.example", { fetch });
		expect(doc.message.endpoint).toBe("https://exchange.example/rpc");
		expect(seen).toEqual(["https://exchange.example/.well-known/fora.json"]);
	});

	it("refuses a manifest the injected fetch serves under the wrong media type", async () => {
		const { fetch } = serving({
			"https://exchange.example/.well-known/fora.json": { body: MANIFEST, contentType: "text/plain" },
		});
		await expect(edge.readManifest("exchange.example", { fetch })).rejects.toBeInstanceOf(edge.MediaTypeRefused);
	});

	it("verifies a license document's digest with WebCrypto, and refuses bytes that do not match it", async () => {
		const uri = "https://publisher.example/terms";
		const { fetch } = serving({ [uri]: { body: LICENSE_TEXT } });
		const ok = await edge.readLicenseDocument({ uri, uri_digest: await sha256(LICENSE_TEXT) }, { fetch });
		expect(ok.digest).toBe(await sha256(LICENSE_TEXT));
		await expect(
			edge.readLicenseDocument({ uri, uri_digest: await sha256(`${LICENSE_TEXT}tampered`) }, { fetch }),
		).rejects.toBeInstanceOf(edge.DigestMismatch);
	});

	it("resolves an Exchange endpoint through the injected fetch, and reports an outage when it fails", async () => {
		const { fetch } = serving({
			"https://exchange.example/.well-known/fora.json": { body: MANIFEST, contentType: "application/json" },
		});
		expect(await edge.createWellKnownEndpointResolver({ fetch }).resolveEndpoint("exchange.example")).toBe(
			"https://exchange.example/rpc",
		);
		await expect(
			edge.createWellKnownEndpointResolver({ fetch }).resolveEndpoint("unknown.example"),
		).rejects.toBeInstanceOf(edge.DirectoryUnavailable);
	});

	it("exports none of the Node entry's transports", () => {
		for (const name of ["guardedFetchFromEnv", "ssrfGuard", "SsrfBlockedError"]) {
			expect(name in edge, name).toBe(false);
			expect(name in node, name).toBe(true);
		}
	});
});

describe("the Node resolvers entry", () => {
	it("passes an injected fetch through to the edge-safe reader", async () => {
		const { fetch, seen } = serving({
			"https://exchange.example/.well-known/fora.json": { body: MANIFEST, contentType: "application/json" },
		});
		const doc = await node.readManifest("exchange.example", { fetch });
		expect(doc.message.role).toBe("ROLE_EXCHANGE");
		expect(seen).toEqual(["https://exchange.example/.well-known/fora.json"]);
	});
});
