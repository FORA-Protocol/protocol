// The document read enforces its own bounds, whatever transport is injected: a body cap,
// one deadline for the whole read, the redirect cap and the scheme of every hop. The edge
// entry hands the runtime's own fetch straight to the readers, so these are exercised
// first through a fetch answering WHATWG Responses (as a Worker's does), then through the
// Node default transport against a real server. Go and Python enforce the same cap and
// deadline in their readers; the redirect rules match their guarded clients.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { readRevocationList } from "../resolvers/edge.ts";
import { DirectoryUnavailable } from "../resolvers/errors.ts";
import {
	DOCUMENT_READ_TIMEOUT_MS,
	type FetchInit,
	type FetchLike,
	fetchDocument,
	fetchSoft,
	MAX_DOC_BYTES,
} from "../resolvers/fetch.ts";
import { guardedFetchFromEnv } from "../resolvers/http.ts";
import { MAX_REDIRECTS } from "../resolvers/ssrf.ts";

/** A fetch answering from `route`, recording every URL and init it was handed. */
function recordingFetch(route: (url: string) => Response | Promise<Response>): {
	fetch: FetchLike;
	calls: { url: string; init: FetchInit | undefined }[];
} {
	const calls: { url: string; init: FetchInit | undefined }[] = [];
	const fetch: FetchLike = async (url, init) => {
		calls.push({ url, init });
		return route(url);
	};
	return { fetch, calls };
}

const ok = (body: BodyInit, contentType = "application/json"): Response =>
	new Response(body, { status: 200, headers: { "content-type": contentType } });

const redirect = (location: string, status = 302): Response =>
	new Response(null, { status, headers: { location } });

/** A redirect chain on https://doc.example: /n answers a relative redirect to /(n-1),
 * and /0 is the document. */
function chain(): ReturnType<typeof recordingFetch> {
	return recordingFetch((url) => {
		const n = Number.parseInt(new URL(url).pathname.slice(1), 10);
		return n > 0 ? redirect(`/${n - 1}`) : ok("{}");
	});
}

describe("the document read bounds the body", () => {
	it("accepts a body of exactly MAX_DOC_BYTES and refuses one byte more", async () => {
		const exact = recordingFetch(() => ok(new Uint8Array(MAX_DOC_BYTES)));
		expect((await fetchDocument(exact.fetch, "https://doc.example/d")).body.byteLength).toBe(MAX_DOC_BYTES);

		const over = recordingFetch(() => ok(new Uint8Array(MAX_DOC_BYTES + 1)));
		await expect(fetchDocument(over.fetch, "https://doc.example/d")).rejects.toBeInstanceOf(DirectoryUnavailable);
	});

	it("stops reading a body that never ends once it passes the cap", async () => {
		const chunk = new Uint8Array(64 * 1024);
		let pulls = 0;
		const endless = new ReadableStream<Uint8Array>({
			pull(controller) {
				pulls += 1;
				controller.enqueue(chunk);
			},
		});
		const { fetch } = recordingFetch(() => ok(endless));
		await expect(fetchDocument(fetch, "https://doc.example/d")).rejects.toBeInstanceOf(DirectoryUnavailable);
		// The cap is 16 chunks; the read takes the one that crosses it and stops.
		expect(pulls).toBeLessThanOrEqual(MAX_DOC_BYTES / chunk.byteLength + 2);
	});

	it("refuses an over-cap body through an edge reader, and fetchSoft reads it as absent", async () => {
		const { fetch } = recordingFetch(() => ok(new Uint8Array(MAX_DOC_BYTES + 1)));
		await expect(readRevocationList("https://doc.example/rev", { fetch })).rejects.toBeInstanceOf(DirectoryUnavailable);
		expect(await fetchSoft(fetch, "https://doc.example/rev")).toBeUndefined();
	});
});

describe("the document read follows redirects itself", () => {
	it("asks the transport not to follow, and hands it the read's signal", async () => {
		const { fetch, calls } = chain();
		await fetchDocument(fetch, "https://doc.example/2");
		expect(calls).toHaveLength(3);
		for (const call of calls) {
			expect(call.init?.redirect).toBe("manual");
			expect(call.init?.signal).toBeInstanceOf(AbortSignal);
		}
	});

	it(`follows ${MAX_REDIRECTS} redirects, resolving a relative Location, and refuses one more`, async () => {
		const at = chain();
		const doc = await fetchDocument(at.fetch, `https://doc.example/${MAX_REDIRECTS}`);
		expect(doc.url).toBe(`https://doc.example/${MAX_REDIRECTS}`);
		expect(at.calls.map((c) => c.url).at(-1)).toBe("https://doc.example/0");

		const over = chain();
		await expect(fetchDocument(over.fetch, `https://doc.example/${MAX_REDIRECTS + 1}`)).rejects.toBeInstanceOf(
			DirectoryUnavailable,
		);
		expect(over.calls).toHaveLength(MAX_REDIRECTS + 1);
	});

	it.each([
		["a step down from https to plaintext http", "http://doc.example/next"],
		["a scheme that is not http(s)", "ftp://doc.example/next"],
		["credentials in the Location", "https://user:secret@doc.example/next"],
		["no Location at all", ""],
	])("refuses a redirect with %s", async (_name, location) => {
		const { fetch, calls } = recordingFetch((url) =>
			url === "https://doc.example/start" ? redirect(location) : ok("{}"),
		);
		await expect(fetchDocument(fetch, "https://doc.example/start")).rejects.toBeInstanceOf(DirectoryUnavailable);
		expect(calls).toHaveLength(1);
	});

	it("follows http to http, where the read started in plaintext", async () => {
		const { fetch } = recordingFetch((url) =>
			url === "http://doc.example/start" ? redirect("http://doc.example/next") : ok("{}"),
		);
		expect((await fetchDocument(fetch, "http://doc.example/start")).body.byteLength).toBe(2);
	});

	it("refuses a 3xx that names no new location, and any 3xx for a key directory", async () => {
		const notModified = recordingFetch(() => new Response(null, { status: 300 }));
		await expect(fetchDocument(notModified.fetch, "https://doc.example/d")).rejects.toBeInstanceOf(DirectoryUnavailable);

		const directory = recordingFetch(() => redirect("https://doc.example/elsewhere"));
		await expect(
			fetchDocument(directory.fetch, "https://doc.example/dir", { noRedirect: true }),
		).rejects.toBeInstanceOf(DirectoryUnavailable);
		expect(directory.calls).toHaveLength(1);
	});

	it("refuses a response the transport followed although it was asked not to", async () => {
		const followed = ok("{}");
		Object.defineProperty(followed, "redirected", { value: true });
		const { fetch } = recordingFetch(() => followed);
		await expect(fetchDocument(fetch, "https://doc.example/d")).rejects.toBeInstanceOf(DirectoryUnavailable);
	});

	it("never fetches a URL that is not http(s)", async () => {
		const { fetch, calls } = recordingFetch(() => ok("{}"));
		await expect(fetchDocument(fetch, "data:application/json,{}")).rejects.toBeInstanceOf(DirectoryUnavailable);
		expect(calls).toHaveLength(0);
	});
});

describe("the document read ends at its deadline", () => {
	afterEach(() => {
		vi.useRealTimers();
	});

	it("gives up when the transport never answers, and aborts the signal it passed", async () => {
		vi.useFakeTimers();
		let seen: AbortSignal | undefined;
		const fetch: FetchLike = (_url, init) => {
			seen = init?.signal;
			return new Promise(() => undefined);
		};
		const read = fetchDocument(fetch, "https://doc.example/slow");
		const refused = expect(read).rejects.toBeInstanceOf(DirectoryUnavailable);
		await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
		await refused;
		expect(seen?.aborted).toBe(true);
	});

	it("gives up on a body that stalls", async () => {
		vi.useFakeTimers();
		const stalled = new ReadableStream<Uint8Array>({ pull: () => new Promise(() => undefined) });
		const { fetch } = recordingFetch(() => ok(stalled));
		const read = fetchDocument(fetch, "https://doc.example/slow");
		const refused = expect(read).rejects.toBeInstanceOf(DirectoryUnavailable);
		await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
		await refused;
	});
});

describe("the Node default transport under the reader's bounds", () => {
	let server: Server | undefined;
	afterEach(async () => {
		vi.unstubAllEnvs();
		if (server !== undefined) {
			const s = server;
			await new Promise<void>((resolve) => s.close(() => resolve()));
			server = undefined;
		}
	});

	async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
		server = createServer(handler);
		const s = server;
		await new Promise<void>((resolve) => s.listen(0, "127.0.0.1", resolve));
		return `http://127.0.0.1:${(s.address() as AddressInfo).port}`;
	}

	it("refuses an over-cap body and follows a plaintext chain up to the cap", async () => {
		// A loopback origin over plaintext is what the two deployment flags admit.
		vi.stubEnv("SKIP_SSRF", "true");
		vi.stubEnv("ALLOW_INSECURE", "true");
		const base = await listen((req, res) => {
			const path = req.url ?? "/";
			if (path === "/big") {
				res.writeHead(200, { "content-type": "application/json" });
				res.end(Buffer.alloc(MAX_DOC_BYTES + 1));
				return;
			}
			const n = Number.parseInt(path.slice(1), 10) || 0;
			if (n > 0) {
				res.writeHead(302, { location: `/${n - 1}` });
				res.end();
				return;
			}
			res.writeHead(200, { "content-type": "application/json" });
			res.end("{}");
		});
		const transport = guardedFetchFromEnv();

		await expect(fetchDocument(transport, `${base}/big`)).rejects.toBeInstanceOf(DirectoryUnavailable);
		expect((await fetchDocument(transport, `${base}/${MAX_REDIRECTS}`)).body.byteLength).toBe(2);
		await expect(fetchDocument(transport, `${base}/${MAX_REDIRECTS + 1}`)).rejects.toBeInstanceOf(DirectoryUnavailable);
	});
});
