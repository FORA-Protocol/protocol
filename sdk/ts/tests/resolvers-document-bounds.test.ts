// The document read enforces its own bounds, whatever transport is injected: a body cap,
// one deadline for the whole read, the redirect cap and the scheme of every hop. The edge
// entry hands the runtime's own fetch straight to the readers, so these are exercised
// first through a fetch answering WHATWG Responses (as a Worker's does), then through the
// Node default transport against a real server. Go and Python enforce the same cap and
// deadline in their readers; the redirect rules match their guarded clients.
//
// The bounds are exercised twice: on a runtime with AbortController and AbortSignal, and on
// one without either, as Fastly Compute's JavaScript runtime is. Here both are stubbed as
// undefined rather than deleted, because Node's own Response reads the global AbortSignal
// when it first loads; edge-fastly-globals.test.ts runs the edge entry where neither exists
// at all. A refusal counts only once the read is shown to have reached its transport,
// because a read that failed before it fetched anything is a DirectoryUnavailable too.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { readRevocationList } from "../resolvers/edge.ts";
import { DirectoryUnavailable, DocumentNotFound, RedirectRefused } from "../resolvers/errors.ts";
import {
	DOCUMENT_READ_TIMEOUT_MS,
	type FetchInit,
	type FetchLike,
	type FetchResponse,
	fetchDocument,
	fetchSoft,
	MAX_DOC_BYTES,
} from "../resolvers/fetch.ts";
import { guardedFetchFromEnv } from "../resolvers/http.ts";
import { MAX_REDIRECTS } from "../resolvers/ssrf.ts";
import { stalledBody } from "./resolvers-harness.ts";

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

/** What `read` settled to: its value, or the error it was refused with. Attached before the
 * clock moves, so a refusal is never an unhandled rejection. */
const settled = <T>(read: Promise<T>): Promise<T | unknown> => read.catch((err: unknown) => err);

/** The two runtimes a read must work on. Node, Workers and Deno have AbortController and
 * AbortSignal; Fastly Compute has neither. The one with them runs first, so Node's own
 * fetch machinery loads with them. */
const RUNTIMES = [
	{ name: "a runtime with AbortController", abort: true },
	{ name: "a runtime without AbortController, as Fastly Compute is", abort: false },
];

describe.each(RUNTIMES)("on $name", ({ abort }) => {
	beforeEach(() => {
		if (!abort) {
			vi.stubGlobal("AbortController", undefined);
			vi.stubGlobal("AbortSignal", undefined);
		}
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		vi.useRealTimers();
	});

	describe("the document read bounds the body", () => {
		it("accepts a body of exactly MAX_DOC_BYTES and refuses one byte more", async () => {
			const exact = recordingFetch(() => ok(new Uint8Array(MAX_DOC_BYTES)));
			expect((await fetchDocument(exact.fetch, "https://doc.example/d")).body.byteLength).toBe(MAX_DOC_BYTES);

			const over = recordingFetch(() => ok(new Uint8Array(MAX_DOC_BYTES + 1)));
			await expect(fetchDocument(over.fetch, "https://doc.example/d")).rejects.toBeInstanceOf(DirectoryUnavailable);
			expect(over.calls).toHaveLength(1);
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
			expect(pulls).toBeGreaterThan(MAX_DOC_BYTES / chunk.byteLength);
			expect(pulls).toBeLessThanOrEqual(MAX_DOC_BYTES / chunk.byteLength + 2);
		});

		it("refuses an over-cap body through an edge reader, and fetchSoft reads it as absent", async () => {
			const { fetch, calls } = recordingFetch(() => ok(new Uint8Array(MAX_DOC_BYTES + 1)));
			await expect(readRevocationList("https://doc.example/rev", { fetch })).rejects.toBeInstanceOf(DirectoryUnavailable);
			expect(await fetchSoft(fetch, "https://doc.example/rev")).toBeUndefined();
			expect(calls).toHaveLength(2);
		});
	});

	describe("the document read follows redirects itself", () => {
		it.runIf(abort)("asks the transport not to follow, and hands it the read's signal", async () => {
			const { fetch, calls } = chain();
			await fetchDocument(fetch, "https://doc.example/2");
			expect(calls).toHaveLength(3);
			for (const call of calls) {
				expect(call.init?.redirect).toBe("manual");
				expect(call.init?.signal).toBeInstanceOf(AbortSignal);
			}
		});

		it.runIf(!abort)("asks the transport not to follow, and hands it no signal", async () => {
			const { fetch, calls } = chain();
			await fetchDocument(fetch, "https://doc.example/2");
			expect(calls).toHaveLength(3);
			for (const call of calls) {
				expect(call.init?.redirect).toBe("manual");
				expect(Object.keys(call.init ?? {})).toEqual(["redirect"]);
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
			const err = await fetchDocument(fetch, "https://doc.example/start").catch((e: unknown) => e);
			// A hop a follow read will not take is an unavailable document, not a refused
			// redirect: only a key directory refuses a redirect outright.
			expect(err).toBeInstanceOf(DirectoryUnavailable);
			expect(err).not.toBeInstanceOf(RedirectRefused);
			expect(calls).toHaveLength(1);
		});

		it("reads a followed redirect that ends at a 404 as a missing document", async () => {
			const moved = recordingFetch((url) => (url === "https://doc.example/start" ? redirect("/list") : ok("{}")));
			expect((await fetchDocument(moved.fetch, "https://doc.example/start")).url).toBe("https://doc.example/start");
			const gone = recordingFetch((url) =>
				url === "https://doc.example/start" ? redirect("/gone") : new Response(null, { status: 404 }),
			);
			const err = await fetchDocument(gone.fetch, "https://doc.example/start").catch((e: unknown) => e);
			expect(err).toBeInstanceOf(DocumentNotFound);
			expect(err).not.toBeInstanceOf(RedirectRefused);
			expect(gone.calls).toHaveLength(2);
		});

		it("follows http to http, where the read started in plaintext", async () => {
			const { fetch } = recordingFetch((url) =>
				url === "http://doc.example/start" ? redirect("http://doc.example/next") : ok("{}"),
			);
			expect((await fetchDocument(fetch, "http://doc.example/start")).body.byteLength).toBe(2);
		});

		it("refuses a 3xx that names no new location, and any 3xx for a key directory", async () => {
			const notModified = recordingFetch(() => new Response(null, { status: 300 }));
			const plain = await fetchDocument(notModified.fetch, "https://doc.example/d").catch((e: unknown) => e);
			expect(plain).toBeInstanceOf(DirectoryUnavailable);
			expect(plain).not.toBeInstanceOf(RedirectRefused);
			expect(notModified.calls).toHaveLength(1);

			const directory = recordingFetch(() => redirect("https://doc.example/elsewhere"));
			const refused = await fetchDocument(directory.fetch, "https://doc.example/dir", { noRedirect: true }).catch(
				(e: unknown) => e,
			);
			expect(refused).toBeInstanceOf(RedirectRefused);
			expect(refused).toBeInstanceOf(DirectoryUnavailable);
			expect((refused as Error).message).not.toContain("elsewhere");
			expect(directory.calls).toHaveLength(1);
		});

		it("refuses as a redirect a Location no URL parser reads, on a key-directory read", async () => {
			// The read sees the status before it looks at the Location, so this is a refused
			// redirect here. Go's and Python's HTTP clients reject that answer before their
			// reads see its status, and report an unavailable document.
			const { fetch, calls } = recordingFetch(() => redirect("http://[::1"));
			const err = await fetchDocument(fetch, "https://doc.example/dir", { noRedirect: true }).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(RedirectRefused);
			expect(calls).toHaveLength(1);
		});

		it("refuses a response the transport followed although it was asked not to", async () => {
			const { fetch, calls } = recordingFetch(() => {
				const followed = ok("{}");
				Object.defineProperty(followed, "redirected", { value: true });
				return followed;
			});
			const plain = await fetchDocument(fetch, "https://doc.example/d").catch((e: unknown) => e);
			expect(plain).toBeInstanceOf(DirectoryUnavailable);
			expect(plain).not.toBeInstanceOf(RedirectRefused);
			const directory = await fetchDocument(fetch, "https://doc.example/dir", { noRedirect: true }).catch(
				(e: unknown) => e,
			);
			expect(directory).toBeInstanceOf(RedirectRefused);
			expect(calls).toHaveLength(2);
		});

		it("never fetches a URL that is not http(s)", async () => {
			const { fetch, calls } = recordingFetch(() => ok("{}"));
			await expect(fetchDocument(fetch, "data:application/json,{}")).rejects.toBeInstanceOf(DirectoryUnavailable);
			expect(calls).toHaveLength(0);
		});
	});

	describe("the document read ends at its deadline", () => {
		it.runIf(abort)("gives up when the transport never answers, and aborts the signal it passed", async () => {
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

		it.runIf(!abort)("gives up when the transport never answers, though it could hand it no signal", async () => {
			vi.useFakeTimers();
			const seen: (FetchInit | undefined)[] = [];
			const fetch: FetchLike = (_url, init) => {
				seen.push(init);
				return new Promise(() => undefined);
			};
			const read = fetchDocument(fetch, "https://doc.example/slow");
			const refused = expect(read).rejects.toBeInstanceOf(DirectoryUnavailable);
			await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
			await refused;
			expect(seen).toHaveLength(1);
			expect(Object.keys(seen[0] ?? {})).toEqual(["redirect"]);
		});

		it("reports its deadline even when the transport gives up as its signal aborts", async () => {
			vi.useFakeTimers();
			// A transport that honours the signal, as undici does: it fails the moment the
			// signal aborts. The read's own refusal must still be the one reported. Where there
			// is no signal to honour, it never answers.
			const seen: number[] = [];
			const fetch: FetchLike = (_url, init) => {
				seen.push(1);
				return new Promise((_resolve, reject) => {
					init?.signal?.addEventListener("abort", () => reject(new Error("aborted by the read")), { once: true });
				});
			};
			const outcome = settled(fetchDocument(fetch, "https://doc.example/slow"));
			await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
			const err = await outcome;
			expect(err).toBeInstanceOf(DirectoryUnavailable);
			expect((err as Error).message).toContain(`within ${DOCUMENT_READ_TIMEOUT_MS} ms`);
			expect(seen).toHaveLength(1);
		});

		it("gives up on a body that stalls, and cancels it", async () => {
			vi.useFakeTimers();
			const body = stalledBody();
			const { fetch, calls } = recordingFetch(() => ok(body.stream));
			const read = fetchDocument(fetch, "https://doc.example/slow");
			const refused = expect(read).rejects.toBeInstanceOf(DirectoryUnavailable);
			await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
			await refused;
			expect(calls).toHaveLength(1);
			expect(body.cancelled()).toBe(true);
		});

		it("refuses a body cut off at the deadline, and never returns it short", async () => {
			vi.useFakeTimers();
			const body = stalledBody(new Uint8Array(10));
			const { fetch, calls } = recordingFetch(() => ok(body.stream));
			const outcome = settled(fetchDocument(fetch, "https://doc.example/slow"));
			await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
			const err = await outcome;
			expect(err).toBeInstanceOf(DirectoryUnavailable);
			expect((err as Error).message).toContain(`within ${DOCUMENT_READ_TIMEOUT_MS} ms`);
			expect(calls).toHaveLength(1);
			expect(body.cancelled()).toBe(true);
		});

		it("releases an answer that arrives after the deadline, unread", async () => {
			vi.useFakeTimers();
			const body = stalledBody();
			let answer: ((resp: Response) => void) | undefined;
			const { fetch, calls } = recordingFetch(
				() =>
					new Promise<Response>((resolve) => {
						answer = resolve;
					}),
			);
			const read = fetchDocument(fetch, "https://doc.example/late");
			const refused = expect(read).rejects.toBeInstanceOf(DirectoryUnavailable);
			await vi.advanceTimersByTimeAsync(DOCUMENT_READ_TIMEOUT_MS);
			await refused;
			expect(calls).toHaveLength(1);
			answer?.(ok(body.stream));
			await vi.advanceTimersByTimeAsync(0);
			expect(body.cancelled()).toBe(true);
		});
	});
});

describe("every failure of a document read is a DirectoryUnavailable, its cause the error that ended it", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("when the runtime's AbortController cannot be built", async () => {
		const boom = new Error("no controller");
		vi.stubGlobal(
			"AbortController",
			class {
				constructor() {
					throw boom;
				}
			},
		);
		const { fetch, calls } = recordingFetch(() => ok("{}"));
		const err = await settled(fetchDocument(fetch, "https://doc.example/d"));
		expect(err).toBeInstanceOf(DirectoryUnavailable);
		expect((err as Error).cause).toBe(boom);
		expect(calls).toHaveLength(0);
	});

	it("when the transport's answer throws as the read inspects it", async () => {
		const boom = new TypeError("status unreadable");
		const fetch: FetchLike = async (): Promise<FetchResponse> => ({
			get status(): number {
				throw boom;
			},
			text: async () => "",
		});
		const err = await settled(fetchDocument(fetch, "https://doc.example/d"));
		expect(err).toBeInstanceOf(DirectoryUnavailable);
		expect((err as Error).cause).toBe(boom);
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
