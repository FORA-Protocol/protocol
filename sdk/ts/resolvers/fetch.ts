// The transport contract the fetching resolvers share, and the reads built on it: the
// injected FetchLike, the response shape it answers with, and the one GET every document
// read goes through. Edge-safe: nothing here imports a Node module or touches a Node
// global, so the edge entry (resolvers/edge.ts) and a Workers, Fastly or Deno runtime can
// use it with any fetch-compatible callable. The Node-only transports that default it, the
// undici client with the dial-time SSRF guard, live in resolvers/http.ts.
//
// The read owns its own bounds, whatever transport is injected, as Go's and Python's
// readers do: a body cap, one deadline for the whole read, the redirect cap and the scheme
// of every hop. What the transport owns is the address: which hosts it will dial at all
// (the SSRF guard and DNS pinning the Node default carries) and TLS. An edge runtime that
// injects its own fetch keeps that part, and gets the rest from here.

import { DirectoryUnavailable } from "./errors.ts";
import { allowedScheme, MAX_REDIRECTS, redirectChainRefused } from "./ssrf.ts";

/** The most bytes one document read accepts. A body past it is refused, never truncated:
 * a truncated document that happens to decode is worse than a refusal. Go's
 * maxWellKnownDocBytes and Python's _MAX_DOC_BYTES; the Node transports in http.ts bound
 * their own buffered reads by this same number. */
export const MAX_DOC_BYTES = 1 << 20; // 1 MiB

/** How long one document read may take in all: every redirect hop and the body included
 * (Go's maxDocumentFetch, Python's total fetch deadline). */
export const DOCUMENT_READ_TIMEOUT_MS = 30_000;

// Lenient UTF-8, as Node's Buffer#toString decodes: an invalid sequence becomes U+FFFD
// and a leading byte-order mark is kept, so a body that starts with one still fails
// JSON.parse rather than being silently accepted.
const LENIENT_UTF8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** decodeUtf8 decodes `bytes` as lenient UTF-8, byte-order mark kept. */
export function decodeUtf8(bytes: Uint8Array): string {
	return LENIENT_UTF8.decode(bytes);
}

/** The part of a WHATWG body stream a bounded read uses: a reader handing out byte
 * chunks, which the read cancels once it stops reading. */
export interface FetchBodyReader {
	read(): Promise<{ done: boolean; value?: Uint8Array | undefined }>;
	cancel(reason?: unknown): Promise<void>;
}

/** The minimal response shape the resolvers read — a structural subset of the
 * WHATWG `Response`, so the global `fetch` (and undici's) satisfies it.
 *
 * `headers` and `arrayBuffer` are optional so a hand-written FetchLike that predates
 * them keeps working. The document readers use both: a document whose response
 * carries no `headers` has no media type, which the manifest and WBA readers refuse,
 * and a body read without `arrayBuffer` is the UTF-8 encoding of `text()`, which is
 * not the served bytes for a license document that is not UTF-8 text. */
export interface FetchResponse {
	status: number;
	text(): Promise<string>;
	headers?: { get(name: string): string | null };
	arrayBuffer?(): Promise<ArrayBuffer>;
	/** Whether the response is the end of a followed redirect, as a WHATWG Response
	 * reports it. A read asks its transport not to follow redirects, so it refuses one. */
	redirected?: boolean;
	/** The streamed body, as a WHATWG Response carries it. A read through it stops at
	 * MAX_DOC_BYTES without taking the rest of the body; a read without it takes
	 * `arrayBuffer()` or `text()` whole and refuses the result past the cap. */
	body?: { getReader(): FetchBodyReader } | null;
}

/** What a read asks of the transport beyond the URL: a WHATWG RequestInit subset.
 * Every document read passes `redirect: "manual"` — the read follows a redirect itself,
 * vetting each hop, and a key directory is never fetched through one — and a `signal`
 * the read aborts at its deadline. The shipped transports honour both, and the global
 * fetch reads the same members. */
export interface FetchInit {
	redirect?: "follow" | "manual";
	signal?: AbortSignal;
}

/** An injected HTTP GET. The edge entry (@fora-protocol/sdk/resolvers/edge) has no
 * default and every reader there takes one; the Node entry
 * (@fora-protocol/sdk/resolvers) defaults to its SSRF-guarded undici transport. A
 * FetchLike that ignores `init` still cannot widen what a read accepts: the read refuses
 * a response marked `redirected`, bounds the body itself, and gives up at its deadline
 * whether or not the transport stops. */
export type FetchLike = (url: string, init?: FetchInit) => Promise<FetchResponse>;

/** One document as it was served: its bytes, the media type it was labelled with, and
 * its response headers. */
export interface Fetched {
	/** The URL the read was asked for, whatever redirects it followed. */
	url: string;
	body: Uint8Array;
	/** The Content-Type essence (type/subtype), lowercased, parameters stripped;
	 * undefined when the response carried none. */
	mediaType: string | undefined;
	/** A response header's value, or null when absent. A key directory's response
	 * signatures are read through it. */
	header?: (name: string) => string | null;
}

/** The type/subtype of a Content-Type value, lowercased, parameters dropped. */
export function mediaTypeEssence(header: string | null | undefined): string | undefined {
	if (header === null || header === undefined) return undefined;
	const essence = (header.split(";", 1)[0] ?? "").trim().toLowerCase();
	return essence === "" ? undefined : essence;
}

/** The statuses a read follows as a redirect: those whose Location names where the
 * document now is. Any other 3xx is an unavailable document. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** GET `url` and return the body, its media type and its headers. A transport failure
 * or a non-200 status throws DirectoryUnavailable (fail-closed halt) — the taxonomy a
 * composite relies on to distinguish an outage from an unknown key. A blocked SSRF
 * target and a body past the cap are transport failures and surface the same way
 * (never a valid empty doc). The one GET every document read shares, and the place its
 * bounds are enforced, whatever transport `fetchFn` is:
 *
 *  - the body is read up to MAX_DOC_BYTES and refused past it, never truncated;
 *  - the whole read, every hop and the body included, ends at DOCUMENT_READ_TIMEOUT_MS;
 *  - only http and https URLs are fetched, the first one included;
 *  - a redirect is followed by the read itself, never by the transport: at most
 *    MAX_REDIRECTS hops, a relative Location resolved against the current URL, and a
 *    hop refused when it leaves http(s), steps down from https to plaintext http, or
 *    carries credentials;
 *  - `noRedirect` is set for a key directory, which is never fetched through a redirect:
 *    its address is the origin its signer committed to, and a redirect would hand key
 *    lookup to another one, so any 3xx fails the read.
 *
 * A response the transport marks `redirected` is refused either way: the read asked it
 * not to follow, so the hops it took were never vetted here. */
export async function fetchDocument(
	fetchFn: FetchLike,
	url: string,
	opts: { noRedirect?: boolean } = {},
): Promise<Fetched> {
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	const expired = new Promise<never>((_resolve, reject) => {
		timer = setTimeout(() => {
			controller.abort();
			reject(new DirectoryUnavailable(`no complete answer for ${url} within ${DOCUMENT_READ_TIMEOUT_MS} ms`));
		}, DOCUMENT_READ_TIMEOUT_MS);
	});
	// The race below observes the deadline; this stops it surfacing as an unhandled
	// rejection when the read finishes first.
	expired.catch(() => undefined);
	const beforeDeadline = <T>(work: Promise<T>): Promise<T> => Promise.race([work, expired]);

	try {
		let target = url;
		let current = documentURL(url);
		let hops = 0;
		for (;;) {
			let resp: FetchResponse;
			try {
				resp = await beforeDeadline(fetchFn(target, { redirect: "manual", signal: controller.signal }));
			} catch (err) {
				if (err instanceof DirectoryUnavailable) throw err;
				throw new DirectoryUnavailable(`fetch ${url}`, { cause: err });
			}
			const isRedirect = resp.status >= 300 && resp.status < 400;
			if (resp.redirected === true || (isRedirect && opts.noRedirect === true)) {
				discardBody(resp);
				throw new DirectoryUnavailable(
					opts.noRedirect === true
						? `a key directory is never fetched through a redirect: ${url}`
						: `the transport followed a redirect it was asked not to: ${url}`,
				);
			}
			if (isRedirect && REDIRECT_STATUSES.has(resp.status)) {
				discardBody(resp);
				hops += 1;
				if (redirectChainRefused(hops)) {
					throw new DirectoryUnavailable(`more than ${MAX_REDIRECTS} redirects for ${url}`);
				}
				current = redirectTarget(current, resp.headers?.get("location") ?? null, url);
				target = current.href;
				continue;
			}
			if (resp.status !== 200) {
				discardBody(resp);
				throw new DirectoryUnavailable(`status ${resp.status} for ${url}`);
			}
			let body: Uint8Array;
			try {
				body = await beforeDeadline(readCapped(resp, url, controller.signal));
			} catch (err) {
				if (err instanceof DirectoryUnavailable) throw err;
				throw new DirectoryUnavailable(`fetch ${url}`, { cause: err });
			}
			const headers = resp.headers;
			return {
				url,
				body,
				mediaType: mediaTypeEssence(headers?.get("content-type")),
				header: (name) => headers?.get(name) ?? null,
			};
		}
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

/** The URL a read starts at: absolute, and http or https. Any other scheme names no
 * document this SDK fetches, whatever the injected transport would do with it. */
function documentURL(url: string): URL {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch {
		throw new DirectoryUnavailable(`not an absolute URL: ${url}`);
	}
	if (!allowedScheme(parsed.protocol.replace(/:$/, ""))) {
		throw new DirectoryUnavailable(`a ${parsed.protocol} URL is not fetched: ${url}`);
	}
	return parsed;
}

/** Where a redirect from `current` leads, or a refusal. The Location is resolved
 * against the current URL, as a browser resolves it, and the hop is refused when it
 * leaves http(s), steps down from https to plaintext http — an on-path party could then
 * answer for the origin — or carries credentials, which would send a different request
 * from the one the URL names. */
function redirectTarget(current: URL, location: string | null, url: string): URL {
	if (location === null || location === "") {
		throw new DirectoryUnavailable(`a redirect with no Location for ${url}`);
	}
	let next: URL;
	try {
		next = new URL(location, current);
	} catch {
		throw new DirectoryUnavailable(`a redirect to an unparseable Location for ${url}`);
	}
	if (!allowedScheme(next.protocol.replace(/:$/, ""))) {
		throw new DirectoryUnavailable(`a redirect to a ${next.protocol} URL for ${url}`);
	}
	if (current.protocol === "https:" && next.protocol === "http:") {
		throw new DirectoryUnavailable(`a redirect from https to plaintext http for ${url}`);
	}
	if (next.username !== "" || next.password !== "") {
		throw new DirectoryUnavailable(`a redirect carrying credentials for ${url}`);
	}
	return next;
}

/** Read a 200's body, refusing it past MAX_DOC_BYTES. Through the streamed body the
 * read stops as soon as the total passes the cap and cancels the rest, so a body that
 * never ends costs at most the cap; without one it takes `arrayBuffer()` (or `text()`)
 * whole and refuses the result. A chunk is accepted by ArrayBuffer.isView rather than
 * instanceof, so a stream from another realm (a Worker isolate, a vm context) reads the
 * same. */
async function readCapped(resp: FetchResponse, url: string, signal: AbortSignal): Promise<Uint8Array> {
	const stream = resp.body;
	if (stream === undefined || stream === null) {
		const bytes = resp.arrayBuffer !== undefined
			? new Uint8Array(await resp.arrayBuffer())
			: new TextEncoder().encode(await resp.text());
		if (bytes.byteLength > MAX_DOC_BYTES) {
			throw new DirectoryUnavailable(`a document over the ${MAX_DOC_BYTES} byte cap: ${url}`);
		}
		return bytes;
	}
	const reader = stream.getReader();
	const stop = (): void => {
		reader.cancel().catch(() => undefined);
	};
	// At the deadline the read stops waiting on the stream; this lets the stream stop too.
	signal.addEventListener("abort", stop, { once: true });
	try {
		const chunks: Uint8Array[] = [];
		let total = 0;
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			if (value === undefined || !ArrayBuffer.isView(value)) {
				stop();
				throw new DirectoryUnavailable(`a body chunk that is not bytes for ${url}`);
			}
			total += value.byteLength;
			if (total > MAX_DOC_BYTES) {
				stop();
				throw new DirectoryUnavailable(`a document over the ${MAX_DOC_BYTES} byte cap: ${url}`);
			}
			chunks.push(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
		}
		const out = new Uint8Array(total);
		let offset = 0;
		for (const chunk of chunks) {
			out.set(chunk, offset);
			offset += chunk.byteLength;
		}
		return out;
	} finally {
		signal.removeEventListener("abort", stop);
	}
}

/** Release the body of a response the read will not use, so the transport is not left
 * holding a stream open. */
function discardBody(resp: FetchResponse): void {
	try {
		resp.body?.getReader().cancel().catch(() => undefined);
	} catch {
		// A body that cannot be read cannot be held open either.
	}
}

/** GET `url` and return the body text: fetchDocument without the media type, for a
 * reader that has no use for it. */
export async function fetchStrict(
	fetchFn: FetchLike,
	url: string,
): Promise<string> {
	return decodeUtf8((await fetchDocument(fetchFn, url)).body);
}

/** Best-effort GET: the body text on 200, or `undefined` on any failure. It is
 * fetchDocument's read, with the same cap, deadline and redirect rules, so a
 * best-effort caller is never the unbounded path. */
export async function fetchSoft(
	fetchFn: FetchLike,
	url: string,
): Promise<string | undefined> {
	try {
		return decodeUtf8((await fetchDocument(fetchFn, url)).body);
	} catch {
		return undefined;
	}
}
