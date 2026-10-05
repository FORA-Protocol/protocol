// The transport contract the fetching resolvers share, and the reads built on it: the
// injected FetchLike, the response shape it answers with, and the one GET every document
// read goes through. Edge-safe: nothing here imports a Node module or touches a Node
// global, so the edge entry (resolvers/edge.ts) and a Workers, Fastly or Deno runtime can
// use it with any fetch-compatible callable. The Node-only transports that default it, the
// undici client with the dial-time SSRF guard, live in resolvers/http.ts.

import { DirectoryUnavailable } from "./errors.ts";

// Lenient UTF-8, as Node's Buffer#toString decodes: an invalid sequence becomes U+FFFD
// and a leading byte-order mark is kept, so a body that starts with one still fails
// JSON.parse rather than being silently accepted.
const LENIENT_UTF8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

/** decodeUtf8 decodes `bytes` as lenient UTF-8, byte-order mark kept. */
export function decodeUtf8(bytes: Uint8Array): string {
	return LENIENT_UTF8.decode(bytes);
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
	 * reports it. A key-directory read refuses one. */
	redirected?: boolean;
}

/** What a read asks of the transport beyond the URL: a WHATWG RequestInit subset.
 * `redirect: "manual"` asks it not to follow a redirect and to answer the 3xx itself;
 * a key-directory read passes it, because a directory is never fetched through a
 * redirect. The shipped transports honour it, and the global fetch reads the same
 * member. */
export interface FetchInit {
	redirect?: "follow" | "manual";
}

/** An injected HTTP GET. The edge entry (@fora-protocol/sdk/resolvers/edge) has no
 * default and every reader there takes one; the Node entry
 * (@fora-protocol/sdk/resolvers) defaults to its SSRF-guarded undici transport. A
 * FetchLike that ignores `init` still cannot hand a key directory over a redirect: the
 * read refuses a 3xx and a response marked `redirected`. */
export type FetchLike = (url: string, init?: FetchInit) => Promise<FetchResponse>;

/** One document as it was served: its bytes, the media type it was labelled with, and
 * its response headers. */
export interface Fetched {
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

/** GET `url` and return the body, its media type and its headers. A transport failure
 * or a non-200 status throws DirectoryUnavailable (fail-closed halt) — the taxonomy a
 * composite relies on to distinguish an outage from an unknown key. A blocked SSRF
 * target and a body past the cap are transport failures and surface the same way
 * (never a valid empty doc). The one GET every document read shares.
 *
 * `noRedirect` is set for a key directory, which is never fetched through a redirect:
 * its address is the origin its signer committed to, and a redirect would hand key
 * lookup to another one. The transport is asked not to follow, and a 3xx or a response
 * marked redirected fails the read. A revocation list and the manifest follow the
 * transport's bounded redirect chain. */
export async function fetchDocument(
	fetchFn: FetchLike,
	url: string,
	opts: { noRedirect?: boolean } = {},
): Promise<Fetched> {
	let resp: FetchResponse;
	let body: Uint8Array;
	try {
		resp = opts.noRedirect === true ? await fetchFn(url, { redirect: "manual" }) : await fetchFn(url);
		if (opts.noRedirect === true && (resp.redirected === true || (resp.status >= 300 && resp.status < 400))) {
			throw new DirectoryUnavailable(`a key directory is never fetched through a redirect: ${url}`);
		}
		if (resp.status !== 200) {
			throw new DirectoryUnavailable(`status ${resp.status} for ${url}`);
		}
		body =
			resp.arrayBuffer !== undefined
				? new Uint8Array(await resp.arrayBuffer())
				: new TextEncoder().encode(await resp.text());
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

/** GET `url` and return the body text: fetchDocument without the media type, for a
 * reader that has no use for it. */
export async function fetchStrict(
	fetchFn: FetchLike,
	url: string,
): Promise<string> {
	return decodeUtf8((await fetchDocument(fetchFn, url)).body);
}

/** Best-effort GET: returns the body text on 200, or `undefined` on any
 * transport/status failure. The revocation refresh uses this so a fetch blip
 * leaves the prior snapshot in place (Go: best-effort refresh) rather than
 * propagating — a stale-but-present snapshot is safer than dropping revocations. */
export async function fetchSoft(
	fetchFn: FetchLike,
	url: string,
): Promise<string | undefined> {
	try {
		const resp = await fetchFn(url);
		if (resp.status !== 200) return undefined;
		return await resp.text();
	} catch {
		return undefined;
	}
}
