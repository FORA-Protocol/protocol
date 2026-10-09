// The Node-only HTTP transports the fetching resolvers default to. Transport-neutral
// per the SDK dependency policy (the resolvers accept an injected fetch-compatible
// callable, whose contract is in fetch.ts) but the DEFAULT transport runs on a
// maintained HTTP client (undici) instead of a hand-rolled node:http request. undici
// owns the response state machine — status, redirects, 1xx, decompression — so this
// module owns only the SSRF guard (an injectable connection-level connector) and the
// bounded body read. It imports undici and node:dns, so only the Node entry
// (resolvers/index.ts) and the client reach it; the edge entry (resolvers/edge.ts) never
// does. Integration tests / on-prem deployments that must reach a private origin inject
// their own FetchLike (the escape hatch).
//
// A document read asks these transports not to follow redirects and follows them itself
// (resolvers/fetch.ts), so the reader vets every hop's scheme and counts the chain
// whatever transport it was given. The redirect-cap interceptor below still bounds a
// caller that uses a transport directly.

import { lookup as dnsLookup } from "node:dns/promises";

import {
	Agent,
	buildConnector,
	type Dispatcher,
	interceptors,
	request as undiciRequest,
} from "undici";

import { type FetchLike, type FetchResponse, MAX_DOC_BYTES } from "./fetch.ts";
import { allowedScheme, blockedAddress, MAX_REDIRECTS } from "./ssrf.ts";

// The transport contract and the document GET are edge-safe and live in fetch.ts; they
// are re-exported here so every import of them through this module keeps working.
export {
	type FetchInit,
	type FetchLike,
	type FetchResponse,
	type Fetched,
	fetchDocument,
	fetchSoft,
	fetchStrict,
	mediaTypeEssence,
} from "./fetch.ts";

/** Bounds one GET of the guarded default transport so a slow origin cannot pin a
 * Resolve call or the poller (Go: defaultWBAHTTPTimeout). A document read also carries
 * its own whole-read deadline (fetch.ts), which arrives as the caller's signal. */
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;

/** The signal one GET runs under: the per-request timeout, and the caller's signal when
 * it passed one, whichever fires first. */
function requestSignal(caller: AbortSignal | undefined): AbortSignal {
	const timeout = AbortSignal.timeout(DEFAULT_HTTP_TIMEOUT_MS);
	return caller === undefined ? timeout : AbortSignal.any([caller, timeout]);
}

/** An SSRF error surfaced when the guarded transport refuses to dial a target.
 * fetchStrict/fetchSoft see it as an ordinary transport failure (fail-closed
 * DirectoryUnavailable / best-effort undefined), so the guard never resolves a
 * blocked host as a valid — merely empty — directory. */
export class SsrfBlockedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "SsrfBlockedError";
	}
}

/** The GENERIC dial-refusal the guard raises for EVERY refuse reason — an
 * unresolvable host, an empty resolution, or a resolved-reserved address all yield
 * the SAME message. It names only the caller-supplied host (already known to the
 * caller), never the resolved IP, and does not distinguish an NXDOMAIN from a
 * resolved-private answer, so it cannot serve as a pre-auth DNS oracle against
 * internal networks. Identical wording across the three SDKs. */
function ssrfRefusal(host: string): SsrfBlockedError {
	return new SsrfBlockedError(`SSRF guard: refusing to dial ${host}`);
}

/** An SSRF-guarded undici connector, injectable into any undici Dispatcher.
 *
 * DX: `new Agent({ connect: ssrfGuard() })`. The guard runs at the CONNECTION
 * (dial) seam — the only place the DNS-REBINDING window is actually closed: it
 * resolves the host, checks EVERY resolved address against blockedAddress, and
 * pins the dial to a checked IP literal (undici does not re-resolve it), while
 * the TLS `servername` keeps the original hostname so cert/SNI validation is
 * unaffected. Because undici re-dials every followed redirect through the same
 * connector, each redirect hop is re-vetted too (consistent with the Go and
 * Python guards); a redirect into a non-http(s) scheme is a WHATWG-fetch network
 * error, so the scheme allowlist is deny-by-default without a redirect handler. */
export function ssrfGuard(): buildConnector.connector {
	const base = buildConnector({});
	return (opts, cb) => {
		const originalHostname = opts.hostname;
		dnsLookup(originalHostname, { all: true })
			.then((records) => {
				// Fail closed on an empty resolution OR any reserved address in the set (the
				// multi-address any-reserved rule: a MIXED public/reserved answer is refused
				// outright, so a rebinding/round-robin trick cannot land a later connect on
				// the reserved member). Every refuse path raises the SAME generic error.
				if (
					records.length === 0 ||
					records.some(({ address }) => blockedAddress(address))
				) {
					cb(ssrfRefusal(originalHostname), null);
					return;
				}
				// Every address passed; pin to the first (all public) checked IP literal
				// — no re-resolution at connect — and keep servername = original host.
				base(
					{
						...opts,
						hostname: records[0]?.address ?? originalHostname,
						servername: opts.servername || originalHostname,
					},
					cb,
				);
			})
			.catch(() => {
				cb(ssrfRefusal(originalHostname), null);
			});
	};
}

/** The single guarded Dispatcher backing the default guarded transport. The SSRF
 * connector vets + pins every dial (initial and each followed redirect hop); the
 * composed redirect interceptor bounds the chain to the shared MAX_REDIRECTS cap so
 * undici does not inherit its ~20-hop default. Beyond the cap the interceptor stops
 * following and surfaces the 3xx as an ordinary non-2xx (fail-closed at fetchStrict). */
const guardedBase = new Agent({ connect: ssrfGuard() });
const guardedAgent = guardedBase.compose(
	interceptors.redirect({ maxRedirections: MAX_REDIRECTS }),
);

/** Reads a response body, bounded to MAX_DOC_BYTES. Iterates the body stream
 * (async-iterable in Node) so a hostile origin cannot force an unbounded read, and
 * REFUSES a body past the cap rather than truncating it: a truncated document that
 * happens to decode is worse than a refusal, and a truncated license document would
 * be reported as a digest mismatch it is not. The refusal is thrown inside the
 * FetchLike, so fetchStrict reports it as DirectoryUnavailable and fetchSoft as
 * undefined, like every other failed read. */
async function readBounded(
	body: AsyncIterable<Uint8Array> | null,
): Promise<Uint8Array> {
	if (body === null) return new Uint8Array();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for await (const chunk of body) {
		total += chunk.length;
		if (total > MAX_DOC_BYTES) {
			throw new Error(`document exceeds the ${MAX_DOC_BYTES} byte cap`);
		}
		chunks.push(chunk);
	}
	return new Uint8Array(Buffer.concat(chunks.map((c) => Buffer.from(c))));
}

/** The FetchResponse a bounded read answers with: the bytes as read, their UTF-8
 * text, and the response's headers. */
function boundedResponse(
	status: number,
	body: Uint8Array,
	header: (name: string) => string | null,
): FetchResponse {
	return {
		status,
		text: () => Promise.resolve(Buffer.from(body).toString("utf8")),
		arrayBuffer: () =>
			Promise.resolve(
				body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer,
			),
		headers: { get: header },
	};
}

/** GET `url` through `dispatcher` (an undici Agent carrying the SSRF connector
 * and the redirect-cap interceptor), gating the initial scheme with `allowScheme`
 * and bounding the body to MAX_DOC_BYTES. undici owns status/redirect/1xx/decompress
 * and the interceptor bounds the redirect chain, so this owns only the scheme gate
 * and the body cap. A blocked target surfaces as the precise SsrfBlockedError (the
 * connector rejects directly or via `err.cause`); non-guard errors propagate. The
 * one request path both guarded faces share, so their wiring cannot drift. */
async function requestBounded(
	url: string,
	dispatcher: Dispatcher,
	allowScheme: (scheme: string) => boolean,
	signal: AbortSignal | undefined,
): Promise<FetchResponse> {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch (err) {
		throw new SsrfBlockedError(
			`SSRF guard: unparseable url ${url}: ${String(err)}`,
		);
	}
	// Gate the scheme BEFORE any dial. URL.protocol carries a trailing colon ("https:").
	const scheme = parsed.protocol.replace(/:$/, "");
	if (!allowScheme(scheme)) {
		throw new SsrfBlockedError(
			`SSRF guard: refusing disallowed scheme ${parsed.protocol}`,
		);
	}
	let resp: Awaited<ReturnType<typeof undiciRequest>>;
	try {
		resp = await undiciRequest(url, {
			dispatcher,
			signal: requestSignal(signal),
		});
	} catch (err) {
		if (err instanceof SsrfBlockedError) throw err;
		const cause = (err as { cause?: unknown }).cause;
		if (cause instanceof SsrfBlockedError) throw cause;
		throw err;
	}
	const body = await readBounded(resp.body as AsyncIterable<Uint8Array> | null);
	return boundedResponse(resp.statusCode, body, (name) => {
		const value = resp.headers[name.toLowerCase()];
		if (value === undefined) return null;
		return Array.isArray(value) ? value.join(", ") : value;
	});
}

/** The SSRF-guarded default transport. The directory host is derived from a
 * caller-supplied Signature-Agent and the fetch runs BEFORE the ed25519 check,
 * so an unguarded default would be a pre-auth SSRF lever. Runs on undici through
 * the guarded connector (see ssrfGuard): the initial URL's scheme is vetted
 * deny-by-default, every dial (initial + each redirect hop) is address-checked and
 * pinned, the redirect chain is bounded to MAX_REDIRECTS, and undici owns
 * status/redirect/1xx so a non-2xx is an ordinary response, never a crash. */
export const guardedFetch: FetchLike = (url, init) =>
	requestBounded(
		url,
		init?.redirect === "manual" ? guardedBase : guardedAgent,
		allowedScheme,
		init?.signal,
	);

// ---------------------------------------------------------------------------
// The ONE env-driven, best-effort guarded fetch factory.
// ---------------------------------------------------------------------------

/** Read a boolean env flag: true iff the value is "true" (any case) or "1". Every
 * other value (including unset and "0") is false. */
function envFlag(name: string): boolean {
	return ["true", "1"].includes((process.env[name] ?? "").toLowerCase());
}

/** Whether the dial-time address guard is disabled (SKIP_SSRF). Default: off.
 *
 * Exported because the client tier builds its own dispatchers and has to honour the same
 * deployment flag this tier does — Go reads it in NewGuardedTransport and Python in
 * guarded_client, so a TypeScript client that ignored it would be the one place the
 * documented opt-out did nothing. */
export function skipSSRF(): boolean {
	return envFlag("SKIP_SSRF");
}

/** Whether plaintext http is permitted (ALLOW_INSECURE); else https-only. Default: off. */
function allowInsecure(): boolean {
	return envFlag("ALLOW_INSECURE");
}

/** The two-flag scheme decision: https always, http only under ALLOW_INSECURE,
 * everything else denied (a scheme denylist is unwinnable — ftp, telnet, gopher,
 * file, data, …). Case-insensitive. */
export function schemeGuardAllows(scheme: string): boolean {
	const s = scheme.toLowerCase();
	if (s === "https") return true;
	return s === "http" && allowInsecure();
}

/**
 * requireScheme refuses a URL this SDK will not dial, BEFORE any dial happens.
 *
 * The connector returned by ssrfGuard is an ADDRESS pin — it decides what a hostname is
 * allowed to resolve to, and it never sees the scheme, because by then the URL has already
 * been reduced to a host and a port. So a dispatcher built from it alone will happily carry
 * an RFC 9421 signature, or a proof of possession, over plaintext http. The scheme is a
 * separate decision and needs a separate gate: Go states it in schemeGuardRoundTripper and
 * Python in _SchemeGuardTransport, both wrapping the transport so it applies to whatever
 * base a caller injected. This is the same gate for the callers that dial undici directly.
 *
 * Raising SsrfBlockedError rather than a typed client failure is deliberate: the client
 * tier already classifies an unrecognised dial failure the way Go classifies this one,
 * which reaches it through the RoundTripper for the same reason.
 */
export function requireScheme(url: string): void {
	let parsed: URL;
	try {
		parsed = new URL(url);
	} catch (err) {
		throw new SsrfBlockedError(`SSRF guard: unparseable url: ${String(err)}`);
	}
	// URL.protocol carries a trailing colon ("https:").
	if (!schemeGuardAllows(parsed.protocol.replace(/:$/, ""))) {
		throw new SsrfBlockedError(
			`SSRF guard: refusing disallowed scheme ${parsed.protocol}`,
		);
	}
}

/** The ONE public env-driven best-effort guarded fetch factory — every consumer's
 * fetch for any third-party-influenceable request. Two orthogonal env flags drive
 * it: SKIP_SSRF toggles the dial-time address guard (default: on), ALLOW_INSECURE
 * toggles the scheme guard (default: https-only). There is no deployment-stack
 * allow-list and no config error. Both paths use a per-factory undici Agent that
 * ignores HTTP(S)_PROXY env, so a proxied CONNECT cannot tunnel a private target
 * past the (guarded) dial guard, and both carry the same request timeout. Returns
 * a FetchLike closing over one dispatcher. */
export function guardedFetchFromEnv(): FetchLike {
	// One dispatcher per factory: the SSRF connector (unless SKIP_SSRF) plus the
	// redirect-cap interceptor, so a proxied CONNECT cannot tunnel past the (guarded)
	// dial guard and the redirect chain is bounded to the shared MAX_REDIRECTS cap.
	const base = skipSSRF() ? new Agent() : new Agent({ connect: ssrfGuard() });
	const dispatcher = base.compose(
		interceptors.redirect({ maxRedirections: MAX_REDIRECTS }),
	);
	// A read that refuses redirects dials the base agent, which follows none: the 3xx
	// comes back as the answer and the read fails on it.
	return (url, init) =>
		requestBounded(
			url,
			init?.redirect === "manual" ? base : dispatcher,
			schemeGuardAllows,
			init?.signal,
		);
}

/** Default transport for a resolver whose URL is a FIXED, operator-chosen address
 * (the well-known JWKS): a plain fetch, NOT SSRF-guarded. An on-prem JWKS may
 * legitimately be private, and the operator rather than an attacker chose it.
 *
 * Which default a resolver takes follows its URL's PROVENANCE, and that is the
 * whole rule — the Go oracle states it in the options struct these ports mirror.
 * A fixed operator-chosen URL takes this transport. A REQUEST-DERIVED host — the
 * WBA directory named by a Signature-Agent header, an Exchange domain read off an
 * offer or a registration — takes `guardedFetchFromEnv`, because the party
 * choosing the address is not the party running the process.
 *
 * The endpoint resolver in this package is request-derived and still defaults
 * here, which is a known gap being closed separately; it is not the rule. Do not
 * reach for this transport for a new resolver without first asking where its URL
 * comes from. */
export const defaultFetch: FetchLike = async (url, init) => {
	const r = await fetch(url, {
		...(init?.redirect === "manual" ? { redirect: "manual" as const } : {}),
		...(init?.signal !== undefined ? { signal: init.signal } : {}),
	});
	// Bound the body read even on the unguarded path: a misconfigured / hostile
	// well-known origin cannot force an unbounded read into the JSON decoder. The
	// WHATWG Response body is async-iterable in Node, so it reuses readBounded (the
	// same 1 MiB cap as the guarded transport and the Go/Python well-known paths).
	const body = await readBounded(
		r.body as unknown as AsyncIterable<Uint8Array> | null,
	);
	return boundedResponse(r.status, body, (name) => r.headers.get(name));
};

