// sdk/ts outbound auto-sign transport — the TS sibling of Go
// core.NewSigningTransport (sdk/go/core/transport.go) and Python
// SigningTransport / SignedOutbound (sdk/python/fora_sdk/signing_transport.py).
//
// Core Invariant: this module is a pure ORCHESTRATION of the already
// byte-parity-locked primitives signRequest / appendSignature (core/sign-request.ts)
// and the clockWindow (core/window.ts). It stamps EVERY covered header
// at the value that entered the signature base — Content-Digest / Signature-Agent /
// Signature-Input / Signature, and the Authorization whose value may be empty —
// byte-identical to the shared Go/Python oracle, forwards the request body UNMODIFIED,
// and adds NO new crypto and NO new signature-base rendering.
//
// Two faces, mirroring Python's transport-neutral shape (the cleaner fit for TS's
// multi-runtime edge, which has no Go http.RoundTripper):
//   - signOutbound(...): the transport-NEUTRAL header core (Python SignedOutbound
//     sibling) — computes the RFC 9421 headers for one request and returns them
//     with the untouched body. Wraps no client.
//   - createSigningTransport(send, opts): wraps a WHATWG-fetch-shaped outbound seam
//     send(url, init) — buffers the body, computes headers via signOutbound, and
//     forwards the SAME body bytes to send.
//
// Every signature names its signer's key directory: the transport's own
// signatureAgent, or the one a per-request SignerSource returns. On the append branch
// the new member is added to the request's Signature-Agent dictionary beside the
// earlier signers' members, which stay untouched (Go helpers.AppendSignature).

import { encodeBase64Url } from "../src/base64url.ts";
import { SignatureAgentHeader } from "../src/wire.ts";
import {
	appendSignature,
	type PriorSignatures,
	type SignRequestOptions,
	signRequest,
} from "./sign-request.ts";
import { MAX_SIGNATURE_LIFETIME } from "./wba.ts";
import { clockWindow, type Window } from "./window.ts";

// The DEFAULT freshness window: clock-derived created + MAX_SIGNATURE_LIFETIME, the
// longest a Web Bot Auth request signature may live (Go signWindow). A caller with its
// own freshness policy injects a shorter window; a longer one is refused at signing. The
// clock reads seconds (Date.now()/1000); clockWindow floors to Go's .Unix().
const DEFAULT_WINDOW_TTL_SEC = MAX_SIGNATURE_LIFETIME;

function defaultWindow(): Window {
	return clockWindow(() => Date.now() / 1000, DEFAULT_WINDOW_TTL_SEC);
}

// Entropy per signature nonce: 64 bytes, 86 base64url characters. 64 bytes is the
// length the Web Bot Auth test vectors use, and widely deployed WBA verifiers refuse a
// nonce of any other length. Matches Go and Python.
const NONCE_BYTES = 64;

// A fresh RFC 9421 nonce from the platform CSPRNG, base64url without padding.
// getRandomValues throws when it cannot produce random bytes; the error
// propagates, so nothing is signed or sent without a nonce.
export function newNonce(): string {
	return encodeBase64Url(crypto.getRandomValues(new Uint8Array(NONCE_BYTES)));
}

// Case-insensitive header lookup over a plain header record. Incoming requests may
// spell header names in any case; the covered values (authorization, prior
// Signature state, Signature-Agent) must be read regardless of casing. Repeated
// spellings are joined, as the wire reads one field per name.
function getHeader(
	headers: Record<string, string>,
	name: string,
): string | undefined {
	const lower = name.toLowerCase();
	const values: string[] = [];
	for (const k of Object.keys(headers)) {
		if (k.toLowerCase() === lower) values.push(headers[k] as string);
	}
	return values.length === 0 ? undefined : values.join(", ").trim();
}

/**
 * mergeSigned overlays the signed headers onto the caller's, REPLACING any the caller
 * spelled in a different case rather than letting both survive.
 *
 * A plain spread would not: header names are case-insensitive on the wire, JS object keys
 * are not, so a caller's `Authorization` and a signed `authorization` become two field
 * lines. getHeader above already reads case-insensitively; this is the write side
 * agreeing with it. See docs/design-history.md, "A covered header the peer never receives
 * is not bound".
 */
function mergeSigned(
	callerHeaders: Record<string, string>,
	signedHeaders: Record<string, string>,
): Record<string, string> {
	const claimed = new Set(Object.keys(signedHeaders).map((k) => k.toLowerCase()));
	const merged: Record<string, string> = {};
	for (const [name, value] of Object.entries(callerHeaders)) {
		if (!claimed.has(name.toLowerCase())) merged[name] = value;
	}
	return { ...merged, ...signedHeaders };
}

/** Inputs for signOutbound — the transport-neutral header core. */
export interface SignOutboundOptions {
	privKey: CryptoKey;
	keyid: string;
	method: string;
	url: string;
	// Uint8Array<ArrayBuffer> (never SharedArrayBuffer-backed), matching the
	// sdk/ts WebCrypto convention (core/sign-request.ts, core/verifier.ts).
	body: Uint8Array<ArrayBuffer>;
	authorization: string;
	// The signer's key-directory origin ("https://agent.example"), written as the
	// signature's Signature-Agent member and covered. Required: empty or not an https
	// origin throws WebBotAuthError and nothing is signed.
	signatureAgent: string;
	// Freshness window; defaults to clockWindow(now, MAX_SIGNATURE_LIFETIME) when absent.
	window?: Window;
	// appendOnly routes through appendSignature even for a fresh request;
	// appendSignature produces a byte-identical sig1 when prior is empty.
	appendOnly?: boolean;
	// coverPrevious makes an appended signature cover the last signature already on the
	// request (SignRequestOptions.coverPrevious). Read on the append branch only.
	coverPrevious?: boolean;
	// Prior signature state carried by the incoming request.
	prior?: PriorSignatures;
	// Nonce source, called once per signature; defaults to 64 random bytes,
	// base64url. Replace it only for deterministic output in tests. An empty nonce
	// is refused: without one, identical requests in one second collide.
	nonce?: () => string;
}

/** The RFC 9421 header set (plus the untouched body) a signed request carries. */
export interface SignedOutbound {
	headers: Record<string, string>;
	body: Uint8Array<ArrayBuffer>;
}

/**
 * signOutbound computes the Web Bot Auth Signature-Agent and the RFC 9421
 * Content-Digest / Signature-Input / Signature headers for one outbound request and
 * returns them with the body untouched — the transport-neutral core (Python
 * SignedOutbound sibling). It orchestrates the parity-locked primitives:
 * appendSignature when appendOnly is set OR a prior Signature is present, signRequest
 * otherwise. Throws, before anything is signed, when the signer's directory is missing
 * or not an https origin, the window is longer than MAX_SIGNATURE_LIFETIME, or the
 * prior Signature-Agent cannot take another member (WebBotAuthError).
 *
 * It returns EVERY covered header at the value that entered the signature base, empty
 * values included — see the emit below for why. The keys are LOWERCASE, which is the
 * spelling the corpus records and Python emits, and is what lets a merge over a caller's
 * own headers replace rather than duplicate.
 */
export async function signOutbound(
	o: SignOutboundOptions,
): Promise<SignedOutbound> {
	const [created, expires] = (o.window ?? defaultWindow())();
	const nonce = (o.nonce ?? newNonce)();
	if (nonce === "") {
		throw new Error("signing transport: nonce source returned an empty nonce");
	}
	const signOpts: SignRequestOptions = {
		method: o.method,
		url: o.url,
		body: o.body,
		authorization: o.authorization,
		signatureAgent: o.signatureAgent,
		keyid: o.keyid,
		created,
		expires,
		nonce,
	};
	const prior = o.prior ?? { signatureInput: "", signature: "" };
	const chained = (o.appendOnly ?? false) || prior.signature !== "";
	const signed = chained
		? await appendSignature(o.privKey, prior, { ...signOpts, coverPrevious: o.coverPrevious ?? false })
		: await signRequest(o.privKey, signOpts);

	// EVERY covered header is emitted, at exactly the value that entered the signature
	// base — the empty authorization included. A verifier rebuilds the base from the
	// request it received, so a value bound but never sent is not bound at all: it reads
	// the covered names off signature-input, finds nothing on the wire under one of them,
	// and refuses. See docs/design-history.md, "A covered header the peer never receives
	// is not bound", for why, and why the emitted key is LOWERCASE (a signed key spelled
	// differently from the caller's survives the merge beside it, putting the name on the
	// wire twice).
	//
	// Taken straight off `signed`, never re-read from `o`: the primitive echoes what it
	// bound, so there is one place the emitted value can come from and no way for the two
	// to drift.
	const headers: Record<string, string> = {
		"content-digest": signed.contentDigest,
		"signature-input": signed.signatureInput,
		signature: signed.signature,
		authorization: signed.authorization,
		[SignatureAgentHeader.toLowerCase()]: signed.signatureAgent,
	};
	return { headers, body: o.body };
}

/** The WHATWG-fetch-shaped outbound request the transport inspects / forwards. */
export interface OutboundInit {
	method?: string;
	headers?: Record<string, string>;
	body?: Uint8Array<ArrayBuffer>;
}

/** The seam createSigningTransport wraps: a WHATWG-fetch-shaped send(url, init). */
export type OutboundSend<R> = (url: string, init: OutboundInit) => Promise<R>;

/** What a sign predicate or a signer source inspects about one outbound request. */
export interface OutboundRequest {
	url: string;
	method: string;
	headers: Record<string, string>;
	body: Uint8Array<ArrayBuffer> | undefined;
}

/** The identity one signature is made as: the private key, its keyid, and the https
 * origin of the key directory that publishes it. */
export interface SignerIdentity {
	privKey: CryptoKey;
	keyid: string;
	signatureAgent: string;
}

/**
 * SignerSource returns the signer and its Signature-Agent directory origin for one
 * request, for a service that signs as many identities: an identity service signing as
 * the calling agent, a console signing as the calling publisher (Go core.SignerSource).
 * A source that throws, or returns no signer, means nothing is sent.
 */
export type SignerSource = (req: OutboundRequest) => SignerIdentity | undefined | Promise<SignerIdentity | undefined>;

/**
 * Options for createSigningTransport — an idiomatic TS options object, one field per Go
 * WithX. privKey/keyid/signatureAgent name the one identity the transport signs as;
 * signerSource replaces all three with a per-request identity. window replaces the
 * default freshness window; appendOnly forces the append branch and coverPrevious makes
 * an appended signature cover the last earlier one; predicate gates which requests are
 * signed (default: sign every bodied request).
 */
export interface SigningTransportOptions {
	privKey?: CryptoKey;
	keyid?: string;
	/** The signer's key-directory origin ("https://agent.example"), written as every
	 * signature's Signature-Agent member. Required unless signerSource supplies it: a
	 * request signed with no directory is refused (WebBotAuthError) and never sent. */
	signatureAgent?: string;
	/** Resolves the signer and its directory per request, in place of privKey, keyid and
	 * signatureAgent (Go WithSignerSource). Every signature it makes follows the same
	 * profile, with a fresh nonce. */
	signerSource?: SignerSource;
	window?: Window;
	/** Route EVERY signed request through appendSignature (Go WithAppendSigner): a fresh
	 * request gets sig1, a request already carrying signatures gets one more with its own
	 * label and Signature-Agent member, leaving the earlier ones untouched. */
	appendOnly?: boolean;
	/** Make an appended signature cover the last signature already on the request, as
	 * WG-00 §5.2.2 permits a party that forwards a request unchanged in every component
	 * that signature covers (Go WithCoverPrevious). Append branch only. A party that
	 * changed the request, such as a Broker re-packaging a purchase, must not set it. */
	coverPrevious?: boolean;
	predicate?: (req: OutboundRequest) => boolean;
	// Nonce source for each signature (see SignOutboundOptions.nonce). Every signed
	// request gets a fresh nonce by default, so identical requests in the same second
	// are not refused as replays. Resending signed bytes unchanged is still a replay.
	nonce?: () => string;
}

// identityFor returns the signer and directory for req: the source's when one is
// configured, the transport's own otherwise.
async function identityFor(opts: SigningTransportOptions, req: OutboundRequest): Promise<SignerIdentity> {
	if (opts.signerSource === undefined) {
		if (opts.privKey === undefined || opts.keyid === undefined) {
			throw new TypeError("signing transport: no signer configured (privKey and keyid, or signerSource)");
		}
		return { privKey: opts.privKey, keyid: opts.keyid, signatureAgent: opts.signatureAgent ?? "" };
	}
	const identity = await opts.signerSource(req);
	if (identity === undefined) throw new Error("signing transport: signer source returned no signer");
	return identity;
}

/**
 * createSigningTransport wraps a WHATWG-fetch-shaped send and returns a send with the
 * same shape that auto-signs each outbound request: it buffers the body, computes the
 * Signature-Agent and RFC 9421 headers via signOutbound, merges them, and forwards the
 * SAME body bytes to the wrapped send. A request with no body — or one the predicate
 * excludes — passes through UNSIGNED (there is nothing to bind a Content-Digest to);
 * that is not an error. A request already carrying a Signature gets an additional
 * signature (appendSignature) rather than having its signature replaced. A signing
 * refusal — no signer, no directory, a source error — rejects, and the wrapped send is
 * never called. Naming stays family-consistent with the newXResolver siblings; the
 * whole-surface newX -> create rename is a separate, broader change, not this module's
 * concern.
 */
export function createSigningTransport<R>(
	send: OutboundSend<R>,
	opts: SigningTransportOptions,
): OutboundSend<R> {
	const window = opts.window ?? defaultWindow();
	return async (url, init) => {
		const body = init.body;
		const method = init.method ?? "GET";
		const headers = init.headers ?? {};

		// No body / predicate-excluded: pass through UNSIGNED, body untouched.
		const excluded =
			opts.predicate !== undefined &&
			!opts.predicate({ url, method, headers, body });
		if (body === undefined || excluded) {
			return send(url, init);
		}

		const identity = await identityFor(opts, { url, method, headers, body });
		const prior: PriorSignatures = {
			signatureInput: getHeader(headers, "signature-input") ?? "",
			signature: getHeader(headers, "signature") ?? "",
			signatureAgent: getHeader(headers, SignatureAgentHeader) ?? "",
			contentDigest: getHeader(headers, "content-digest") ?? "",
		};

		const signed = await signOutbound({
			privKey: identity.privKey,
			keyid: identity.keyid,
			method,
			url,
			body,
			authorization: getHeader(headers, "authorization") ?? "",
			signatureAgent: identity.signatureAgent,
			window,
			appendOnly: opts.appendOnly ?? false,
			coverPrevious: opts.coverPrevious ?? false,
			prior,
			...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
		});

		// Forward the SAME body bytes (body integrity — buffer for the digest
		// but never consume/replace the payload; Go resets req.Body + GetBody).
		return send(url, {
			...init,
			headers: mergeSigned(headers, signed.headers),
			body,
		});
	};
}
