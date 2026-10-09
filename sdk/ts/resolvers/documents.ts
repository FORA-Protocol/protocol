// Reading the documents the protocol defines, as a party publishes them.
//
// Four documents are served over plain HTTPS rather than answered over RPC: the
// well-known manifest (/.well-known/fora.json), the WBA key directory
// (/.well-known/http-message-signatures-directory), the key revocation list a directory
// points to, and the license document a License.uri names. This module is the one place
// each of them is fetched and decoded.
//
// Two faces read them, and they share everything up to the decision of how strict to be.
//
// - The public readers (readManifest, readWBADirectory, readRevocationList,
//   readLicenseDocument) check what a party publishes. Each refuses a document served
//   under the wrong media type, a body that fails the published strict JSON Schema of its
//   message or one of the cross-field rules, and, for a license document, bytes that do
//   not hash to uri_digest. Each resolves to the parsed generated model, or rejects; none
//   resolves to undefined. A conformance harness reads through these.
// - The resolvers (the endpoint resolver, the registration-requirements reader, the WBA
//   key resolver and the offer-directory fetch) read the same documents to route and to
//   verify. They call the lenient functions below, which skip the strict check: a reader
//   that must accept a newer protocol version cannot refuse a field it does not know.
//
// A key directory is read under the Web Bot Auth profile by both faces: it is fetched
// with no redirect, must be served as application/http-message-signatures-directory+json,
// and its response must be signed by the keys it lists (verifyDirectoryResponse). A key
// the response carries no valid signature by is never handed out. A revocation list and
// the manifest may follow up to five redirects.
//
// Every fetch goes through the transport the caller passes as `fetch`. This module is
// edge-safe and has no default: the edge entry (resolvers/edge.ts) exports these readers
// as they are. The Node entry (resolvers/index.ts) defaults the transport to
// guardedFetchFromEnv, the one the resolvers use for an address another party chose: the
// dial-time SSRF guard refuses loopback, private and metadata addresses, and the scheme
// guard refuses anything but https. SKIP_SSRF and ALLOW_INSECURE relax them for a
// sandbox. Whatever the transport, the read itself (fetchDocument in fetch.ts) caps a
// body at 1 MiB and refuses it, never truncates it, past the cap; ends the whole read at
// 30 seconds; and follows at most five redirects, refusing a hop out of http(s), from
// https down to plaintext http, or carrying credentials.

import { parseWire } from "../../../gen/ts/wire/base.ts";
import {
	KeyRevocationListSchema,
	type LicenseSchema,
	WBAFileSchema,
	WellKnownManifestSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { verifyDirectoryResponse } from "../core/directory-response.ts";
import { decodeBase64UrlStrict } from "../src/base64url.ts";
import type { Ed25519Verify } from "../src/pop.ts";
import { invalidHost } from "../src/host-ref.ts";
import { isBareHost } from "../src/hosts.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { type StrictMessage, StrictViolation, checkStrictOf } from "../src/strict-core.ts";
import { strict as KEY_REVOCATION_LIST_STRICT } from "../../../gen/ts/strict/fora.v1.KeyRevocationList.ts";
import { strict as LICENSE_STRICT } from "../../../gen/ts/strict/fora.v1.License.ts";
import { strict as WBA_FILE_STRICT } from "../../../gen/ts/strict/fora.v1.WBAFile.ts";
import { strict as WELL_KNOWN_MANIFEST_STRICT } from "../../../gen/ts/strict/fora.v1.WellKnownManifest.ts";
import { manifestVersionRefusal, WellKnownPath } from "../src/wire.ts";
import {
	DigestMismatch,
	DirectoryResponseUnsigned,
	DirectoryUnavailable,
	ManifestVersionRefused,
	MediaTypeRefused,
} from "./errors.ts";
import { decodeUtf8, type FetchLike, type Fetched, fetchDocument } from "./fetch.ts";

/** The media type /.well-known/fora.json is served under. */
export const MANIFEST_MEDIA_TYPE = "application/json";
/** The media type a Web Bot Auth key directory is served under (WG-00 §5.5). Any other
 * label, the JWK Set type application/jwk-set+json included, is refused. */
export const WBA_DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";

/** The single public well-known path a WBA identity directory is served at (Web
 * Bot Auth; the identity half of the identity/commercial split — the commercial
 * overlay stays in /.well-known/fora.json). The one shared copy across the whole SDK. */
export const WBA_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";

/** Build the full WBA identity-directory URL from a scheme and an already-joined
 * host: `${scheme}://${host}` + {@link WBA_DIRECTORY_PATH}. An empty scheme
 * defaults to https. A PURE string function — the host arrives ALREADY-JOINED (any
 * port-join / IPv6 bracketing is the caller's concern), there is NO env read and NO
 * scheme-in-host detection (those stay consumer glue). It mirrors the sdk/go
 * WBADirectoryURL oracle byte-for-byte, locked by the tri-replayed
 * wba-url-vectors.json corpus. */
export function wbaDirectoryURL(scheme: string, host: string): string {
	const s = scheme === "" ? "https" : scheme;
	return `${s}://${host}${WBA_DIRECTORY_PATH}`;
}

export type WellKnownManifest = ReturnType<typeof WellKnownManifestSchema.parse>;
export type WBAFile = ReturnType<typeof WBAFileSchema.parse>;
export type KeyRevocationList = ReturnType<typeof KeyRevocationListSchema.parse>;
export type License = ReturnType<typeof LicenseSchema.parse>;

/** One document a reader fetched and accepted. */
export interface Document<T> {
	/** The parsed generated model. */
	message: T;
	/** The Content-Type essence the document was served under, lowercased and without
	 * parameters. For the manifest and the WBA directory it is the media type the
	 * protocol names, since anything else is refused; for a revocation list, which the
	 * protocol names none for, it is whatever was served, or undefined. */
	mediaType: string | undefined;
	/** The URL that was fetched. */
	url: string;
	/** The bytes as served. */
	body: Uint8Array;
}

/** The document a License.uri names, verified against License.uri_digest. */
export interface LicenseDocument {
	/** The bytes as served. */
	body: Uint8Array;
	/** The digest of `body` in "method:hexdigest" form. Equal to the license's
	 * uri_digest, since anything else is refused. */
	digest: string;
	/** The Content-Type essence the document was served under, or undefined. The protocol
	 * names no media type for a license document, so it is not checked. */
	mediaType: string | undefined;
	/** The URL that was fetched. */
	url: string;
}

/** How a document reader dials. */
export interface ReadDocumentOptions {
	/** The transport. Required here; the Node entry's readers default it to
	 * guardedFetchFromEnv(), built for the call. */
	fetch: FetchLike;
	/** Used when a reader builds the URL from a domain. Defaults to https. */
	scheme?: string;
	/** The Ed25519 verify primitive readWBADirectory checks the directory's response
	 * signatures with, for a runtime without WebCrypto Ed25519. Defaults to WebCrypto. */
	verifyEd25519?: Ed25519Verify;
}

/** How the resolvers' lenient directory read checks a response. */
export interface DirectoryReadOptions {
	/** The epoch-ms clock the response signatures' windows are judged against. Defaults
	 * to Date.now(). */
	now?: number | undefined;
	/** The Ed25519 verify primitive the response signatures are checked with. Defaults to
	 * WebCrypto. */
	verifyEd25519?: Ed25519Verify | undefined;
}

// --- the shared reads: one fetch-and-decode per document --------------------------------

/** The URL of `host`'s well-known manifest. An empty scheme means https. */
export function manifestURL(scheme: string, host: string): string {
	return `${scheme === "" ? "https" : scheme}://${host}${WellKnownPath}`;
}

/** GET a manifest and decode it, leniently: no media type, no strict check. Resolves to
 * the text, decoded as UTF-8 once (the registration-requirements reader slices a member
 * out of it to compile from the bytes as served), and its JSON value. A body that is not
 * JSON throws DirectoryUnavailable. No member is read here: each caller applies the
 * version gate first, under its own verdict. */
export async function fetchManifest(
	fetchFn: FetchLike,
	url: string,
): Promise<{ text: string; doc: unknown }> {
	const fetched = await fetchDocument(fetchFn, url);
	const text = decodeUtf8(fetched.body);
	try {
		return { text, doc: JSON.parse(text) };
	} catch (err) {
		throw new DirectoryUnavailable(`manifest decode ${url}`, { cause: err });
	}
}

/** GET `url`, with no redirect, and decode the body as a WBAFile, leniently: an unknown
 * member is a newer minor version, not a reason to stop verifying. The media type must be
 * WBA_DIRECTORY_MEDIA_TYPE. The file returned lists only the keys that signed the
 * response (signedDirectoryKeys), so no caller can hand out a key the directory did not
 * sign for. `opts` carries the clock the response signatures' windows are judged against
 * and the Ed25519 primitive they are checked with. The one read of a directory the WBA key resolver and the offer-directory
 * fetch share, so the two never drift. Every failure throws DirectoryUnavailable. */
export async function fetchWBAFile(
	fetchFn: FetchLike,
	url: string,
	opts: DirectoryReadOptions = {},
): Promise<WBAFile> {
	const fetched = await fetchDocument(fetchFn, url, { noRedirect: true });
	if (fetched.mediaType !== WBA_DIRECTORY_MEDIA_TYPE) {
		throw new DirectoryUnavailable(`wba directory ${url}`, {
			cause: new MediaTypeRefused(`${url} was served with ${JSON.stringify(fetched.mediaType ?? "")}`),
		});
	}
	const file = lenient(fetched, WBAFileSchema, "wba directory decode");
	try {
		return await signedDirectoryKeys(fetched, file, opts.now ?? Date.now(), opts.verifyEd25519);
	} catch (err) {
		throw new DirectoryUnavailable(`wba directory signature ${url}`, { cause: err });
	}
}

/**
 * signedDirectoryKeys returns a copy of `file` listing only the keys whose response
 * signature verifies, checked against the authority `fetched` was read from, through
 * `verifyEd25519` when one is given and WebCrypto otherwise. A key that
 * is not an Ed25519 key cannot sign and is dropped with the rest. It throws for a
 * response listing keys that cannot be checked at all: a Content-Digest that does not
 * match the body, or no response signature. A directory listing no key has nothing to
 * sign and is returned as it is.
 */
export async function signedDirectoryKeys(
	fetched: Fetched,
	file: WBAFile,
	now: number,
	verifyEd25519?: Ed25519Verify,
): Promise<WBAFile> {
	const keys = file.keys ?? [];
	if (keys.length === 0) return file;
	const pubs = keys.map(wbaPublicKey);
	const verified = await verifyDirectoryResponse(
		requestAuthority(fetched.url),
		{ get: (name) => fetched.header?.(name) ?? null },
		fetched.body as Uint8Array<ArrayBuffer>,
		pubs.filter((p): p is Uint8Array<ArrayBuffer> => p !== undefined),
		Math.floor(now / 1000),
		{ verifyEd25519 },
	);
	const signed: typeof keys = [];
	for (const [i, key] of keys.entries()) {
		const pub = pubs[i];
		if (pub !== undefined && verified.has(await thumbprint(pub))) signed.push(key);
	}
	return { ...file, keys: signed };
}

// wbaPublicKey decodes a listed key's Ed25519 public key, or undefined when the key is
// not one. kty/crv are matched case-insensitively, the SDK convention the WBA resolver
// applies when it selects a key.
function wbaPublicKey(key: NonNullable<WBAFile["keys"]>[number]): Uint8Array<ArrayBuffer> | undefined {
	if (key.kty.toUpperCase() !== "OKP" || key.crv.toLowerCase() !== "ed25519") return undefined;
	const raw = decodeBase64UrlStrict(key.x);
	return raw !== undefined && raw.length === 32 ? raw : undefined;
}

/** The RFC 9421 @authority of a fetch of `url`: the host, lowercased, with the port
 * only when it is not the scheme's default (the WHATWG URL host already omits it), and
 * an IPv6 literal in brackets. */
export function requestAuthority(url: string): string {
	return new URL(url).host.toLowerCase();
}

/** GET `url` and decode the body as a KeyRevocationList, leniently. Every failure throws
 * DirectoryUnavailable; the WBA resolver's revocation refresh contains it and keeps the
 * snapshot it holds. */
export async function fetchRevocationList(
	fetchFn: FetchLike,
	url: string,
): Promise<KeyRevocationList> {
	return lenient(await fetchDocument(fetchFn, url), KeyRevocationListSchema, "revocation list decode");
}

function lenient<T>(fetched: Fetched, schema: { parse(v: unknown): T }, what: string): T {
	try {
		return schema.parse(JSON.parse(decodeUtf8(fetched.body)));
	} catch (err) {
		throw new DirectoryUnavailable(`${what} ${fetched.url}`, { cause: err });
	}
}

// --- the checks a public reader applies ------------------------------------------------

/** What the contract says about one document: its message's strict check, compiled at
 * build time, and the media type it is served under when the protocol names one. */
export interface DocumentKind<T> {
	strict: StrictMessage;
	schema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } };
	mediaType: string | undefined;
	/** Whether `ver` is read before any other member (the manifest's rule). */
	versionGate: boolean;
	/** Carries the model type; never read. */
	readonly model?: T;
}

export const MANIFEST: DocumentKind<WellKnownManifest> = {
	strict: WELL_KNOWN_MANIFEST_STRICT,
	schema: WellKnownManifestSchema,
	mediaType: MANIFEST_MEDIA_TYPE,
	versionGate: true,
};
export const WBA_DIRECTORY: DocumentKind<WBAFile> = {
	strict: WBA_FILE_STRICT,
	schema: WBAFileSchema,
	mediaType: WBA_DIRECTORY_MEDIA_TYPE,
	versionGate: false,
};
export const REVOCATION_LIST: DocumentKind<KeyRevocationList> = {
	strict: KEY_REVOCATION_LIST_STRICT,
	schema: KeyRevocationListSchema,
	mediaType: undefined,
	versionGate: false,
};

// ignoreBOM: false is the default, spelled out for the Workers runtime types.
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

/**
 * accept checks a fetched document as `kind` and parses it, or throws. The checks run in
 * the order the contract reads a document: the media type, when the protocol names one;
 * the body as JSON; for the manifest, `ver` before any other member; then the strict
 * schema and the cross-field rules. Pure: the document-check corpus replays it with the
 * bytes and the label it carries, so the three languages answer one document with one
 * verdict.
 */
export function accept<T>(kind: DocumentKind<T>, fetched: Fetched): Document<T> {
	if (kind.mediaType !== undefined && fetched.mediaType !== kind.mediaType) {
		const served = fetched.mediaType === undefined ? "no media type" : JSON.stringify(fetched.mediaType);
		throw new MediaTypeRefused(`${fetched.url} was served with ${served}, not "${kind.mediaType}"`);
	}
	let payload: unknown;
	try {
		payload = JSON.parse(UTF8.decode(fetched.body));
	} catch (err) {
		throw new DirectoryUnavailable(`decode ${fetched.url}`, { cause: err });
	}
	if (kind.versionGate) {
		const ver = typeof payload === "object" && payload !== null ? (payload as { ver?: unknown }).ver : undefined;
		const refusal = manifestVersionRefusal(ver);
		if (refusal !== undefined) throw new ManifestVersionRefused(refusal);
	}
	checkStrictOf(payload, kind.strict);
	const parsed = parseWire<T>(kind.schema, payload);
	if (!parsed.success) {
		// A value the schema leaves to the parse, such as a timestamp that is not RFC 3339,
		// is the document breaking its message all the same. The model also names an enum
		// by its value name, so an enum written as its number, which the schema admits and
		// the Go reader accepts, is refused here.
		throw new StrictViolation(kind.strict.message, "the generated model refused the document");
	}
	return { message: parsed.data, mediaType: fetched.mediaType, url: fetched.url, body: fetched.body };
}

// The WebCrypto digest each uri_digest method names.
const DIGEST_METHODS: Readonly<Record<string, string>> = { sha256: "SHA-256", sha384: "SHA-384", sha512: "SHA-512" };

/** verifyDigest hashes the fetched bytes with `uriDigest`'s method and compares, or
 * throws. Pure apart from the WebCrypto digest, and replayed by the license-digest
 * corpus. `uriDigest` has passed the strict License check by the time a reader calls
 * this, so its method is one of the three the contract admits; a value that is not
 * throws a plain Error. */
export async function verifyDigest(uriDigest: string, fetched: Fetched): Promise<LicenseDocument> {
	const colon = uriDigest.indexOf(":");
	const method = colon < 0 ? uriDigest : uriDigest.slice(0, colon);
	const expected = colon < 0 ? "" : uriDigest.slice(colon + 1);
	const algorithm = DIGEST_METHODS[method];
	if (algorithm === undefined) throw new Error(`uri_digest names no supported method: ${JSON.stringify(method)}`);
	const actual = hex(new Uint8Array(await crypto.subtle.digest(algorithm, fetched.body as Uint8Array<ArrayBuffer>)));
	if (!constantTimeEqual(actual, expected)) {
		throw new DigestMismatch(
			`document at ${fetched.url} hashes to ${method}:${actual}, the license pins ${uriDigest}`,
		);
	}
	return { body: fetched.body, digest: `${method}:${actual}`, mediaType: fetched.mediaType, url: fetched.url };
}

// hex renders bytes as lowercase hexadecimal, the form uri_digest carries.
function hex(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// constantTimeEqual compares two strings in time that depends only on their lengths, not
// on where they first differ. Strings of different length are unequal at once: the
// length of a digest is public, fixed by its method.
function constantTimeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

// --- the public readers ----------------------------------------------------------------

/**
 * readManifest fetches and checks `domain`'s /.well-known/fora.json.
 *
 * The checks run in the order the contract reads the document: the media type must be
 * application/json; the body must be JSON; `ver` must carry a recognised major version
 * before any other member is read; and the whole document must pass the strict
 * WellKnownManifest schema and the cross-field rules.
 *
 * Throws an Error when `domain` is not a bare host (a port is allowed), before anything
 * is dialled; DirectoryUnavailable when the fetch fails or the body is not JSON;
 * MediaTypeRefused; ManifestVersionRefused; and StrictViolation.
 */
export async function readManifest(
	domain: string,
	opts: ReadDocumentOptions,
): Promise<Document<WellKnownManifest>> {
	if (!isBareHost(domain)) throw invalidHost(domain, "not a bare host");
	const fetched = await fetchDocument(opts.fetch, manifestURL(opts.scheme ?? "", domain));
	return accept(MANIFEST, fetched);
}

/**
 * readWBADirectory fetches and checks a WBA key directory. `urlOrDomain` is the
 * directory's full URL, or a bare host whose directory is read from
 * scheme://host/.well-known/http-message-signatures-directory.
 *
 * The directory is fetched with no redirect: a redirect fails the fetch. The media type
 * must be application/http-message-signatures-directory+json, the body must pass the
 * strict WBAFile schema and the cross-field rules, and the response must carry a valid
 * response signature by every key it lists, checked through `opts.verifyEd25519` when one
 * is given. Key validity windows and revocation are not
 * evaluated: that is the WBA key resolver's job, and a directory listing an expired key
 * is still a well-formed directory. Throws an Error for a value that is neither a URL nor
 * a bare host; DirectoryUnavailable; MediaTypeRefused; StrictViolation; and
 * DirectoryResponseUnsigned.
 */
export async function readWBADirectory(
	urlOrDomain: string,
	opts: ReadDocumentOptions,
): Promise<Document<WBAFile>> {
	let url = urlOrDomain;
	if (!urlOrDomain.includes("://")) {
		if (!isBareHost(urlOrDomain)) throw invalidHost(urlOrDomain, "neither a URL nor a bare host");
		url = wbaDirectoryURL(opts.scheme ?? "", urlOrDomain);
	}
	const fetched = await fetchDocument(opts.fetch, url, { noRedirect: true });
	const doc = accept(WBA_DIRECTORY, fetched);
	let signed: WBAFile;
	try {
		signed = await signedDirectoryKeys(fetched, doc.message, Date.now(), opts.verifyEd25519);
	} catch (err) {
		throw new DirectoryResponseUnsigned(`${url}: ${(err as Error).message}`, { cause: err });
	}
	const listed = doc.message.keys?.length ?? 0;
	if ((signed.keys?.length ?? 0) !== listed) {
		throw new DirectoryResponseUnsigned(
			`${signed.keys?.length ?? 0} of ${listed} listed keys signed the response at ${url}`,
		);
	}
	return doc;
}

/**
 * readRevocationList fetches and checks the key revocation list at `url`, a directory's
 * revocation_url. The protocol names no media type for this document, so the label is
 * reported and not checked. The body must pass the strict KeyRevocationList schema and
 * the cross-field rules. Whether `url` is anchored to the directory's host is the caller's
 * question: the WBA key resolver skips a list that is not. Throws DirectoryUnavailable
 * and StrictViolation.
 */
export async function readRevocationList(
	url: string,
	opts: ReadDocumentOptions,
): Promise<Document<KeyRevocationList>> {
	return accept(REVOCATION_LIST, await fetchDocument(opts.fetch, url));
}

/**
 * readLicenseDocument fetches the document `license.uri` names and verifies it against
 * `license.uri_digest`.
 *
 * The license itself is checked first, against the strict License schema and its
 * cross-field rules, so a uri without a digest, or a digest whose method is not sha256,
 * sha384 or sha512, is refused before anything is dialled. The fetched bytes are then
 * hashed with the digest's method and compared with it. The protocol names no media type
 * for a license document, so the label is reported and not checked. A uri with a scheme
 * other than https, such as a data-labels identifier that is not a URL, is refused by the
 * scheme guard and reported as DirectoryUnavailable: it names a document, not a place to
 * fetch one.
 *
 * Throws an Error when the license carries no uri; StrictViolation; DirectoryUnavailable;
 * and DigestMismatch.
 */
export async function readLicenseDocument(
	license: License,
	opts: ReadDocumentOptions,
): Promise<LicenseDocument> {
	if (license.uri === undefined || license.uri === "") {
		throw new Error("license carries no uri: there is no document to read");
	}
	// Through JSON, as it travels: a member set to undefined is an absent member.
	checkStrictOf(JSON.parse(JSON.stringify(license)), LICENSE_STRICT);
	const fetched = await fetchDocument(opts.fetch, license.uri);
	return verifyDigest(license.uri_digest ?? "", fetched);
}
