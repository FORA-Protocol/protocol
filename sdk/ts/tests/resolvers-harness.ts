// Shared served-directory harness for the resolver integration suites
// (resolvers-wellknown.integration.test.ts + resolvers-wba.integration.test.ts).
//
// Per the FORA testing doctrine these resolvers are IO-BOUND, so the suites
// exercise them against a REAL in-process node:http server on 127.0.0.1:0 — never
// a mocked fetch. The resolvers use their default global-fetch transport; only
// the clock (and the poll timer/seams) are injected for determinism. This module
// stands up that real origin and mints real Ed25519 keys.
//
// A key directory is served under the Web Bot Auth profile: its own media type and a
// response signed by every key it lists, for the authority it was fetched from. Every
// key this harness mints is registered by its public half, and the origin signs a
// served directory with the registered keys it lists. A listed key nobody registered
// is left unsigned, which a resolver treats as absent.

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { WBAFileSchema } from "../../../gen/ts/wire/schemas.ts";
import { signDirectoryResponse } from "../core/directory-response.ts";
import { WBA_DIRECTORY_MEDIA_TYPE } from "../resolvers/documents.ts";
import { decodeBase64Url } from "../src/base64url.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { WellKnownManifestVersion } from "../src/wire.ts";

// Well-known paths the origin serves. The WBA directory path is the fixed Web
// Bot Auth path; the JWKS key doc and the endpoint manifest sit on distinct
// paths so the key face (fixed URL) and endpoint face (host-keyed fora.json)
// never collide.
export const WBA_DIR_PATH = "/.well-known/http-message-signatures-directory";
export const REVOCATION_PATH = "/.well-known/fora-key-revocations.json";
export const MANIFEST_PATH = "/.well-known/fora.json";
export const JWKS_PATH = "/keys.json";

/** A real Ed25519 key: raw 32-byte public key, its base64url `x`, its RFC 7638
 * thumbprint (the WBA keyid), and the private key a served directory is signed with.
 * Produced through the SDK's own thumbprint primitive so lookups match the port
 * byte-for-byte. */
export interface TestKey {
	rawPub: Uint8Array;
	x: string;
	tp: string;
	privKey: CryptoKey;
}

// Every key the harness minted, by its base64url public half, so a served directory is
// signed by the keys it lists.
const registered = new Map<string, TestKey>();

async function register(privKey: CryptoKey, x: string): Promise<TestKey> {
	const raw = decodeBase64Url(x);
	if (!raw) throw new Error("harness: could not decode JWK x");
	const key = { rawPub: raw, x, tp: await thumbprint(raw), privKey };
	registered.set(x, key);
	return key;
}

/** Mint a fresh Ed25519 key, derive its SDK thumbprint, and register it. */
export async function makeKey(): Promise<TestKey> {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const jwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
	return register(kp.privateKey, jwk.x ?? "");
}

/** Register the key a 32-byte Ed25519 seed derives, for a directory another oracle
 * minted from a fixed seed. */
export async function registerSeed(seed: Uint8Array): Promise<TestKey> {
	const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
	const der = new Uint8Array(prefix.length + seed.length);
	der.set(prefix, 0);
	der.set(seed, prefix.length);
	const priv = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
	const jwk = await crypto.subtle.exportKey("jwk", priv);
	return register(priv, jwk.x ?? "");
}

// The response-signature window: wide enough to contain every injected test clock.
const RESPONSE_CREATED = 1;
const RESPONSE_EXPIRES = 2 ** 40;

/** The headers a key directory response carries: the profile's media type and a
 * response signature by each listed key the harness registered (all of them, or only
 * those whose `x` is in `signedBy`), for `authority`. */
export async function signedDirectoryHeaders(
	authority: string,
	body: string,
	signedBy?: readonly string[],
): Promise<Record<string, string>> {
	const headers: Record<string, string> = { "content-type": WBA_DIRECTORY_MEDIA_TYPE };
	let listed: string[] = [];
	try {
		const doc = JSON.parse(body) as { keys?: Array<{ x?: string }> };
		listed = (doc.keys ?? []).map((k) => k.x ?? "");
	} catch {
		return headers;
	}
	const signers = listed
		.filter((x) => signedBy === undefined || signedBy.includes(x))
		.map((x) => registered.get(x))
		.filter((k): k is TestKey => k !== undefined)
		.map((k) => ({ privKey: k.privKey, keyid: k.tp }));
	if (signers.length === 0) return headers;
	const sig = await signDirectoryResponse(
		authority,
		new TextEncoder().encode(body) as Uint8Array<ArrayBuffer>,
		signers,
		RESPONSE_CREATED,
		RESPONSE_EXPIRES,
	);
	headers["content-digest"] = sig.contentDigest;
	headers["signature-input"] = sig.signatureInput;
	headers.signature = sig.signature;
	return headers;
}

/** One JWK member of a WBA directory, snake_case exactly as the Go oracle emits
 * it via protojson (UseProtoNames). */
export function wbaJwk(
	x: string,
	notBefore: string,
	notAfter: string,
): Record<string, unknown> {
	return {
		kty: "OKP",
		crv: "Ed25519",
		use: "sig",
		alg: "EdDSA",
		x,
		not_before: notBefore,
		not_after: notAfter,
	};
}

/** Serialize a WBAFile carrying keys (and optionally a revocation_url). */
export function wbaFileJson(
	keys: Record<string, unknown>[],
	revocationUrl?: string,
): string {
	const doc: Record<string, unknown> = { keys };
	if (revocationUrl !== undefined) doc.revocation_url = revocationUrl;
	return JSON.stringify(doc);
}

/** Serialize a KeyRevocationList snapshot (as_of RFC3339-Z + revoked thumbprints). */
export function revocationJson(asOf: string, revoked: string[]): string {
	return JSON.stringify({ as_of: asOf, revoked });
}

/** Serialize the ad-hoc kid-carrying JWKS key doc (shape:
 * `{keys:[{kid,kty,crv,x}]}`) the WellKnownKeyResolver reads. */
export function jwksKeyDocJson(entries: Record<string, unknown>[]): string {
	return JSON.stringify({ keys: entries });
}

/** A valid Ed25519 JWKS entry keyed by kid. */
export function jwksEntry(kid: string, x: string): Record<string, unknown> {
	return { kid, kty: "OKP", crv: "Ed25519", x };
}

/** Serialize a WellKnownManifest projection ({ver, role, endpoint}); omit
 * endpoint to model a valid-but-inert manifest, and pass `ver: null` to omit the
 * version member and model a manifest with no version at all. */
export function manifestJson(endpoint?: string, ver: string | null = WellKnownManifestVersion): string {
	const doc: Record<string, unknown> = { role: "ROLE_EXCHANGE" };
	if (ver !== null) doc.ver = ver;
	if (endpoint !== undefined) doc.endpoint = endpoint;
	return JSON.stringify(doc);
}

interface OriginState {
	wba?: string;
	wbaSignedBy?: readonly string[] | undefined;
	wbaStatus: number;
	wbaHits: number;
	rev?: string;
	jwks?: string;
	jwksStatus: number;
	jwksHits: number;
	manifest?: string;
	manifestStatus: number;
	manifestHits: number;
}

/** A real in-process origin serving the WBA directory, revocation snapshot,
 * JWKS key doc, and fora.json manifest. Each doc is independently settable so a
 * test can rotate keys, publish a new revocation snapshot, or force a 500. */
export interface Origin {
	url: string;
	host: string;
	/** Serve `body` as the key directory, signed by every listed registered key, or only
	 * by those whose `x` is in `signedBy`. */
	setWBA(body: string, signedBy?: readonly string[]): void;
	setWBAStatus(code: number): void;
	wbaHits(): number;
	setRevocation(body: string): void;
	setJwks(body: string): void;
	setJwksStatus(code: number): void;
	jwksHits(): number;
	setManifest(body: string): void;
	setManifestStatus(code: number): void;
	manifestHits(): number;
	revocationURL(): string;
	close(): Promise<void>;
}

function route(
	state: OriginState,
	path: string,
): { code: number; body: string } | undefined {
	if (path === WBA_DIR_PATH) {
		state.wbaHits += 1;
		if (state.wbaStatus !== 0) return { code: state.wbaStatus, body: "" };
		if (state.wba === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.wba };
	}
	if (path === REVOCATION_PATH) {
		if (state.rev === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.rev };
	}
	if (path === JWKS_PATH) {
		state.jwksHits += 1;
		if (state.jwksStatus !== 0) return { code: state.jwksStatus, body: "" };
		if (state.jwks === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.jwks };
	}
	if (path === MANIFEST_PATH) {
		state.manifestHits += 1;
		if (state.manifestStatus !== 0)
			return { code: state.manifestStatus, body: "" };
		if (state.manifest === undefined) return { code: 404, body: "" };
		return { code: 200, body: state.manifest };
	}
	return undefined;
}

/** Start a real origin on 127.0.0.1:0. */
export async function startOrigin(): Promise<Origin> {
	const state: OriginState = {
		wbaStatus: 0,
		wbaHits: 0,
		jwksStatus: 0,
		jwksHits: 0,
		manifestStatus: 0,
		manifestHits: 0,
	};
	const server: Server = createServer((req, res) => {
		const path = (req.url ?? "").split("?")[0] ?? "";
		const hit = route(state, path);
		if (hit === undefined) {
			res.writeHead(404);
			res.end();
			return;
		}
		if (path !== WBA_DIR_PATH || hit.code !== 200) {
			res.writeHead(hit.code, { "content-type": "application/json" });
			res.end(hit.body);
			return;
		}
		void signedDirectoryHeaders(req.headers.host ?? "", hit.body, state.wbaSignedBy).then((headers) => {
			res.writeHead(200, headers);
			res.end(hit.body);
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	const addr = server.address() as AddressInfo;
	const host = `127.0.0.1:${addr.port}`;
	const url = `http://${host}`;
	return {
		url,
		host,
		setWBA: (b, signedBy) => {
			state.wba = b;
			state.wbaSignedBy = signedBy;
		},
		setWBAStatus: (c) => {
			state.wbaStatus = c;
		},
		wbaHits: () => state.wbaHits,
		setRevocation: (b) => {
			state.rev = b;
		},
		setJwks: (b) => {
			state.jwks = b;
		},
		setJwksStatus: (c) => {
			state.jwksStatus = c;
		},
		jwksHits: () => state.jwksHits,
		setManifest: (b) => {
			state.manifest = b;
		},
		setManifestStatus: (c) => {
			state.manifestStatus = c;
		},
		manifestHits: () => state.manifestHits,
		revocationURL: () => url + REVOCATION_PATH,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
}

// Time constants shared by the suites. The anchor sits well inside the validity
// windows the active-key builders emit.
export const HOUR_MS = 3_600_000;
export const ANCHOR_MS = Date.UTC(2026, 4, 1, 12, 0, 0); // 2026-05-01T12:00:00Z

/** RFC3339-Z rendering of an epoch-ms instant. */
export function iso(ms: number): string {
	return new Date(ms).toISOString();
}

/** The unguarded transport the integration suites inject to reach the in-process
 * 127.0.0.1 origin. The SDK's DEFAULT transport is now SSRF-guarded (it refuses
 * loopback / private targets — see resolvers/ssrf.ts), which is exactly the
 * pre-auth SSRF lever these faces close. A test origin is loopback, so — like
 * the Go oracle's tests, which inject an httptest client — the suites inject
 * this bare global-fetch transport as the escape hatch, keeping the guard on the
 * production default while still exercising the resolver logic against a real
 * server. It is a REAL fetch, never a mock; only the clock/poll seams are stubbed. */
export const loopbackFetch = (
	url: string,
): Promise<{ status: number; text(): Promise<string> }> =>
	fetch(url) as unknown as Promise<{ status: number; text(): Promise<string> }>;

// Parsed-WBAFile builders. These mirror the inline helpers the active-key
// behavior suite uses, hoisted here so the offer-key-cache suite consumes a
// PARSED WBAFile (the shape the cache's injected OfferDirectoryFetch seam
// returns) without re-deriving window arithmetic. `WBAFileSchema` is a generated
// schema (always present), so importing it here does NOT couple the harness to
// the not-yet-existing offer-key-cache face — a RED run still points at that
// missing module, not at this fixture.
export type WBAFile = ReturnType<typeof WBAFileSchema.parse>;

/** Parse raw JWK member objects into a WBAFile, exactly as an injected
 * directory-fetch seam would hand one to the cache. */
export function directory(keys: Record<string, unknown>[]): WBAFile {
	return WBAFileSchema.parse({ keys });
}

/** A window-active JWK member: validity window straddles ANCHOR
 * ([ANCHOR-1h, ANCHOR+1h]), so its `not_after` is ANCHOR+1h — the bound the
 * cache clamps its TTL against. */
export function activeJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - HOUR_MS), iso(ANCHOR_MS + HOUR_MS));
}

/** A retired JWK member: validity window sits entirely before ANCHOR, so it is
 * never window-active at ANCHOR. */
export function expiredJwk(x: string): Record<string, unknown> {
	return wbaJwk(x, iso(ANCHOR_MS - 2 * HOUR_MS), iso(ANCHOR_MS - HOUR_MS));
}
