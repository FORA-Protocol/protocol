// Shared fixtures for the Web Bot Auth profile suites: decoding the Go-emitted vectors'
// hex and base64url fields, importing a vector's Ed25519 seed as a signing key, a
// resolver keyed by (directory, keyid) so a signature resolved through the wrong
// Signature-Agent member finds no key, an in-memory replay store, and the header bag a
// verify vector describes.

import type { ReplayStore, RequestKeyResolver, VerifyRequestHeaders } from "../core/verify-request.ts";

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
	const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
	const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

// The fixed PKCS8 DER prefix for an Ed25519 private key; the 32-byte seed follows.
// WebCrypto cannot import a bare Ed25519 seed as "raw", so it is wrapped and imported
// as "pkcs8".
const PKCS8_ED25519_PREFIX = Uint8Array.from([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Import a 32-byte Ed25519 seed (hex) as a signing key. */
export async function importSigningKey(seedHex: string): Promise<CryptoKey> {
	const seed = hexToBytes(seedHex);
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
	pkcs8.set(PKCS8_ED25519_PREFIX, 0);
	pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
	return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

/** A resolver that finds a key only under the directory it was registered in, and
 * records every (directory, keyid) it was asked for. */
export function directoryResolver(
	entries: Array<{ directory: string; keyid: string; pub: Uint8Array<ArrayBuffer> }>,
): RequestKeyResolver & { calls: Array<[string, string]> } {
	const keys = new Map(entries.map((e) => [`${e.directory} ${e.keyid}`, e.pub]));
	const calls: Array<[string, string]> = [];
	return {
		calls,
		resolve(keyid, directory) {
			calls.push([directory, keyid]);
			return keys.get(`${directory} ${keyid}`);
		},
	};
}

/** The agent directory most live-signed fixtures sign as. */
export const AGENT_DIRECTORY = "https://agent.example";

/** An in-test replay store the SDK orchestrates over (seenNonce / seenOrAdd). The SDK
 * ships no default store, so replay state lives entirely here. */
export function memoryReplayStore(): ReplayStore {
	const seen = new Set<string>();
	return {
		async seenNonce(nonce) {
			return seen.has(nonce);
		},
		async seenOrAdd(nonce) {
			if (seen.has(nonce)) return true;
			seen.add(nonce);
			return false;
		},
	};
}

/** The columns of a verify vector the header bag is built from. */
export type VerifyVectorColumns = {
	content_digest: string;
	signature_input: string;
	signature: string;
	authorization: string;
	signature_agent: string;
	entitlement?: string;
	omit_headers?: string[];
	extra_headers?: Record<string, string>;
};

/** verifyVectorHeaders is the header bag a verify vector describes: the base five from
 * the scalar columns, the entitlement header when the vector carries one, a name in
 * omit_headers dropped (absent is not empty), and each extra field line added AFTER the
 * base ones, so the join order is the order the oracle added them. The
 * repeated_field_lines_* rows test exactly that order, so every replay builds the bag
 * here. */
export function verifyVectorHeaders(v: VerifyVectorColumns): VerifyRequestHeaders {
	const headers: VerifyRequestHeaders = {
		"content-digest": v.content_digest,
		"signature-input": v.signature_input,
		signature: v.signature,
		authorization: v.authorization,
		"signature-agent": v.signature_agent,
	};
	if (v.entitlement) headers["x-entitlement-token"] = v.entitlement;
	const bag = headers as Record<string, string | undefined>;
	for (const name of v.omit_headers ?? []) delete bag[name.toLowerCase()];
	for (const [name, value] of Object.entries(v.extra_headers ?? {})) bag[name] = value;
	return headers;
}
