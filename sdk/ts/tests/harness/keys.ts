// Bytes and Ed25519 keys for the corpus replays. The base64 codecs are the SDK's own
// (src/base64url.ts); this module holds what the SDK does not export: hex, and the
// import of a 32-byte Ed25519 seed, which WebCrypto cannot import as "raw".

import { decodeBase64Url } from "../../src/base64url.ts";

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) {
		out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	}
	return out;
}

export function bytesToHex(bytes: Uint8Array): string {
	let out = "";
	for (let i = 0; i < bytes.length; i += 1) out += (bytes[i] as number).toString(16).padStart(2, "0");
	return out;
}

/** Decode base64url or standard base64 through the SDK's decoder, throwing on input it
 * refuses, so a malformed vector fails the test that reads it. */
export function b64urlToBytes(s: string): Uint8Array<ArrayBuffer> {
	const out = decodeBase64Url(s);
	if (out === undefined) throw new Error(`not base64: ${s}`);
	return out;
}

/** The agent directory most live-signed fixtures sign as. */
export const AGENT_DIRECTORY = "https://agent.example";

// The fixed PKCS8 DER prefix for an Ed25519 private key; the 32-byte seed follows.
// WebCrypto cannot import a bare Ed25519 seed as "raw", so it is wrapped and imported
// as "pkcs8".
const PKCS8_ED25519_PREFIX = Uint8Array.from([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Import a 32-byte Ed25519 seed (hex, or the bytes) as a signing key. */
export async function importSigningKey(seed: string | Uint8Array, extractable = false): Promise<CryptoKey> {
	const raw = typeof seed === "string" ? hexToBytes(seed) : seed;
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + raw.length);
	pkcs8.set(PKCS8_ED25519_PREFIX, 0);
	pkcs8.set(raw, PKCS8_ED25519_PREFIX.length);
	return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, extractable, ["sign"]);
}

/** The base64url `x` of the public half of a 32-byte Ed25519 seed (hex, or the bytes). */
export async function publicXForSeed(seed: string | Uint8Array): Promise<string> {
	const jwk = await crypto.subtle.exportKey("jwk", await importSigningKey(seed, true));
	return jwk.x ?? "";
}

/** The verify key of a 32-byte Ed25519 seed (hex). */
export async function publicKeyForSeed(seedHex: string): Promise<CryptoKey> {
	const pubJwk: JsonWebKey = { kty: "OKP", crv: "Ed25519", x: await publicXForSeed(seedHex) };
	return crypto.subtle.importKey("jwk", pubJwk, { name: "Ed25519" }, false, ["verify"]);
}

/** Import a raw 32-byte Ed25519 public key, given as bytes or as base64 or base64url
 * text, as a verify key. */
export async function importVerifyKey(pub: Uint8Array<ArrayBuffer> | string): Promise<CryptoKey> {
	const raw = typeof pub === "string" ? b64urlToBytes(pub) : pub;
	return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}
