// Shared fixtures for the Web Bot Auth profile suites: decoding the Go-emitted vectors'
// hex and base64url fields, importing a vector's Ed25519 seed as a signing key, a
// resolver keyed by (directory, keyid) so a signature resolved through the wrong
// Signature-Agent member finds no key, and a throwaway signer with a capturing send for
// the signing-transport suites.

import type { OutboundInit } from "../core/signing-transport.ts";
import type { RequestKeyResolver } from "../core/verify-request.ts";

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

/** A freshly generated Ed25519 signer for transport tests that pin plumbing, not byte
 * parity: any real key works. pub is the raw public key, for a verifier's resolver. */
export async function genSigner(signatureAgent: string = AGENT_DIRECTORY): Promise<{
	privKey: CryptoKey;
	pub: Uint8Array<ArrayBuffer>;
	keyid: string;
	signatureAgent: string;
}> {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const pub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	return { privKey: kp.privateKey, pub, keyid: "test-key.v1", signatureAgent };
}

/** One request a capturing send received. */
export type Captured = { url: string; init: OutboundInit };

/** The WHATWG-fetch-shaped send a signing transport wraps, faked: it records every
 * forwarded call, so a test can read the stamped headers and the forwarded body, and
 * answers 200. */
export function capturingSend(): {
	send: (url: string, init: OutboundInit) => Promise<{ status: number }>;
	calls: Captured[];
} {
	const calls: Captured[] = [];
	const send = async (url: string, init: OutboundInit) => {
		calls.push({ url, init });
		return { status: 200 };
	};
	return { send, calls };
}
