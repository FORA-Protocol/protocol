// Shared fixtures for the Web Bot Auth profile suites: decoding the Go-emitted vectors'
// hex and base64url fields, importing a vector's Ed25519 seed as a signing key, a
// resolver keyed by (directory, keyid) so a signature resolved through the wrong
// Signature-Agent member finds no key, the corpus outcome a replay compares with
// (outcomeOf and expectedOutcome, ADR-002), and, for the signing-transport suites, a
// throwaway signer, a capturing send, the emitted Signature-Agent spelling and a byte
// comparison.

import registry from "../../parity/corpora.json";
import type { OutboundInit } from "../core/signing-transport.ts";
import type { RequestKeyResolver } from "../core/verify-request.ts";
import { SignatureAgentHeader } from "../src/wire.ts";
import expectedFailuresFile from "./expected-failures.json";

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

/** Import a 32-byte Ed25519 seed (hex) as a signing key; extractable when a test needs
 * to export it, for example to derive the public key. */
export async function importSigningKey(seedHex: string, extractable = false): Promise<CryptoKey> {
	const seed = hexToBytes(seedHex);
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
	pkcs8.set(PKCS8_ED25519_PREFIX, 0);
	pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
	return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, extractable, ["sign"]);
}

/** Import a standard-base64 raw 32-byte Ed25519 public key as a verify key. */
export async function importVerifyKey(pubB64: string): Promise<CryptoKey> {
	const raw = Uint8Array.from(atob(pubB64), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

/** The verify key that matches a 32-byte Ed25519 seed (hex). WebCrypto has no
 * seed-to-public-key operation, so the seed is imported as an extractable private key
 * and its public half (the JWK x member) is imported back as a verify key. */
export async function publicKeyForSeed(seedHex: string): Promise<CryptoKey> {
	const jwk = (await crypto.subtle.exportKey("jwk", await importSigningKey(seedHex, true))) as JsonWebKey;
	// kty, crv and x are always present on an exported Ed25519 JWK; the ?? fallbacks pin
	// the string type under exactOptionalPropertyTypes.
	const pubJwk: JsonWebKey = { kty: jwk.kty ?? "OKP", crv: jwk.crv ?? "Ed25519", x: jwk.x ?? "" };
	return crypto.subtle.importKey("jwk", pubJwk, { name: "Ed25519" }, false, ["verify"]);
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

/** The corpus outcome (ADR-002 rule 3) of a call that accepted, or refused for
 * `reason`, the token the SDK reported. A refusal without a token renders as
 * "refused:", which matches no row. */
export function outcomeOf(accepted: boolean, reason?: string): string {
	return accepted ? "accepted" : `refused:${reason ?? ""}`;
}

/** One entry of this port's expected-failure file. */
interface ExpectedFailure {
	row: string;
	outcome: string;
	why: string;
}

// The registry names this port's expected-failure file; the import above must be it.
const EXPECTED_FAILURES_PATH = "sdk/ts/tests/expected-failures.json";
if (registry.expected_failures.ts !== EXPECTED_FAILURES_PATH) {
	throw new Error(`the registry names ${registry.expected_failures.ts}, not ${EXPECTED_FAILURES_PATH}`);
}
const expectedFailures = new Map((expectedFailuresFile.entries as ExpectedFailure[]).map((e) => [e.row, e.outcome]));

/** The outcome a replay asserts for the row at `pointer` (`<corpus>#<row>`): the
 * outcome this port's expected-failure file records for it, or else the row's own.
 * So a listed row fails when it starts passing and when it fails differently
 * (ADR-002 rule 6). */
export function expectedOutcome(pointer: string, outcome: string): string {
	return expectedFailures.get(pointer) ?? outcome;
}

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

/** The Signature-Agent spelling the signer emits. It is lowercase, so a merge over a
 * caller's own headers replaces rather than duplicates: two field lines under one
 * covered name break the rebuilt signature base. It is derived from the exported
 * constant, never written as a literal. */
export const SIGNATURE_AGENT_EMITTED = SignatureAgentHeader.toLowerCase();

/** Whether two byte arrays hold the same bytes; two absent arrays are equal. */
export function bytesEqual(a: Uint8Array | undefined, b: Uint8Array | undefined): boolean {
	if (a === undefined || b === undefined) return a === b;
	if (a.length !== b.length) return false;
	for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
	return true;
}
