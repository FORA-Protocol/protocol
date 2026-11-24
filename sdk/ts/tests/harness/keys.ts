// Shared fixtures for the Web Bot Auth profile suites: decoding the Go-emitted vectors'
// hex and base64url fields, importing a vector's Ed25519 seed as a signing key, a
// resolver keyed by (directory, keyid) so a signature resolved through the wrong
// Signature-Agent member finds no key, and the corpus outcome a replay compares with
// (outcomeOf and expectedOutcome, ADR-002).

import registry from "../../../parity/corpora.json";
import type { RequestKeyResolver } from "../../core/verify-request.ts";
import expectedFailuresFile from "../expected-failures.json";

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
