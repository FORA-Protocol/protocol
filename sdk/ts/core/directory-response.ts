// A key directory's response is signed once per key it lists (WG-00 §5.5 and Appendix
// B.1), and FORA requires it. Each response signature covers "@authority";req, the
// authority the directory was fetched from, and content-digest, carries created,
// expires, keyid (the key's RFC 7638 thumbprint) and alg, and has
// tag="http-message-signatures-directory". "@authority";req takes its value from the
// request that fetched the directory, so the signature cannot be served again under a
// different host. TS port of sdk/go/helpers/directory.go.

import { stdBase64, utf8Bytes } from "../src/base64url.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { DirectoryResponseTag } from "../src/wire.ts";
import { parseSignatureHeaders, type ParsedSignature } from "./multisig-parse.ts";
import { buildSignatureBase, contentDigest, signatureInputInner } from "./sign-request.ts";
import { ed25519Verify, readHeader } from "./verify-request.ts";
import { type CoveredComponent, coversComponent, plain } from "./wba.ts";

/** The three header values a key directory's response carries for its response
 * signatures, ready to set on the response. */
export interface DirectoryResponseSignature {
	contentDigest: string;
	signatureInput: string;
	signature: string;
}

/** One key a directory response is signed with: the private key and its keyid, the
 * RFC 7638 thumbprint of a key the directory lists. */
export interface DirectoryResponseSigner {
	privKey: CryptoKey;
	keyid: string;
}

/** Why a directory response could not be checked at all: its Content-Digest does not
 * match the body ("digest_mismatch"), or it carries no Content-Digest or no response
 * signature ("unsigned"). */
export class DirectoryResponseError extends Error {
	readonly reason: "digest_mismatch" | "unsigned";
	constructor(reason: "digest_mismatch" | "unsigned", message: string) {
		super(message);
		this.name = "DirectoryResponseError";
		this.reason = reason;
	}
}

// The covered set of a directory response signature, in the order a FORA signer emits
// it.
const DIRECTORY_RESPONSE_COVERED: readonly CoveredComponent[] = [
	{ name: "@authority", params: [{ key: "req", value: true }] },
	plain("content-digest"),
];

// A response signature's created may lead the verifier's clock by at most this.
const MAX_FUTURE_SKEW_SEC = 300;

// directoryResponseValue resolves the two components a directory response signature
// covers: the authority, lowercased, and the Content-Digest value.
function directoryResponseValue(authority: string, digest: string): (c: CoveredComponent) => string {
	return (c) => (c.name.toLowerCase() === "@authority" ? authority.toLowerCase() : digest);
}

/**
 * signDirectoryResponse signs a key directory response once per signer, labels
 * sig1..sigN in order. `authority` is the host[:port] the directory is served under,
 * exactly as a client's request names it: lowercase, and without a port when it is the
 * scheme's default. `body` is the exact response body. Each signer's keyid must be the
 * RFC 7638 thumbprint of a key the body lists; a verifier matches the two. The window is
 * the caller's: a directory response is cached and may be signed for longer than a
 * request, so only expires > created > 0 is required.
 */
export async function signDirectoryResponse(
	authority: string,
	body: Uint8Array<ArrayBuffer>,
	signers: readonly DirectoryResponseSigner[],
	created: number,
	expires: number,
): Promise<DirectoryResponseSignature> {
	if (authority === "") throw new Error("directory response needs the authority it is served under");
	if (signers.length === 0) throw new Error("directory response needs at least one signer");
	if (created <= 0 || expires <= created) {
		throw new Error(`directory response window must be positive: created=${created} expires=${expires}`);
	}
	const digest = await contentDigest(body);
	const inputs: string[] = [];
	const sigs: string[] = [];
	for (const [i, signer] of signers.entries()) {
		const label = `sig${i + 1}`;
		const inner = signatureInputInner({
			covered: DIRECTORY_RESPONSE_COVERED,
			keyid: signer.keyid,
			alg: "ed25519",
			created,
			expires,
			tag: DirectoryResponseTag,
		});
		const base = buildSignatureBase(DIRECTORY_RESPONSE_COVERED, directoryResponseValue(authority, digest), inner);
		const raw = await crypto.subtle.sign("Ed25519", signer.privKey, new TextEncoder().encode(base));
		inputs.push(`${label}=${inner}`);
		sigs.push(`${label}=:${stdBase64(new Uint8Array(raw))}:`);
	}
	return { contentDigest: digest, signatureInput: inputs.join(", "), signature: sigs.join(", ") };
}

/** The response headers a directory response check reads: a WHATWG Headers, or a
 * record matched case-insensitively with repeated spellings joined. */
export type ResponseHeaders = { get(name: string): string | null } | Record<string, string | undefined>;

function headerOf(headers: ResponseHeaders, name: string): string | undefined {
	if (typeof headers.get === "function") {
		const v = (headers as { get(name: string): string | null }).get(name);
		return v === null ? undefined : v.trim();
	}
	return readHeader(headers as Record<string, string | undefined>, name);
}

/**
 * verifyDirectoryResponse checks the response signatures of a fetched key directory and
 * returns the RFC 7638 thumbprints of the listed keys that signed it. `authority` is the
 * host[:port] the directory was fetched from, `headers` the response headers, `body` the
 * exact response body, `keys` the raw Ed25519 public keys the body lists, and `now` unix
 * seconds.
 *
 * The Content-Digest must match the body, or no key is verified and it throws
 * DirectoryResponseError ("digest_mismatch"). A response with no Content-Digest or no
 * signature at all throws DirectoryResponseError ("unsigned"). Otherwise each response
 * signature is judged on its own, and one that fails is ignored rather than fatal: it
 * must carry tag="http-message-signatures-directory" and alg="ed25519", cover exactly
 * "@authority";req and content-digest, carry created no later than now plus the
 * 300-second skew and expires no earlier than now, and verify under the listed key whose
 * thumbprint its keyid names.
 */
export async function verifyDirectoryResponse(
	authority: string,
	headers: ResponseHeaders,
	body: Uint8Array<ArrayBuffer>,
	keys: readonly Uint8Array<ArrayBuffer>[],
	now: number,
): Promise<Set<string>> {
	const digest = headerOf(headers, "content-digest");
	if (digest === undefined || digest === "") {
		throw new DirectoryResponseError("unsigned", "key directory response carries no Content-Digest");
	}
	if (digest !== (await contentDigest(body))) {
		throw new DirectoryResponseError("digest_mismatch", "key directory response Content-Digest does not match its body");
	}
	const parsed = parseSignatureHeaders(headerOf(headers, "signature-input"), headerOf(headers, "signature"));
	if (!parsed.ok) throw new DirectoryResponseError("unsigned", "key directory response carries no usable signature");
	const byThumb = new Map<string, Uint8Array<ArrayBuffer>>();
	for (const k of keys) {
		if (k.length === 32) byThumb.set(await thumbprint(k), k);
	}
	const verified = new Set<string>();
	for (const sig of parsed.value) {
		const pub = byThumb.get(sig.keyid);
		if (pub === undefined || !paramsValid(sig, now)) continue;
		const base = buildSignatureBase(sig.covered, directoryResponseValue(authority, digest), sig.rawInner);
		if (await ed25519Verify(pub, sig.signature, utf8Bytes(base))) verified.add(sig.keyid);
	}
	return verified;
}

// paramsValid applies the per-signature rules other than the Ed25519 check: tag, alg,
// covered set and window.
function paramsValid(sig: ParsedSignature, now: number): boolean {
	if (sig.tag !== DirectoryResponseTag || sig.alg?.toLowerCase() !== "ed25519") return false;
	if (sig.covered.length !== DIRECTORY_RESPONSE_COVERED.length) return false;
	if (!DIRECTORY_RESPONSE_COVERED.every((want) => coversComponent(sig.covered, want))) return false;
	if (!sig.created || !sig.expires) return false;
	return sig.created <= now + MAX_FUTURE_SKEW_SEC && sig.expires >= now;
}
