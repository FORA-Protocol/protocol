// sdk/ts/core sign seam — the client/inbound sign face over the WHATWG Fetch
// Request, mirror of Go helpers.SignAgentBinding but adapted to the IMMUTABLE Fetch
// Request: it returns a NEW signed Request (headers set on a clone), never mutating in
// place. It signs the delivery proof of possession — a Web Bot Auth signature over
// @method, @target-uri and the agent's Signature-Agent member — through the same
// signature-base builder the L1 pop verifier rebuilds with, so the signed bytes are
// byte-identical to what the verifier reconstructs.
//
// ZERO framework import (no hono, no connect-es) — only WebCrypto + the L1
// helpers. The Hono binding (sdk/ts/hono) composes this seam; this seam composes
// nothing above the web standard.

import { encodeBase64Url, stdBase64 } from "../src/base64url.ts";
import { opaqueUrl } from "../src/opaque-url.ts";
import { AGENT_KEY_HEADER } from "../src/pop.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { SignatureAgentHeader, WBATag } from "../src/wire.ts";
import { buildSignatureBase, requestComponentValue, signatureInputInner } from "./sign-request.ts";
import {
	checkHttpsOrigin,
	checkNonce,
	keyed,
	MAX_SIGNATURE_LIFETIME,
	plain,
	signatureAgentMember,
	WebBotAuthError,
} from "./wba.ts";
import { clockWindow, type Window } from "./window.ts";

// Re-exported so the module that has always carried the standard-base64 encoder still
// does; the one copy lives with the base64url codec.
export { stdBase64 } from "../src/base64url.ts";

// The default signing window (seconds) for the proof's created/expires params: the
// longest a Web Bot Auth signature may live. A delivery client sets a shorter one.
const DEFAULT_POP_TTL_SEC = MAX_SIGNATURE_LIFETIME;

// The only label a delivery proof carries, and the key of the agent's Signature-Agent
// member. A delivery fetch is a single hop to the edge, so a second signature never
// arises and the label is fixed rather than computed.
const POP_LABEL = "sig1";

/**
 * Ed25519 sign primitive: (privateKey, message) -> signature. Injected so a
 * non-WebCrypto runtime can supply its own without changing the byte contract.
 * Defaults to WebCrypto crypto.subtle over a CryptoKey.
 */
export type Ed25519SignFn = (message: Uint8Array) => Promise<Uint8Array>;

/** Options for signInbound: the agent's directory, the nonce, and the created/expires
 * window with an injectable clock. */
export interface SignInboundOptions {
	/** The https origin of the agent's key directory, the one that publishes the
	 * presented key. Written as the Signature-Agent member sig1="<origin>" and covered,
	 * so a generic WBA verifier can resolve the key there. Required: empty throws
	 * WebBotAuthError ("signature_agent_required"), a value that is not an https origin
	 * ("signature_agent_not_origin"). */
	signatureAgent: string;
	/** The RFC 9421 nonce parameter, base64url. The helper reads no RNG: a delivery
	 * client passes 64 fresh random bytes. Absent or "" emits no nonce. */
	nonce?: string;
	now?: () => number;
	ttlSec?: number;
	/**
	 * An injectable signature Window sourcing (created, expires). Defaults to a
	 * clockWindow over `now`/`ttlSec` (both floored to integer seconds). The window must
	 * be positive and at most MAX_SIGNATURE_LIFETIME, or signing throws WebBotAuthError
	 * ("signature_lifetime").
	 */
	window?: Window;
}

/**
 * signInbound produces a Web Bot Auth proof-of-possession-signed inbound Request over
 * @method, @target-uri and the agent's Signature-Agent member, bound to the agent
 * keypair's RFC 7638 thumbprint (keyid = agent_id). It is the sign side the Hono
 * server-verify binding accepts; it returns a NEW Request carrying the
 * X-FORA-Agent-Key, Signature-Agent, Signature-Input and Signature headers (the Fetch
 * Request is immutable — we clone + set headers, never mutate).
 *
 * The covered set is exactly ("@method" "@target-uri" "signature-agent";key="sig1"),
 * the parameters created, expires, keyid, alg, nonce (when set) and tag="web-bot-auth",
 * matching Go helpers.SignAgentBinding byte for byte, so the produced request verifies
 * through verifyAgentBinding unchanged. Throws WebBotAuthError, before signing, for a
 * missing or non-origin directory, a window that is not positive or longer than
 * MAX_SIGNATURE_LIFETIME, or a nonce outside the base64url alphabet.
 */
export async function signInbound(
	kp: CryptoKeyPair,
	url: string,
	opts: SignInboundOptions,
): Promise<Request> {
	const rawPub = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	);
	const agentId = await thumbprint(rawPub);

	// Source (created, expires) from the injected Window, defaulting to a
	// clockWindow over now (ms → seconds) and ttlSec. clockWindow floors to
	// integer seconds.
	const ttlSec = opts.ttlSec ?? DEFAULT_POP_TTL_SEC;
	const window =
		opts.window ??
		clockWindow(() => (opts.now?.() ?? Date.now()) / 1000, ttlSec);
	const [created, expires] = window();
	checkProofOptions(opts, created, expires);

	// Coerce a URL-like input (a Fastly Compute request URL object) to its opaque
	// string form ONCE at the boundary, so the signed @target-uri and the emitted
	// Request carry the same verbatim bytes. No-op for string callers.
	const target = opaqueUrl(url);
	// The signature base is line-delimited and `target` is written into it
	// verbatim, so a control byte would add or split a component line and the bytes
	// signed here would stop describing the request a verifier reconstructs.
	// Refused rather than escaped, mirroring the Go signer. Checked AFTER the
	// coercion above so it inspects the bytes that actually get signed — and before
	// `new Request(target, …)` below, which would otherwise throw an opaque
	// TypeError instead of naming the reason.
	// Scanned over the UTF-8 BYTES, not the code points, so the reported offset is
	// the same number Go's strings.IndexFunc reports for the same input. Which
	// inputs are refused is unaffected — a control byte is always a single UTF-8
	// byte — but an unlabelled index under identical wording meant three units.
	const badAt = new TextEncoder()
		.encode(target)
		.findIndex((b) => b < 0x20 || b === 0x7f);
	if (badAt !== -1) {
		throw new TypeError(`target URI carries a control byte at byte ${badAt}`);
	}

	const member = signatureAgentMember(POP_LABEL, opts.signatureAgent);
	const covered = [plain("@method"), plain("@target-uri"), keyed("signature-agent", POP_LABEL)];
	const inner = signatureInputInner({
		covered,
		keyid: agentId,
		alg: "ed25519",
		created,
		expires,
		...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
		tag: WBATag,
	});
	const base = buildSignatureBase(
		covered,
		requestComponentValue({
			method: "GET",
			url: target,
			header: (name) => (name === "signature-agent" ? member : undefined),
		}),
		inner,
	);
	const sig = await crypto.subtle.sign(
		"Ed25519",
		kp.privateKey,
		new TextEncoder().encode(base),
	);

	const headers = new Headers();
	headers.set(AGENT_KEY_HEADER, encodeBase64Url(rawPub));
	headers.set(SignatureAgentHeader, member);
	headers.set("signature-input", `${POP_LABEL}=${inner}`);
	headers.set("signature", `${POP_LABEL}=:${stdBase64(new Uint8Array(sig))}:`);

	return new Request(target, { method: "GET", headers });
}

// checkProofOptions refuses a proof no profile verifier accepts, before anything is
// signed: no created, a window that is not positive or longer than the limit, a missing
// or non-origin directory, or a nonce outside the base64url alphabet.
function checkProofOptions(opts: SignInboundOptions, created: number, expires: number): void {
	const life = expires - created;
	if (created <= 0 || life <= 0 || life > MAX_SIGNATURE_LIFETIME) {
		throw new WebBotAuthError(
			"signature_lifetime",
			`proof lifetime must be positive and at most ${MAX_SIGNATURE_LIFETIME}s: created=${created} expires=${expires}`,
		);
	}
	if (opts.signatureAgent === "") {
		throw new WebBotAuthError("signature_agent_required", "a proof needs the agent's Signature-Agent origin");
	}
	checkHttpsOrigin(opts.signatureAgent);
	checkNonce(opts.nonce ?? "");
}
