// sdk/ts framework-agnostic RFC 9421 single-signature SERVER-verify face under the Web
// Bot Auth profile — the verify sibling of core/sign-request.ts and the TS port of
// sdk/go/connectserver's verify path over helpers/verify.go. Where
// hono/middleware.ts::foraVerify is the edge delivery-proof path (self-verifying, no
// resolver) and core/verifier.ts is OFFER verify (JCS), this is the request-verify a
// Broker/Exchange built in TS wires behind its framework: it parses the inbound
// Signature-Input/Signature, enforces the profile and the FORA RPC covered set,
// resolves the keyid in the key directory the signature's own Signature-Agent member
// names through an INJECTED resolver (the SDK owns no keys), runs the two-phase replay
// check over an INJECTED store (the SDK owns no replay state), reads time through an
// INJECTED clock (the SDK owns no wall clock), and returns a VERDICT — never throws.
//
// The first signature in header order is the one judged; a request carrying several is
// the multisig sibling's (core/verify-multisig-request.ts). The reject reasons are the
// two the single-signature surface produces (connectserver classify.go
// RejectReason.String()): "signature" (the default — a bad signature, expiry, an
// unresolvable key, a tampered covered field, a missing component, a refused form) and
// "replay".

import { WBATag } from "../src/wire.ts";
import { parseSignatureHeaders, type ParsedSignature } from "./multisig-parse.ts";
import { stdBase64 } from "../src/base64url.ts";
import {
	buildSignatureBase,
	ComponentUnavailable,
	contentDigest,
	requestComponentValue,
} from "./sign-request.ts";
import {
	acceptSignatureFor,
	type Checked,
	ENTITLEMENT_COVERED,
	type Refusal,
	REQUIRED_RPC_COMPONENTS,
	signatureDirectory,
} from "./wba.ts";

export { acceptSignature, ENTITLEMENT_COVERED } from "./wba.ts";

/**
 * The classified reject reason (connectserver classify.go RejectReason.String()).
 * SINGLE-SIG surface: "signature" (the default — authenticity/freshness/key/covered-set
 * and profile failures) and "replay".
 */
export type RejectReason = "signature" | "replay";

/**
 * The injected verifying-key resolver (ADR-020 §4). Distinct from
 * core/verifier.ts::OfferKeyResolver, which is EXCHANGE-keyed for offer verify: a
 * request-verify resolver is keyed by the Signature-Input keyid and the https origin of
 * the key directory the signature's own covered Signature-Agent member names, so each
 * signature is resolved in its own signer's directory. Returns the raw 32-byte Ed25519
 * public key, or undefined when that directory publishes no such key.
 */
export interface RequestKeyResolver {
	resolve(
		keyid: string,
		directory: string,
	): Uint8Array<ArrayBuffer> | undefined | Promise<Uint8Array<ArrayBuffer> | undefined>;
}

/**
 * The injected replay-nonce store (mirrors Go core.ReplayStore). The SDK ships NO
 * default — replay state lives entirely in the injected implementation.
 * `seenNonce` is the read-only first phase; `seenOrAdd` is the commit phase
 * (resolves true if the nonce was already present).
 */
export interface ReplayStore {
	seenNonce(nonce: string): Promise<boolean>;
	seenOrAdd(nonce: string): Promise<boolean>;
}

/**
 * The request headers a server-verify reads.
 *
 * Lowercased keys are the convention and the members below spell them that way, but
 * every name is matched case-insensitively and repeated spellings of one name are
 * JOINED before the base is rebuilt — the wire has one field per name however an
 * object spells it. Declared as a type alias rather than an interface because only a
 * type alias gets the implicit index signature that lets a value of this type reach
 * readHeader's `Record<string, string | undefined>` parameter; an interface is open to
 * declaration merging and TypeScript withholds it.
 *
 * Every member is optional so an ABSENT header is distinguishable from an empty one. A
 * request with no Signature-Input or Signature is unsigned and is answered with
 * Accept-Signature. A covered header the request does not carry cannot be
 * reconstructed, and defaulting it to "" would invent a value the signer may never have
 * bound; the oracle draws the same line by reading headers with Values rather than Get.
 * See docs/design-history.md, "A covered header the peer never receives is not bound".
 */
export type VerifyRequestHeaders = {
	"content-digest"?: string;
	"signature-input"?: string;
	signature?: string;
	authorization?: string;
	/** The Signature-Agent dictionary naming each signer's key directory. */
	"signature-agent"?: string;
	/**
	 * The entitlement-token header (mirrors Go entitlementHeaderLower). When present, the
	 * covered set MUST commit to it; omit/empty when the request carries no entitlement.
	 * Format-neutral — JWT/opaque token; coverage is enforced, contents are not.
	 */
	"x-entitlement-token"?: string;
};

/** Inputs for verifyRequestServer — the request material plus the injected boundary. */
export interface VerifyRequestServerInput {
	method: string;
	url: string;
	body: Uint8Array<ArrayBuffer>;
	headers: VerifyRequestHeaders;
	resolve: RequestKeyResolver;
	/** Omit to disable replay detection (verify-only), matching Go WithReplayStore-absent. */
	replayStore?: ReplayStore;
	/** Injected clock returning unix seconds — verify reads time ONLY through this. */
	now: () => number;
	/**
	 * The per-signature lifetime clamp in SECONDS (mirrors Go
	 * VerifyOptions.MaxSignatureAge). When > 0, a signature whose declared window
	 * (expires − created) EXCEEDS this is rejected as "signature"; the bound is
	 * inclusive (a window exactly equal to it is accepted). 0/undefined = unbounded.
	 */
	maxSignatureAge?: number;
}

/** The returned verdict: valid with what the signature proved, or invalid with the
 * classified reason. */
export interface VerifyVerdict {
	valid: boolean;
	reason?: RejectReason;
	/** The keyid of the verified signature. */
	keyid?: string;
	/** The https origin of the verified signer's key directory: the value of the
	 * Signature-Agent member the signature covers, the directory its keyid was resolved
	 * in. It is covered, so it is signed. */
	signatureAgent?: string;
	/**
	 * The Accept-Signature value (RFC 9421 §5.1, WG-00 §5.3) a refusal is answered with,
	 * naming the components and form the verifier requires. Set when the request carried
	 * no signature, a signature omitted a required component, its tag was missing or
	 * wrong, or its Signature-Agent was in a form the profile refuses; unset for every
	 * other refusal. A server sets it on its 401 as the AcceptSignatureHeader field.
	 */
	acceptSignature?: string;
}

// A created timestamp may not lead the verifier clock by more than this
// (mirrors Go helpers.defaultMaxFutureSkew = 300s).
const MAX_FUTURE_SKEW_SEC = 300;

/**
 * Read the request's value for `name`, or undefined when it carries no such field.
 *
 * The port of the oracle's covered-component read (`http.Header.Values` plus the
 * RFC 9421 join), and it makes two distinctions a plain property lookup erases.
 *
 * ABSENT is not EMPTY. undefined means the request carried no field line under this
 * name at all; "" means it carried one whose value is empty. The base is rebuilt
 * from the request that ARRIVED, so a covered name with nothing under it cannot be
 * reconstructed, while an empty one reconstructs to the empty value the signer
 * bound — which is the whole reason an empty covered header is put on the wire.
 *
 * Repeated spellings JOIN, they do not shadow. Header names are case-insensitive on
 * the wire and a JavaScript object's keys are not, so a caller's `Authorization` and
 * a signer's `authorization` are two field lines under ONE covered name. The oracle
 * joins them with ", " before rebuilding the base, so the covered value changes and
 * the signature no longer reproduces. Returning the first match instead would hand
 * back the signed value and accept whatever was slipped in beside it — the token
 * injection the covered set exists to prevent.
 *
 * Exported for the multisig sibling, which reads the same request the same way.
 * See docs/design-history.md, "A covered header the peer never receives is not bound".
 */
export function readHeader(
	headers: Record<string, string | undefined>,
	name: string,
): string | undefined {
	const lower = name.toLowerCase();
	const values: string[] = [];
	for (const [key, value] of Object.entries(headers)) {
		if (key.toLowerCase() === lower && value !== undefined) values.push(value);
	}
	if (values.length === 0) return undefined;
	return values.join(", ").trim();
}

/** The request a signature is verified against: its request line, its exact body, and
 * a header lookup that joins repeated field lines (see readHeader). */
export interface VerifiableRequest {
	method: string;
	url: string;
	body: Uint8Array<ArrayBuffer>;
	header(name: string): string | undefined;
}

/** verifiableRequest adapts the request material a verify face receives. */
export function verifiableRequest(
	method: string,
	url: string,
	body: Uint8Array<ArrayBuffer>,
	headers: Record<string, string | undefined>,
): VerifiableRequest {
	return { method, url, body, header: (name) => readHeader(headers, name) };
}

// The replay nonce mirrors connectserver.replayNonce: keyid + NUL +
// STANDARD-base64(signature bytes), so neither part can forge the boundary and
// the value is independent of incidental wire whitespace.
function replayNonce(keyid: string, sigBytes: Uint8Array<ArrayBuffer>): string {
	return `${keyid}\u0000${stdBase64(sigBytes)}`;
}

export async function ed25519Verify(
	pub: Uint8Array<ArrayBuffer>,
	sig: Uint8Array<ArrayBuffer>,
	message: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
	try {
		const key = await crypto.subtle.importKey(
			"raw",
			pub,
			{ name: "Ed25519" },
			false,
			["verify"],
		);
		return await crypto.subtle.verify("Ed25519", key, sig, message);
	} catch {
		return false;
	}
}

/** What one verified signature proved. */
export interface VerifiedSignature {
	keyid: string;
	/** The https origin of the key directory the signature's member names. */
	directory: string;
}

const refuse = (refusal: Refusal): { ok: false; refusal: Refusal } => ({ ok: false, refusal });
const SIGNATURE: Refusal = { kind: "signature" };

/**
 * verifyParsedSignature runs the full per-signature check shared by the single-sig and
 * multisig faces (mirrors Go verifySingleSignature, MINUS replay): alg, the Web Bot Auth
 * tag, the FORA RPC components, the signature's own Signature-Agent member, entitlement
 * coverage, the created/expires window, content-digest, then the key the member's
 * directory publishes and the Ed25519 check over the rebuilt base. `sigCount` is the
 * number of signatures on the request: the legacy String form of Signature-Agent is
 * accepted only when it is one. `maxSignatureAge` (seconds, mirrors Go
 * VerifyOptions.MaxSignatureAge) clamps the declared lifetime: when > 0 a window
 * EXCEEDING it is refused; 0/undefined = unbounded. NO replay — the caller owns that.
 */
export async function verifyParsedSignature(
	req: VerifiableRequest,
	sig: ParsedSignature,
	sigCount: number,
	resolve: RequestKeyResolver,
	nowSec: number,
	maxSignatureAge?: number,
): Promise<Checked<VerifiedSignature>> {
	if (sig.alg === undefined || sig.alg.toLowerCase() !== "ed25519") return refuse(SIGNATURE);
	if (sig.tag !== WBATag) return refuse({ kind: "tag" });
	const names = new Set(sig.covered.map((c) => c.name.toLowerCase()));
	for (const need of REQUIRED_RPC_COMPONENTS) {
		if (!names.has(need)) return refuse({ kind: "missing_component", component: need });
	}
	const directory = signatureDirectory(req.header("signature-agent"), sig, sigCount);
	if (!directory.ok) return directory;
	// Every field line under the name, joined: a reader taking the first line alone is
	// shadowed by an empty line put ahead of a real token, and the coverage rule never runs.
	const entitlement = req.header(ENTITLEMENT_COVERED);
	if (entitlement !== undefined && entitlement !== "" && !names.has(ENTITLEMENT_COVERED)) {
		return refuse({ kind: "missing_component", component: ENTITLEMENT_COVERED });
	}
	if (!sig.created || !sig.expires) return refuse(SIGNATURE);
	if (sig.expires < nowSec || sig.created > nowSec + MAX_FUTURE_SKEW_SEC) return refuse(SIGNATURE);
	if (maxSignatureAge !== undefined && maxSignatureAge > 0 && sig.expires - sig.created > maxSignatureAge) {
		return refuse(SIGNATURE);
	}
	if (names.has("content-digest")) {
		const digest = req.header("content-digest");
		if (digest === undefined || digest.trim() !== (await contentDigest(req.body))) return refuse(SIGNATURE);
	}
	let pub: Uint8Array<ArrayBuffer> | undefined;
	try {
		pub = await resolve.resolve(sig.keyid, directory.value);
	} catch {
		return refuse(SIGNATURE);
	}
	if (pub === undefined || pub.length !== 32) return refuse(SIGNATURE);
	let base: string;
	try {
		base = buildSignatureBase(sig.covered, requestComponentValue(req), sig.rawInner);
	} catch (err) {
		if (err instanceof ComponentUnavailable) return refuse(SIGNATURE);
		throw err;
	}
	if (!(await ed25519Verify(pub, sig.signature, new TextEncoder().encode(base)))) return refuse(SIGNATURE);
	return { ok: true, value: { keyid: sig.keyid, directory: directory.value } };
}

/** rejected maps a refusal onto the public verdict: reason "signature", plus the
 * Accept-Signature value when the refusal earns one. */
function rejected(refusal: Refusal): VerifyVerdict {
	const accept = acceptSignatureFor(refusal);
	return { valid: false, reason: "signature", ...(accept !== undefined ? { acceptSignature: accept } : {}) };
}

/**
 * Verify an inbound FORA request's first signature; return a reason-tagged verdict.
 *
 * Mirrors the Go connectserver verify order: the profile and covered-set checks → the
 * created/expires window → content-digest → key resolution in the signature's own
 * directory → Ed25519 over the rebuilt base → two-phase replay. Every
 * authenticity/freshness/key/covered-set/form failure collapses to "signature" (the Go
 * default branch); a replayed signature is "replay". Keys resolve ONLY through
 * `resolve`; replay state lives ONLY in `replayStore` when supplied; time is read ONLY
 * through `now`.
 */
export async function verifyRequestServer(
	input: VerifyRequestServerInput,
): Promise<VerifyVerdict> {
	const parsed = parseSignatureHeaders(
		readHeader(input.headers, "signature-input"),
		readHeader(input.headers, "signature"),
	);
	if (!parsed.ok) return rejected(parsed.refusal);
	const sig = parsed.value[0] as ParsedSignature;
	const req = verifiableRequest(input.method, input.url, input.body, input.headers);
	const nowSec = Math.floor(input.now());
	const verified = await verifyParsedSignature(
		req,
		sig,
		parsed.value.length,
		input.resolve,
		nowSec,
		input.maxSignatureAge,
	);
	if (!verified.ok) return rejected(verified.refusal);

	if (input.replayStore) {
		// Two-phase (read-only Seen, then SeenOrAdd) mirrors connectserver.verify so a
		// part-way rejection never burns the nonce (single-sig: one signature).
		const nonce = replayNonce(sig.keyid, sig.signature);
		if (await input.replayStore.seenNonce(nonce)) return { valid: false, reason: "replay" };
		if (await input.replayStore.seenOrAdd(nonce)) return { valid: false, reason: "replay" };
	}

	return { valid: true, keyid: verified.value.keyid, signatureAgent: verified.value.directory };
}

