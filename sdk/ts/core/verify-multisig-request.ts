// sdk/ts framework-agnostic RFC 9421 SERVER-verify face for a request carrying several
// signatures — the TS port of Go helpers.VerifyMultisigRequest[Resolved] (verify.go /
// keyresolver.go). Where core/verify-request.ts judges the first signature, this verifies
// EVERY signature on the request, each on its own, against the key its keyid names in
// the directory its OWN covered Signature-Agent member names, and returns a verdict with
// the verified keyids and directories in header order, never throwing.
//
// A signature need not cover another (WG-00 §5.2.2: a forwarder MAY); one that does
// must cover the earlier signature's Signature member, its Signature-Input member and
// every component it lists, and may only cover a signature that appears before it.
// Labels carry no meaning: sig1..sigN is the SDK's convention, not a rule.
//
// Reject precedence (parity-critical, mirrors Go VerifyMultisigRequest):
//   hop_budget → broken_chain → signature.
//
// NO replay: the Go helpers oracle VerifyMultisigRequest[Resolved] performs no replay
// (replay lives at the connectserver layer), so this face reuses the replay-free
// per-signature core (verifyParsedSignature) and never touches a ReplayStore.

import { type ParsedSignature, parseSignatureHeaders } from "./multisig-parse.ts";
import {
	readHeader,
	type RequestKeyResolver,
	verifiableRequest,
	verifyParsedSignature,
	type VerifyRequestHeaders,
} from "./verify-request.ts";
import { acceptSignatureFor, componentParam, coversComponent, keyed, type Refusal } from "./wba.ts";

/**
 * The classified multisig reject reason (mirrors the Go taxonomy): "hop_budget" (more
 * signatures than maxSignatures; the protocol answers it with resource_exhausted, HTTP
 * 429, and no typed reason), "broken_chain" (a signature covers an earlier
 * one incompletely, or names one that does not appear before it), and "signature" (any
 * per-signature authenticity/freshness/key/covered-set/form failure — the default).
 */
export type MultisigRejectReason = "signature" | "broken_chain" | "hop_budget";

/** The injected verifying-key resolver every signature's key resolves through, keyed by
 * keyid and by the directory that signature's own member names (the SDK owns no keys).
 * Structurally identical to RequestKeyResolver. */
export type MultisigKeyResolver = RequestKeyResolver;

/**
 * The request headers a multisig server-verify reads. Read exactly as the single-sig
 * sibling reads them: case-insensitively, joining repeated spellings of one name. When
 * the entitlement-token header is present, EVERY signature's covered set must commit to
 * it (Go runs enforceEntitlementCoverage inside verifySingleSignature, per signature).
 */
export type MultisigVerifyHeaders = VerifyRequestHeaders;

/** Inputs for verifyMultisigRequestServer. */
export interface VerifyMultisigRequestInput {
	method: string;
	url: string;
	body: Uint8Array<ArrayBuffer>;
	headers: MultisigVerifyHeaders;
	resolve: MultisigKeyResolver;
	/** Injected clock returning unix seconds — verify reads time ONLY through this. */
	now: () => number;
	/** The hop budget: the most RFC 9421 signatures a request may carry. Every signature
	 * counts, whether or not it covers another, so an Exchange sets this to the
	 * max_intermediary_hops it publishes in its manifest, with nothing added. A request
	 * carrying more is refused as "hop_budget" BEFORE any signature is checked; the
	 * protocol's code for that refusal is resource_exhausted (HTTP 429), with no typed
	 * reason. 0 / omitted means unbounded (mirrors Go VerifyOptions.MaxSignatures). */
	maxSignatures?: number;
	/** The per-signature lifetime clamp in SECONDS (mirrors Go
	 * VerifyOptions.MaxSignatureAge), enforced on EVERY signature exactly like the
	 * single-sig path. 0 / omitted means unbounded; the bound is inclusive. */
	maxSignatureAge?: number;
}

/** The returned verdict: valid with the verified keyids and directories in header
 * order, or invalid with the classified reason. Never thrown — always returned. */
export interface MultisigVerifyVerdict {
	valid: boolean;
	reason?: MultisigRejectReason;
	keyids?: string[];
	/** The https origin of each verified signer's key directory, in header order. */
	signatureAgents?: string[];
	/** The Accept-Signature value a refusal is answered with, set on the same refusals
	 * as the single-sig verdict's (see VerifyVerdict.acceptSignature). */
	acceptSignature?: string;
}

function rejected(reason: MultisigRejectReason, refusal?: Refusal): MultisigVerifyVerdict {
	const accept = refusal === undefined ? undefined : acceptSignatureFor(refusal);
	return { valid: false, reason, ...(accept !== undefined ? { acceptSignature: accept } : {}) };
}

/**
 * enforceEarlierCoverage applies WG-00 §5.2.2 to every signature that covers another
 * (Go enforceEarlierCoverage): for each covered "signature";key=X, X must be a signature
 * that appears earlier in Signature-Input, and the covering signature must also cover
 * "signature-input";key=X and every component X lists. A covered
 * "signature-input";key=X must likewise name an earlier signature.
 */
export function enforceEarlierCoverage(sigs: readonly ParsedSignature[]): boolean {
	const position = new Map(sigs.map((s, i) => [s.label, i] as const));
	for (let i = 0; i < sigs.length; i += 1) {
		const sig = sigs[i] as ParsedSignature;
		for (const c of sig.covered) {
			const name = c.name.toLowerCase();
			if (name !== "signature" && name !== "signature-input") continue;
			const key = componentParam(c, "key");
			const at = key === undefined ? undefined : position.get(key);
			if (key === undefined || key === "" || at === undefined || at >= i) return false;
			if (name === "signature" && !coversEarlierFully(sig, sigs[at] as ParsedSignature)) return false;
		}
	}
	return true;
}

// coversEarlierFully reports whether sig, which covers prev's Signature member, also
// covers prev's Signature-Input member and every component prev lists.
function coversEarlierFully(sig: ParsedSignature, prev: ParsedSignature): boolean {
	if (!coversComponent(sig.covered, keyed("signature-input", prev.label))) return false;
	return prev.covered.every((c) => coversComponent(sig.covered, c));
}

/**
 * Verify every signature on an inbound FORA request; return a reason-tagged verdict
 * carrying the verified keyids and directories in header order. Enforces the hop
 * budget, then the completeness of any coverage of an earlier signature, then each
 * signature independently — in that precedence. The request is refused if any one
 * signature fails.
 */
export async function verifyMultisigRequestServer(
	input: VerifyMultisigRequestInput,
): Promise<MultisigVerifyVerdict> {
	const parsed = parseSignatureHeaders(
		readHeader(input.headers, "signature-input"),
		readHeader(input.headers, "signature"),
	);
	if (!parsed.ok) return rejected("signature", parsed.refusal);
	const sigs = parsed.value;

	const budget = input.maxSignatures ?? 0;
	if (budget > 0 && sigs.length > budget) return rejected("hop_budget");
	if (!enforceEarlierCoverage(sigs)) return rejected("broken_chain");

	const req = verifiableRequest(input.method, input.url, input.body, input.headers);
	const nowSec = Math.floor(input.now());
	const keyids: string[] = [];
	const signatureAgents: string[] = [];
	for (const sig of sigs) {
		const verified = await verifyParsedSignature(
			req,
			sig,
			sigs.length,
			input.resolve,
			nowSec,
			input.maxSignatureAge,
		);
		if (!verified.ok) return rejected("signature", verified.refusal);
		keyids.push(verified.value.keyid);
		signatureAgents.push(verified.value.directory);
	}
	return { valid: true, keyids, signatureAgents };
}
