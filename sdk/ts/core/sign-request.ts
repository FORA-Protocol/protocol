// sdk/ts outbound RFC 9421 request signer under the Web Bot Auth profile — the TS
// sibling of Go helpers.SignRequest / AppendSignature and Python httpsig.sign_request /
// append_signature. It signs byte-identical to the shared Go oracle, so a request signed
// in TS verifies unchanged at any Go/Python broker or exchange.
//
// A FORA RPC signature covers @method, @target-uri, content-digest, authorization and
// its own Signature-Agent member, "signature-agent";key="<label>", whose value
// <label>="<origin>" names the key directory a verifier resolves the keyid in. Its
// parameters are created, expires, keyid, alg, nonce (when set) and
// tag="web-bot-auth", in that order. authorization is ALWAYS bound — an empty string
// still renders, with the trailing space, so a later token injection cannot ride under
// the signature.
//
// This module also holds the one signature-base builder the request signer, the
// request verifiers and the key-directory response signatures share
// (buildSignatureBase), so sign and verify reconstruct the same bytes by construction.
//
// created/expires are INJECTED unix seconds (L1-pure, no wall clock). Values pass
// through verbatim: the caller supplies an absolute @target-uri; the signer never
// normalizes it.

import { opaqueUrl } from "../src/opaque-url.ts";
import { WBATag } from "../src/wire.ts";
import { parseSignatureHeaders, type ParsedSignature } from "./multisig-parse.ts";
import { parseDictionary, serializeBareItem, serializeMember } from "./sfv.ts";
import { stdBase64 } from "../src/base64url.ts";
import {
	checkHttpsOrigin,
	checkNonce,
	type CoveredComponent,
	coversComponent,
	keyed,
	MAX_SIGNATURE_LIFETIME,
	plain,
	REQUIRED_RPC_COMPONENTS,
	renderComponent,
	signatureAgentDictionary,
	signatureAgentMember,
	validLabel,
	WebBotAuthError,
} from "./wba.ts";

// The profile's public names that are defined in core/wba.ts, re-exported from this
// published module so a caller importing the signer reaches them.
export {
	acceptSignature,
	checkHttpsOrigin,
	MAX_SIGNATURE_LIFETIME,
	WebBotAuthError,
	type WebBotAuthErrorReason,
} from "./wba.ts";

/** Inputs for signRequest and appendSignature. */
export interface SignRequestOptions {
	method: string;
	url: string;
	// Byte param is Uint8Array<ArrayBuffer> (never SharedArrayBuffer-backed),
	// matching the sdk/ts WebCrypto convention (see core/verifier.ts, src/pop.ts).
	body: Uint8Array<ArrayBuffer>;
	authorization: string;
	/** The signer's key-directory origin, the ASCII serialization of an https origin such
	 * as "https://agent.example". Required: the signature covers its own Signature-Agent
	 * member, <label>="<origin>". Empty throws WebBotAuthError
	 * ("signature_agent_required"), a value that is not an https origin
	 * ("signature_agent_not_origin"). */
	signatureAgent: string;
	keyid: string;
	/** Unix seconds. The window expires − created must be positive and at most
	 * MAX_SIGNATURE_LIFETIME, or signing throws WebBotAuthError ("signature_lifetime"). */
	created: number;
	expires: number;
	/** RFC 9421 nonce parameter. Ed25519 is deterministic and created/expires have
	 * one-second resolution, so identical requests signed in the same second get the same
	 * signature and a replay store refuses the second. The signer reads no RNG: a caller
	 * that needs unique signatures passes a fresh nonce (the signing transport passes 64
	 * random bytes). Absent or "" emits no nonce. A non-empty nonce must use only
	 * base64url characters, or signing throws WebBotAuthError ("invalid_nonce"). */
	nonce?: string;
	/** The signature's label, which is also the key of its Signature-Agent member.
	 * Absent means "sig1" for signRequest and, for appendSignature, the first "sigN" no
	 * signature or member on the request uses. A label that is not a structured-field
	 * key, or one already in use, throws WebBotAuthError ("signature_label"). */
	label?: string;
	/** Read by appendSignature only. Makes the new signature cover the last signature
	 * already on the request, if there is one, as WG-00 §5.2.2 permits a party that
	 * forwards a request unchanged: every component that signature lists, its Signature
	 * member and its Signature-Input member. Leave it unset when the request was changed
	 * in any component the earlier signature covers. */
	coverPrevious?: boolean;
}

/**
 * The RFC 9421 artifacts a signed request carries, plus the covered base bytes.
 *
 * EVERY covered header is here, at the value that entered the base — the empty
 * authorization included. A verifier rebuilds the base from the request it received, so
 * a covered value bound but never sent is not bound at all; the oracle's signer reaches
 * the same place by mutating the request it was handed (helpers.SignRequest), which is
 * why it has no such field to omit. See docs/design-history.md, "A covered header the
 * peer never receives is not bound".
 */
export interface SignedRequest {
	contentDigest: string;
	signatureInput: string;
	signature: string;
	signatureBase: string;
	/** Echoed from the input so a caller attaching what this returns sends what was
	 * signed. Empty is a value, not an absence. */
	authorization: string;
	/** The Signature-Agent header value to send: the signature's own member,
	 * <label>="<origin>", after any members already on the request. */
	signatureAgent: string;
}

// RFC 9530 Content-Digest header value: `sha-256=:<STANDARD-base64(SHA-256)>:`.
// Exported so the verify sibling recomputes the digest over the exact body bytes
// and compares against the covered Content-Digest header byte-for-byte.
export async function contentDigest(
	body: Uint8Array<ArrayBuffer>,
): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body));
	return `sha-256=:${stdBase64(digest)}:`;
}

// --- the signature base ----------------------------------------------------------------

/** The parameters of one signature, the input of signatureInputInner. */
export interface SignatureParams {
	covered: readonly CoveredComponent[];
	keyid: string;
	alg: string;
	created: number;
	expires: number;
	nonce?: string;
	tag: string;
}

/**
 * signatureInputInner renders the inner list and parameter tail, the exact value used
 * both in the @signature-params line and as the Signature-Input member. The parameter
 * order is the one the Web Bot Auth profile's examples use — created, expires, keyid,
 * alg, nonce, tag — and the three SDKs make the same choice so their signatures agree
 * byte for byte. A verifier rebuilds the base from the parameters as received, so the
 * order is the signer's choice.
 */
export function signatureInputInner(p: SignatureParams): string {
	const keyid = serializeBareItem({ type: "string", value: p.keyid });
	let tail = `;created=${p.created};expires=${p.expires};keyid=${keyid};alg="${p.alg}"`;
	if (p.nonce !== undefined && p.nonce !== "") tail += `;nonce="${p.nonce}"`;
	return `(${p.covered.map(renderComponent).join(" ")})${tail};tag="${p.tag}"`;
}

/**
 * buildSignatureBase assembles the RFC 9421 §2.5 signature base: one
 * `<component>: <value>` line per covered component, in covered order, terminated by
 * `"@signature-params": <rawInner>` with NO trailing newline. `valueOf` resolves each
 * component's canonical value and throws when the message does not carry it. `rawInner`
 * is the VERBATIM inner list and parameters — the signer's own on sign, the wire's on
 * verify. The ONE base builder in the SDK's request path: the request signer, both
 * request verifiers and the key-directory response signatures all compose it.
 */
export function buildSignatureBase(
	covered: readonly CoveredComponent[],
	valueOf: (c: CoveredComponent) => string,
	rawInner: string,
): string {
	const lines = covered.map((c) => `${renderComponent(c)}: ${valueOf(c)}`);
	lines.push(`"@signature-params": ${rawInner}`);
	return lines.join("\n");
}

/** The request a request signature's components are resolved against. `header` answers
 * a field's value, every field line joined, or undefined when the request carries no
 * such field. */
export interface RequestComponents {
	method: string;
	url: string;
	header(name: string): string | undefined;
}

/** The component a signature covers names nothing the request carries. */
export class ComponentUnavailable extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ComponentUnavailable";
	}
}

/**
 * requestComponentValue yields the canonical value of a covered component of `req`:
 * @method, @target-uri (verbatim), @authority, a header, or the dictionary member a
 * "key" parameter selects (RFC 9421 §2.1.2) — serialized from the parsed member, so
 * signer and verifier agree byte for byte however the member was spaced on the wire.
 * Throws ComponentUnavailable for a header the request does not carry, a member it does
 * not hold, or a component parameter other than key.
 */
export function requestComponentValue(req: RequestComponents): (c: CoveredComponent) => string {
	return (c) => {
		const name = c.name.toLowerCase();
		if (c.params.length > 0) return memberValue(req, c);
		switch (name) {
			case "@method":
				return req.method.toUpperCase();
			case "@target-uri":
				return opaqueUrl(req.url);
			case "@authority":
				return new URL(opaqueUrl(req.url)).host.toLowerCase();
		}
		if (name.startsWith("@")) throw new ComponentUnavailable(`unsupported derived component ${c.name}`);
		const v = req.header(name);
		if (v === undefined) throw new ComponentUnavailable(`header "${name}" missing from request`);
		return v;
	};
}

function memberValue(req: RequestComponents, c: CoveredComponent): string {
	const p = c.params[0];
	if (c.name.startsWith("@") || c.params.length !== 1 || p?.key !== "key" || p.value === true) {
		throw new ComponentUnavailable(`unsupported component parameters on "${c.name}"`);
	}
	const raw = req.header(c.name.toLowerCase());
	if (raw === undefined) throw new ComponentUnavailable(`header "${c.name}" missing from request`);
	const member = parseDictionary(raw)?.get(p.value);
	if (member === undefined) throw new ComponentUnavailable(`${c.name} has no member "${p.value}"`);
	return serializeMember(member);
}

/** headerLookup answers a header from a plain lowercase-keyed record. */
function headerLookup(headers: Record<string, string>): (name: string) => string | undefined {
	return (name) => headers[name.toLowerCase()];
}

// --- signing ---------------------------------------------------------------------------

// The covered set of a FORA RPC signature labelled label: the FORA RPC components and
// the signature's own Signature-Agent member.
function rpcCovered(label: string): CoveredComponent[] {
	return [...REQUIRED_RPC_COMPONENTS.map(plain), keyed("signature-agent", label)];
}

// checkSignOptions refuses what no conformant signature can carry: a missing or
// non-origin Signature-Agent, an unusable label, a window that is not positive or longer
// than MAX_SIGNATURE_LIFETIME, or a nonce outside the base64url alphabet.
function checkSignOptions(opts: SignRequestOptions, label: string): void {
	if (opts.signatureAgent === "") {
		throw new WebBotAuthError("signature_agent_required", "a signature needs the signer's Signature-Agent origin");
	}
	checkHttpsOrigin(opts.signatureAgent);
	if (!validLabel(label)) {
		throw new WebBotAuthError("signature_label", `signature label ${JSON.stringify(label)} is not a structured-field key`);
	}
	const life = opts.expires - opts.created;
	if (opts.created <= 0 || life <= 0 || life > MAX_SIGNATURE_LIFETIME) {
		throw new WebBotAuthError(
			"signature_lifetime",
			`signature lifetime must be positive and at most ${MAX_SIGNATURE_LIFETIME}s: created=${opts.created} expires=${opts.expires}`,
		);
	}
	checkNonce(opts.nonce ?? "");
}

async function ed25519Sign(privKey: CryptoKey, base: string): Promise<string> {
	const sig = await crypto.subtle.sign("Ed25519", privKey, new TextEncoder().encode(base));
	return stdBase64(new Uint8Array(sig));
}

/**
 * signRequest signs opts as a FORA RPC under the Web Bot Auth profile with privKey and
 * returns the Content-Digest, Signature-Agent, Signature-Input and Signature header
 * values plus the exact signature base. Signature-Agent is the one-member dictionary
 * <label>="<origin>", replacing any value the request carried. The Signature is
 * `<label>=:<STANDARD-base64(sig)>:` (NOT b64url — do not unify with the thumbprint
 * encoding); Signature-Input is `<label>=` + the inner the base carries. Throws
 * WebBotAuthError, before signing anything, for what no profile signature carries.
 */
export async function signRequest(
	privKey: CryptoKey,
	opts: SignRequestOptions,
): Promise<SignedRequest> {
	const label = opts.label ?? "sig1";
	checkSignOptions(opts, label);
	const digestHeader = await contentDigest(opts.body);
	const signatureAgent = signatureAgentMember(label, opts.signatureAgent);
	const covered = rpcCovered(label);
	const inner = signatureInputInner(rpcParams(opts, covered));
	const base = buildSignatureBase(
		covered,
		requestComponentValue({
			method: opts.method,
			url: opts.url,
			header: headerLookup({
				"content-digest": digestHeader,
				authorization: opts.authorization,
				"signature-agent": signatureAgent,
			}),
		}),
		inner,
	);
	return {
		contentDigest: digestHeader,
		signatureInput: `${label}=${inner}`,
		signature: `${label}=:${await ed25519Sign(privKey, base)}:`,
		signatureBase: base,
		authorization: opts.authorization,
		signatureAgent,
	};
}

function rpcParams(opts: SignRequestOptions, covered: readonly CoveredComponent[]): SignatureParams {
	return {
		covered,
		keyid: opts.keyid,
		alg: "ed25519",
		created: opts.created,
		expires: opts.expires,
		...(opts.nonce !== undefined ? { nonce: opts.nonce } : {}),
		tag: WBATag,
	};
}

/** A request's prior signature state: the Signature-Input, Signature and
 * Signature-Agent header values already on it, every field line joined (all "" or
 * absent for an unsigned request), and its Content-Digest, kept when present. */
export interface PriorSignatures {
	signatureInput: string;
	signature: string;
	signatureAgent?: string;
	contentDigest?: string;
}

// usedLabels collects every label already present on the request: the members of
// Signature-Input and Signature, and the keys of a Signature-Agent dictionary. A new
// signature takes a label none of them uses, so its Signature-Agent member cannot
// collide with another signature's. A value that does not parse contributes none.
function usedLabels(prev: PriorSignatures): Set<string> {
	const used = new Set<string>();
	for (const value of [prev.signatureInput, prev.signature, prev.signatureAgent ?? ""]) {
		if (value.trim() === "") continue;
		for (const key of parseDictionary(value)?.keys() ?? []) used.add(key);
	}
	return used;
}

// nextFreeLabel returns "sigN" for the smallest N >= 1 no label on the request uses.
function nextFreeLabel(used: Set<string>): string {
	for (let n = 1; ; n += 1) {
		if (!used.has(`sig${n}`)) return `sig${n}`;
	}
}

/**
 * coverEarlier extends own, the covered set of a new signature, to cover the earlier
 * signature prev under WG-00 §5.2.2: every component prev lists that own does not
 * already cover, then "signature";key=<prev> and "signature-input";key=<prev>. A party
 * may do this only when it forwards the request unchanged in every component prev
 * covers.
 */
export function coverEarlier(own: readonly CoveredComponent[], prev: ParsedSignature): CoveredComponent[] {
	const out = [...own];
	for (const c of prev.covered) {
		if (!coversComponent(out, c)) out.push(c);
	}
	out.push(keyed("signature", prev.label), keyed("signature-input", prev.label));
	return out;
}

const joined = (existing: string, member: string): string =>
	existing.trim() === "" ? member : `${existing}, ${member}`;

/**
 * appendSignature adds a signature to the request whose prior signature state is `prev`
 * WITHOUT disturbing any signature already on it — the TS port of Go
 * helpers.AppendSignature. It appends the new signature's member to the Signature-Agent
 * dictionary and its members to Signature-Input and Signature, and returns the appended
 * values. The new signature covers its own request components and its own member and,
 * only when opts.coverPrevious is set, the last earlier signature (see
 * SignRequestOptions.coverPrevious). A Content-Digest in `prev` is kept rather than
 * recomputed. Appending to an unsigned request produces a signature byte-for-byte
 * identical to signRequest with the same label.
 *
 * A request whose Signature-Agent is not a dictionary, such as an agent's legacy String
 * form, throws WebBotAuthError ("signature_agent_form"): a String cannot take a second
 * member, and rewriting it would break the earlier signature.
 */
export async function appendSignature(
	privKey: CryptoKey,
	prev: PriorSignatures,
	opts: SignRequestOptions,
): Promise<SignedRequest> {
	const used = usedLabels(prev);
	const label = opts.label ?? nextFreeLabel(used);
	checkSignOptions(opts, label);
	if (used.has(label)) {
		throw new WebBotAuthError("signature_label", `signature label ${JSON.stringify(label)} is already in use on the request`);
	}
	const existingAgent = prev.signatureAgent ?? "";
	if (signatureAgentDictionary(existingAgent) === undefined) {
		throw new WebBotAuthError(
			"signature_agent_form",
			"Signature-Agent is not a dictionary, so it cannot take another signature's member",
		);
	}
	let covered = rpcCovered(label);
	if (opts.coverPrevious === true && prev.signatureInput.trim() !== "") {
		const parsed = parseSignatureHeaders(prev.signatureInput, prev.signature);
		if (!parsed.ok) throw new Error("appendSignature: cannot cover the previous signature: it does not parse");
		covered = coverEarlier(covered, parsed.value[parsed.value.length - 1] as ParsedSignature);
	}
	const digestHeader =
		prev.contentDigest !== undefined && prev.contentDigest !== ""
			? prev.contentDigest
			: await contentDigest(opts.body);
	const signatureAgent = joined(existingAgent, signatureAgentMember(label, opts.signatureAgent));
	const inner = signatureInputInner(rpcParams(opts, covered));
	const base = buildSignatureBase(
		covered,
		requestComponentValue({
			method: opts.method,
			url: opts.url,
			header: headerLookup({
				"content-digest": digestHeader,
				authorization: opts.authorization,
				"signature-agent": signatureAgent,
				"signature-input": prev.signatureInput,
				signature: prev.signature,
			}),
		}),
		inner,
	);
	return {
		contentDigest: digestHeader,
		signatureInput: joined(prev.signatureInput, `${label}=${inner}`),
		signature: joined(prev.signature, `${label}=:${await ed25519Sign(privKey, base)}:`),
		signatureBase: base,
		authorization: opts.authorization,
		signatureAgent,
	};
}
