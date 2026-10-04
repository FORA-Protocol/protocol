// The Web Bot Auth profile of RFC 9421 request signatures, as FORA pins it:
// draft-ietf-webbotauth-httpsig-protocol-00 ("WG-00"). The authentication page's
// "The Web Bot Auth Profile" is the normative statement; this module holds the pieces
// of it the signer and the verifiers share. TS port of sdk/go/helpers/wba.go.
//
//   - Signature-Agent is a structured-field Dictionary. The member for a signature is
//     <label>="https://<origin>", and the signature covers it as
//     "signature-agent";key="<label>". Each signature's keyid is resolved in the key
//     directory its own covered member names.
//   - Every signature carries created, expires, keyid, alg="ed25519" and
//     tag="web-bot-auth"; a FORA signer adds a fresh nonce.
//   - A verifier also accepts the legacy sf-string form of Signature-Agent, covered as
//     plain "signature-agent", on a request carrying one signature, a member key that
//     differs from the label, no nonce, and a type=directory member parameter. It
//     refuses the bare unquoted value the v1.0.8 SDKs sent.

import { WBATag } from "../src/wire.ts";
import {
	parseDictionary,
	parseItem,
	type SfDictionary,
	type SfMember,
	serializeBareItem,
} from "./sfv.ts";

/** The longest window (expires − created), in seconds, a FORA signer gives a request
 * signature. A signature is never a long-lived credential. */
export const MAX_SIGNATURE_LIFETIME = 300;

/** Why a signing call refused, or why a Signature-Agent was not accepted. */
export type WebBotAuthErrorReason =
	| "signature_agent_required"
	| "signature_agent_not_origin"
	| "signature_agent_form"
	| "signature_label"
	| "signature_lifetime"
	| "invalid_nonce";

/**
 * WebBotAuthError is a refusal to sign what no Web Bot Auth signature can carry: no
 * Signature-Agent origin, a value that is not an https origin, a request whose
 * Signature-Agent cannot take another member, an unusable label, a window that is not
 * positive or longer than MAX_SIGNATURE_LIFETIME, or a nonce outside the base64url
 * alphabet. Nothing is signed when it is thrown. checkHttpsOrigin throws it too.
 */
export class WebBotAuthError extends Error {
	readonly reason: WebBotAuthErrorReason;
	constructor(reason: WebBotAuthErrorReason, message: string) {
		super(message);
		this.name = "WebBotAuthError";
		this.reason = reason;
	}
}

/**
 * checkHttpsOrigin returns when `s` is the ASCII serialization of an https origin, the
 * only value a Signature-Agent member carries in this profile: "https://" followed by a
 * lowercase host (an IP literal allowed, an IPv6 one in brackets) and, only when it is
 * not 443, ":port". Anything else throws WebBotAuthError ("signature_agent_not_origin"):
 * another scheme, uppercase, a path (even "/"), a query, a fragment, credentials, or a
 * non-ASCII host, which an origin carries punycoded. The same rule as Go
 * helpers.CheckHTTPSOrigin and Python check_https_origin.
 */
export function checkHttpsOrigin(s: string): void {
	const notOrigin = (why: string): WebBotAuthError =>
		new WebBotAuthError("signature_agent_not_origin", `Signature-Agent ${JSON.stringify(s)} ${why}`);
	if (!s.startsWith("https://")) throw notOrigin("does not start with https://");
	const rest = s.slice("https://".length);
	if (rest === "" || /[/?#@\\%]/.test(rest)) throw notOrigin("carries more than a host and port");
	for (let i = 0; i < rest.length; i += 1) {
		const c = rest.charCodeAt(i);
		if (c >= 0x80 || c < 0x21 || (c >= 0x41 && c <= 0x5a)) throw notOrigin("is not a lowercase ASCII origin");
	}
	const split = splitHostPort(rest);
	if (split === undefined || split.host === "") throw notOrigin("is not a host[:port]");
	const { host, port } = split;
	if (host.includes(":") ? !isIPv6(host) : !isOriginHostName(host)) throw notOrigin("is not a host[:port]");
	if (port !== undefined) {
		const n = Number(port);
		if (!/^[0-9]+$/.test(port) || n === 0 || n > 65535 || port[0] === "0") {
			throw notOrigin("carries an invalid port");
		}
		if (n === 443) throw notOrigin("spells out the default port");
	}
}

// splitHostPort separates host from port the way a URL authority does: a bracketed IPv6
// literal, or a host with at most one colon. port is "" for a trailing colon and
// undefined when there is no colon at all.
function splitHostPort(rest: string): { host: string; port: string | undefined } | undefined {
	if (rest.startsWith("[")) {
		const close = rest.indexOf("]");
		if (close < 0) return undefined;
		const after = rest.slice(close + 1);
		if (after !== "" && !after.startsWith(":")) return undefined;
		return { host: rest.slice(1, close), port: after === "" ? undefined : after.slice(1) };
	}
	const colon = rest.indexOf(":");
	if (colon < 0) return { host: rest, port: undefined };
	if (rest.indexOf(":", colon + 1) >= 0) return undefined;
	return { host: rest.slice(0, colon), port: rest.slice(colon + 1) };
}

// isOriginHostName reports whether name is a lowercase registered name or IPv4 literal:
// letters, digits, '-', '.' and '_' only, with no empty label.
function isOriginHostName(name: string): boolean {
	if (name === "" || name.startsWith(".") || name.includes("..")) return false;
	return /^[a-z0-9._-]+$/.test(name);
}

// isIPv6 reports whether s is an IPv6 address in text form: eight 16-bit hex groups, or
// fewer around a single "::", the last two optionally written as a dotted IPv4 address.
function isIPv6(s: string): boolean {
	const halves = s.split("::");
	if (halves.length > 2) return false;
	const groups = (part: string): string[] => (part === "" ? [] : part.split(":"));
	const head = groups(halves[0] ?? "");
	const tail = halves.length === 2 ? groups(halves[1] ?? "") : [];
	const all = [...head, ...tail];
	let count = 0;
	for (let i = 0; i < all.length; i += 1) {
		const g = all[i] as string;
		if (i === all.length - 1 && g.includes(".")) {
			if (!isIPv4(g)) return false;
			count += 2;
		} else if (/^[0-9a-f]{1,4}$/.test(g)) {
			count += 1;
		} else {
			return false;
		}
	}
	return halves.length === 2 ? count < 8 : count === 8;
}

function isIPv4(s: string): boolean {
	const parts = s.split(".");
	return parts.length === 4 && parts.every((p) => /^[0-9]{1,3}$/.test(p) && Number(p) <= 255);
}

/** checkNonce refuses a nonce with a character outside the base64url alphabet, the same
 * rule as Go and Python: a quote would end the quoted parameter early, and the SDKs
 * would write different bytes. */
export function checkNonce(nonce: string): void {
	if (!/^[A-Za-z0-9_-]*$/.test(nonce)) {
		throw new WebBotAuthError("invalid_nonce", "nonce must use only base64url characters");
	}
}

/** validLabel reports whether label is a structured-field key (RFC 8941 §3.1.2):
 * lowercase letter or '*' first, then lowercase letters, digits, '_', '-', '.' or '*'. */
export function validLabel(label: string): boolean {
	return /^[a-z*][a-z0-9_.*-]*$/.test(label);
}

/** signatureAgentMember renders one Signature-Agent dictionary member for label. origin
 * has passed checkHttpsOrigin, so it carries no character a String would escape. */
export function signatureAgentMember(label: string, origin: string): string {
	return `${label}="${origin}"`;
}

// --- covered components ----------------------------------------------------------------

/** One RFC 9421 §2.1 parameter on a covered-component identifier: a String value, such
 * as the key="sig1" on "signature-agent";key="sig1", or `true` for a Boolean flag, such
 * as the req on "@authority";req. */
export interface ComponentParam {
	key: string;
	value: string | true;
}

/** One entry of a signature's covered-component set: a name and its parameters. */
export interface CoveredComponent {
	name: string;
	params: readonly ComponentParam[];
}

/** plain builds a covered component with no parameters. */
export function plain(name: string): CoveredComponent {
	return { name, params: [] };
}

/** keyed builds a covered component selecting the dictionary member `key` of `name`. */
export function keyed(name: string, key: string): CoveredComponent {
	return { name, params: [{ key: "key", value: key }] };
}

/** The value of the named String parameter on c, or undefined. */
export function componentParam(c: CoveredComponent, key: string): string | undefined {
	const p = c.params.find((x) => x.key === key);
	return typeof p?.value === "string" ? p.value : undefined;
}

/** renderComponent serializes a covered-component identifier as it appears in the
 * Signature-Input inner list and in a signature-base line: `"name";k="v";flag`. */
export function renderComponent(c: CoveredComponent): string {
	let out = serializeBareItem({ type: "string", value: c.name });
	for (const p of c.params) {
		out += p.value === true ? `;${p.key}` : `;${p.key}=${serializeBareItem({ type: "string", value: p.value })}`;
	}
	return out;
}

/** sameComponent reports whether a and b are one component: the same name, compared
 * case-insensitively, and the same parameters in the same order. */
export function sameComponent(a: CoveredComponent, b: CoveredComponent): boolean {
	if (a.name.toLowerCase() !== b.name.toLowerCase() || a.params.length !== b.params.length) return false;
	return a.params.every((p, i) => p.key === b.params[i]?.key && p.value === b.params[i]?.value);
}

/** coversComponent reports whether set contains c (see sameComponent). */
export function coversComponent(set: readonly CoveredComponent[], c: CoveredComponent): boolean {
	return set.some((s) => sameComponent(s, c));
}

/** The components a FORA RPC signature must cover beyond its own Signature-Agent member,
 * which is checked on its own, and beyond x-entitlement-token, required only when the
 * request carries one. */
export const REQUIRED_RPC_COMPONENTS = ["@method", "@target-uri", "content-digest", "authorization"] as const;

/** The entitlement-token header in covered-component (lowercase) form. When a request
 * carries it, the signature must cover it. */
export const ENTITLEMENT_COVERED = "x-entitlement-token";

const SIGNATURE_AGENT = "signature-agent";

/** acceptSignature renders the Accept-Signature value a FORA verifier answers a refused
 * RPC signature with: the components a FORA RPC signature must cover, the dictionary
 * form of Signature-Agent, and the created, expires and tag parameters (RFC 9421 §5.1,
 * WG-00 §5.3). `entitlement` adds x-entitlement-token, for a request carrying that
 * header. */
export function acceptSignature(entitlement: boolean): string {
	const covered = [...REQUIRED_RPC_COMPONENTS.map(plain), keyed(SIGNATURE_AGENT, "sig1")];
	if (entitlement) covered.push(plain(ENTITLEMENT_COVERED));
	return `sig1=(${covered.map(renderComponent).join(" ")});created;expires;tag="${WBATag}"`;
}

// --- why a signature was refused -------------------------------------------------------

/**
 * Refusal is the internal verdict of one profile check, before it collapses to the
 * public reject reason. It carries what the Accept-Signature decision needs: a missing
 * component, a refused tag or Signature-Agent form, and a request with no signature are
 * answered with Accept-Signature; everything else is not.
 */
export type Refusal =
	| { kind: "unsigned" }
	| { kind: "malformed" }
	| { kind: "missing_component"; component: string }
	| { kind: "tag" }
	| { kind: "form" }
	| { kind: "not_origin" }
	| { kind: "signature" };

/** acceptSignatureFor returns the Accept-Signature value a verifier answers `r` with, or
 * undefined when the refusal is of a well-formed signature that failed for another
 * reason: a bad signature, an unknown key, a stale window, a malformed header. */
export function acceptSignatureFor(r: Refusal): string | undefined {
	switch (r.kind) {
		case "missing_component":
			return acceptSignature(r.component === ENTITLEMENT_COVERED);
		case "unsigned":
		case "tag":
		case "form":
			return acceptSignature(false);
		default:
			return undefined;
	}
}

// --- which directory a signature names -------------------------------------------------

/** The parts of one parsed signature the directory rule reads. */
export interface SignatureNaming {
	label: string;
	covered: readonly CoveredComponent[];
}

/** The outcome of a profile check: a value, or the refusal. */
export type Checked<T> = { ok: true; value: T } | { ok: false; refusal: Refusal };

const refuse = (refusal: Refusal): { ok: false; refusal: Refusal } => ({ ok: false, refusal });

/**
 * signatureDirectory returns the key-directory origin a signature names: the
 * Signature-Agent member it covers. A signature that covers an earlier one also covers
 * that signature's member (WG-00 §5.2.2), so the member followed is the one keyed to the
 * signature's own label (WG-00 §5.2.1); a signature covering exactly one member follows
 * that one, whatever its key, because the profile accepts a member key that differs from
 * the label. A signature covering several members, none keyed to its label, names no
 * directory. `agentHeader` is the request's Signature-Agent, every field line joined, or
 * undefined when absent; `sigCount` is the number of signatures on the request, because
 * the legacy String form, covered as plain "signature-agent", is accepted only when there
 * is one.
 */
export function signatureDirectory(
	agentHeader: string | undefined,
	sig: SignatureNaming,
	sigCount: number,
): Checked<string> {
	const keys: string[] = [];
	let plainCount = 0;
	for (const c of sig.covered) {
		if (c.name.toLowerCase() !== SIGNATURE_AGENT) continue;
		const key = componentParam(c, "key");
		if (key !== undefined && key !== "" && c.params.length === 1) keys.push(key);
		else if (c.params.length === 0) plainCount += 1;
		else return refuse({ kind: "form" });
	}
	if (plainCount === 0 && keys.length === 0) return refuse({ kind: "missing_component", component: SIGNATURE_AGENT });
	if (plainCount > 1 || (plainCount === 1 && keys.length > 0)) return refuse({ kind: "form" });
	if (plainCount === 1) return sigCount > 1 ? refuse({ kind: "form" }) : legacyDirectory(agentHeader);
	let key = keys[0] as string;
	if (keys.length > 1) {
		if (!keys.includes(sig.label)) return refuse({ kind: "form" });
		key = sig.label;
	}
	if (agentHeader === undefined) return refuse({ kind: "missing_component", component: SIGNATURE_AGENT });
	const dict = signatureAgentDictionary(agentHeader);
	if (dict === undefined) return refuse({ kind: "form" });
	const member = dict.get(key);
	if (member === undefined) return refuse({ kind: "form" });
	return directoryFromMember(member);
}

/** signatureAgentDictionary parses a Signature-Agent value as a Dictionary. An empty
 * value is an empty dictionary; a value that is not a Dictionary is undefined. */
export function signatureAgentDictionary(value: string): SfDictionary | undefined {
	return value.trim() === "" ? new Map() : parseDictionary(value);
}

// directoryFromMember reads a Signature-Agent member as the origin of a key directory.
// The member must be a String; a type parameter, when present, must be directory, since
// WG-00 §5.2.1 has a verifier ignore a member of any other type. The value must be an
// https origin.
function directoryFromMember(m: SfMember): Checked<string> {
	if (m.kind !== "item" || m.value.type !== "string") return refuse({ kind: "form" });
	const type = m.params.get("type");
	if (type !== undefined && !((type.type === "string" || type.type === "token") && type.value === "directory")) {
		return refuse({ kind: "form" });
	}
	return originChecked(m.value.value);
}

// legacyDirectory reads a Signature-Agent carried in the legacy form, a single String
// covered as plain "signature-agent". The bare unquoted value the v1.0.8 SDKs sent
// parses as a Token, not a String, and is refused.
function legacyDirectory(agentHeader: string | undefined): Checked<string> {
	if (agentHeader === undefined) return refuse({ kind: "missing_component", component: SIGNATURE_AGENT });
	const item = parseItem(agentHeader);
	if (item === undefined || item.value.type !== "string") return refuse({ kind: "form" });
	return originChecked(item.value.value);
}

function originChecked(origin: string): Checked<string> {
	try {
		checkHttpsOrigin(origin);
	} catch {
		return refuse({ kind: "not_origin" });
	}
	return { ok: true, value: origin };
}
