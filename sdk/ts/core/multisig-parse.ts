// sdk/ts Signature-Input / Signature parsing (RFC 9421 over RFC 8941) — the TS port of
// Go helpers.parseAllSignatures / rawInnerByLabel / splitTopLevelMembers (verify.go).
// The dictionaries are parsed by the structured-field parser in core/sfv.ts, so quoting,
// inner-list, integer and byte-sequence edge cases follow RFC 8941 rather than a
// pattern match. The verbatim inner value per label is split out separately: RFC 9421
// §2.5 terminates a signature base with the exact bytes the signer emitted, which a
// re-serialization cannot be trusted to reproduce.
//
// Every signer, verifier and appender on the request path reads signatures through
// parseSignatureHeaders, so a request carrying one signature is the N=1 case of the
// same parse.

import { type CoveredComponent, type ComponentParam, type Checked } from "./wba.ts";
import { parseDictionary, type SfItem, type SfParams } from "./sfv.ts";

/** One parsed signature: its label, covered components and parameters, and the
 * VERBATIM inner value after `label=` — the exact @signature-params bytes its base must
 * terminate with (Go sigParams.RawInner). */
export interface ParsedSignature {
	label: string;
	covered: CoveredComponent[];
	keyid: string;
	alg?: string;
	created?: number;
	expires?: number;
	nonce?: string;
	tag?: string;
	rawInner: string;
	/** The raw signature bytes the Signature header carries under this label. */
	signature: Uint8Array<ArrayBuffer>;
}

/**
 * Split one SFV dictionary header value on TOP-LEVEL commas, honoring quoted strings
 * and their backslash escapes (Go splitTopLevelMembers). A comma inside a quoted keyid
 * must NOT tear the member in two.
 */
export function splitTopLevelMembers(s: string): string[] {
	const parts: string[] = [];
	let start = 0;
	let inQuote = false;
	let escaped = false;
	for (let i = 0; i < s.length; i += 1) {
		const c = s[i];
		if (escaped) {
			escaped = false;
		} else if (c === "\\" && inQuote) {
			escaped = true;
		} else if (c === '"') {
			inQuote = !inQuote;
		} else if (c === "," && !inQuote) {
			parts.push(s.slice(start, i));
			start = i + 1;
		}
	}
	parts.push(s.slice(start));
	return parts;
}

/**
 * The VERBATIM member value after `label=` for each label across the given
 * Signature-Input header values (Go rawInnerByLabel). Later occurrences overwrite
 * earlier ones, matching SFV dictionary last-wins semantics, so the raw text
 * corresponds to the member the dictionary parse kept.
 */
export function rawInnerByLabel(values: string[]): Record<string, string> {
	const out: Record<string, string> = {};
	for (const v of values) {
		for (const member of splitTopLevelMembers(v)) {
			const eq = member.indexOf("=");
			if (eq <= 0) continue;
			const label = member.slice(0, eq).trim();
			out[label] = member.slice(eq + 1).trim();
		}
	}
	return out;
}

const malformed = (): { ok: false; refusal: { kind: "malformed" } } => ({
	ok: false,
	refusal: { kind: "malformed" },
});

/**
 * parseSignatureHeaders parses the request's Signature-Input and Signature values (each
 * with every field line joined, undefined when absent) into one ParsedSignature per
 * label, in Signature-Input order. A request missing either header is refused as
 * "unsigned"; one whose headers are not the dictionaries RFC 9421 defines, whose member
 * lacks a keyid, or whose label has no byte sequence in Signature is "malformed".
 */
export function parseSignatureHeaders(
	signatureInput: string | undefined,
	signature: string | undefined,
): Checked<ParsedSignature[]> {
	if (signatureInput === undefined || signature === undefined) {
		return { ok: false, refusal: { kind: "unsigned" } };
	}
	const inputs = parseDictionary(signatureInput);
	const sigs = parseDictionary(signature);
	if (inputs === undefined || sigs === undefined || inputs.size === 0) return malformed();
	const raw = rawInnerByLabel([signatureInput]);
	const out: ParsedSignature[] = [];
	for (const [label, member] of inputs) {
		if (member.kind !== "inner-list") return malformed();
		const covered: CoveredComponent[] = [];
		for (const item of member.items) {
			const c = coveredFromItem(item);
			if (c === undefined) return malformed();
			covered.push(c);
		}
		const params = signatureParams(member.params);
		const sig = sigs.get(label);
		if (params === undefined || sig?.kind !== "item" || sig.value.type !== "bytes") return malformed();
		out.push({ label, covered, ...params, rawInner: raw[label] ?? "", signature: sig.value.value });
	}
	return { ok: true, value: out };
}

// coveredFromItem converts one inner-list item (a covered-component identifier such as
// "@method" or "signature-agent";key="sig1") into a CoveredComponent. String-valued
// component parameters and Boolean flags are carried; anything else is malformed.
function coveredFromItem(item: SfItem): CoveredComponent | undefined {
	if (item.value.type !== "string") return undefined;
	const params: ComponentParam[] = [];
	for (const [key, v] of item.params) {
		if (v.type === "boolean" && v.value) params.push({ key, value: true });
		else if (v.type === "string") params.push({ key, value: v.value });
		else return undefined;
	}
	return { name: item.value.value, params };
}

type SignatureParams = Omit<ParsedSignature, "label" | "covered" | "rawInner" | "signature">;

// signatureParams reads keyid, alg, created, expires, nonce and tag off an inner list's
// parameters. A parameter of the wrong type, or no keyid, is malformed.
function signatureParams(params: SfParams): SignatureParams | undefined {
	const out: Partial<SignatureParams> = {};
	for (const name of ["keyid", "alg", "nonce", "tag"] as const) {
		const v = params.get(name);
		if (v === undefined) continue;
		if (v.type !== "string") return undefined;
		out[name] = v.value;
	}
	for (const name of ["created", "expires"] as const) {
		const v = params.get(name);
		if (v === undefined) continue;
		if (v.type !== "integer") return undefined;
		out[name] = v.value;
	}
	if (out.keyid === undefined || out.keyid === "") return undefined;
	return out as SignatureParams;
}
