// The Web Bot Auth draft's own test vectors (draft-ietf-webbotauth-httpsig-protocol-01
// Appendix E, and the JSON file its Appendix F.3 points to) against the shared Go
// oracle, sdk/go/helpers/testdata/wba-appendix-e-vectors.json.
//
// For every request vector the TS face must rebuild expected_base byte for byte, through
// the same parser and base builder its verifiers use. An Ed25519 vector's signature must
// verify over that base under the injected key; an RSASSA-PSS vector's alg must be
// refused, since the SDK verifies Ed25519 only. The FORA request verifier must refuse
// every request vector with the refusal the corpus pins: "unsupported_alg", or
// "missing_component" naming @method, because the vectors cover @authority and at most
// Signature-Agent. The signed directory response (E.2.3) must verify through
// verifyDirectoryResponse, over the base the corpus states.

import { describe, expect, it } from "vitest";
import { verifyDirectoryResponse } from "../core/directory-response.ts";
import { algAccepted, parseSignatureHeaders, type ParsedSignature } from "../core/multisig-parse.ts";
import { buildSignatureBase, requestComponentValue } from "../core/sign-request.ts";
import { ed25519Verify, verifiableRequest, verifyParsedSignature } from "../core/verify-request.ts";
import appendixE from "../../go/helpers/testdata/wba-appendix-e-vectors.json";
import { b64urlToBytes } from "./wba-fixtures.ts";

type RequestVector = {
	name: string;
	section: string;
	method: string;
	url: string;
	signature_agent?: string;
	signature_input: string;
	signature: string;
	pubkey_b64url?: string;
	now: number;
	expected_base: string;
	expected_signature: "verified" | "unsupported_alg";
	expected_verify_request_refusal: "unsupported_alg" | "missing_component";
	expected_missing_component?: string;
};

type DirectoryVector = {
	name: string;
	section: string;
	authority: string;
	body: string;
	content_digest: string;
	signature_input: string;
	signature: string;
	keys: string[];
	now: number;
	expected_base: string;
	expected_verified: string[];
};

const corpus = appendixE as unknown as {
	request_vectors: RequestVector[];
	directory_vectors: DirectoryVector[];
};

const utf8 = (s: string) => new TextEncoder().encode(s) as Uint8Array<ArrayBuffer>;
const EMPTY = new Uint8Array(0) as Uint8Array<ArrayBuffer>;

function headersOf(v: RequestVector): Record<string, string> {
	const h: Record<string, string> = { "signature-input": v.signature_input, signature: v.signature };
	if (v.signature_agent !== undefined) h["signature-agent"] = v.signature_agent;
	return h;
}

function firstSignature(v: { signature_input: string; signature: string }): ParsedSignature {
	const parsed = parseSignatureHeaders(v.signature_input, v.signature);
	if (!parsed.ok) throw new Error(`parse refused: ${parsed.refusal.kind}`);
	return parsed.value[0] as ParsedSignature;
}

describe("the Appendix E corpus", () => {
	it("carries every Appendix E vector and the F.3 file", () => {
		const sections = new Set([...corpus.request_vectors, ...corpus.directory_vectors].map((v) => v.section));
		for (const want of ["E.1.1", "E.1.2", "E.2.1", "E.2.2", "E.2.3", "F.3"]) {
			expect(sections.has(want), want).toBe(true);
		}
	});
});

describe("request vectors replay against the Go oracle", () => {
	for (const v of corpus.request_vectors) {
		it(`${v.name} (${v.section}): base, ${v.expected_signature}, refused ${v.expected_verify_request_refusal}`, async () => {
			const req = verifiableRequest(v.method, v.url, EMPTY, headersOf(v));
			const sig = firstSignature(v);
			const base = buildSignatureBase(sig.covered, requestComponentValue(req), sig.rawInner);
			expect(base).toBe(v.expected_base);

			// An RSA vector carries no key: the verifier holds an all-zero Ed25519 key and
			// refuses the alg before it uses any key.
			const pub = v.pubkey_b64url !== undefined ? b64urlToBytes(v.pubkey_b64url) : new Uint8Array(32);
			if (v.expected_signature === "verified") {
				expect(algAccepted(sig)).toBe(true);
				expect(await ed25519Verify(pub, sig.signature, utf8(base))).toBe(true);
			} else {
				expect(algAccepted(sig)).toBe(false);
			}

			const checked = await verifyParsedSignature(req, sig, 1, { resolve: () => pub }, v.now);
			expect(checked.ok).toBe(false);
			if (checked.ok) return;
			expect(checked.refusal.kind).toBe(v.expected_verify_request_refusal);
			if (checked.refusal.kind === "missing_component") {
				expect(checked.refusal.component).toBe(v.expected_missing_component);
			}
		});
	}
});

describe("directory vectors replay against the Go oracle", () => {
	for (const v of corpus.directory_vectors) {
		it(`${v.name} (${v.section}): base and the verified keys`, async () => {
			const headers = {
				"content-digest": v.content_digest,
				"signature-input": v.signature_input,
				signature: v.signature,
			};
			// The verifier hands the Ed25519 primitive the base it rebuilt; record it and
			// verify with the default primitive.
			const bases: string[] = [];
			const verified = await verifyDirectoryResponse(v.authority, headers, utf8(v.body), v.keys.map(b64urlToBytes), v.now, {
				verifyEd25519: async (pub, sig, message) => {
					bases.push(new TextDecoder().decode(message));
					return ed25519Verify(pub, sig, message);
				},
			});
			expect(bases).toEqual([v.expected_base]);
			expect([...verified].sort()).toEqual(v.expected_verified);
		});
	}
});
