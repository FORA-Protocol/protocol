// sdk/ts outbound RFC 9421 request-SIGN byte-parity against the shared Go oracle, under
// the Web Bot Auth profile.
//
// Byte contract (Go oracle = sdk/go/helpers/sign.go::SignRequest / AppendSignature +
// sigbase.go::buildSignatureBase):
//   - covered set is @method @target-uri content-digest authorization and the
//     signature's own member "signature-agent";key="sig1", whose base line carries the
//     member's serialized value `"<origin>"`;
//   - parameters are created, expires, keyid, alg, nonce (when set), tag="web-bot-auth";
//   - Content-Digest = `sha-256=:<STANDARD-base64(SHA-256(body))>:`;
//   - authorization is ALWAYS bound — an empty string still renders as
//     `"authorization": ` with the trailing space (a `.trim()` would corrupt it);
//   - Signature-Agent is emitted as the one-member dictionary sig1="<origin>";
//   - created/expires are INJECTED (no wall clock).
//
// A vector's `signature_agent` is the ORIGIN the signer is given; the header it emits is
// in emitted_headers["signature-agent"]. An `append_only` vector is signed through
// appendSignature on an unsigned request, which must equal signRequest.
import { describe, expect, it } from "vitest";
import { appendSignature, type SignedRequest, signRequest } from "../core/sign-request.ts";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
import { b64urlToBytes, hexToBytes, importSigningKey } from "./wba-fixtures.ts";

type SignRequestVector = {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	authorization: string;
	signature_agent: string;
	append_only?: boolean;
	keyid: string;
	created: number;
	expires: number;
	nonce?: string;
	signer_seed_hex: string;
	pubkey_b64url: string;
	content_digest: string;
	signature_base: string;
	signature_input: string;
	signature: string;
	emitted_headers: Record<string, string[]>;
};

async function sign(v: SignRequestVector): Promise<SignedRequest> {
	const priv = await importSigningKey(v.signer_seed_hex);
	const opts = {
		method: v.method,
		url: v.url,
		body: hexToBytes(v.body_hex),
		authorization: v.authorization,
		signatureAgent: v.signature_agent,
		keyid: v.keyid,
		created: v.created,
		expires: v.expires,
		nonce: v.nonce ?? "",
	};
	return v.append_only === true
		? appendSignature(priv, { signatureInput: "", signature: "" }, opts)
		: signRequest(priv, opts);
}

describe("sdk/ts request signer matches the shared Go oracle (byte-identical)", () => {
	const doc = signRequestVectors as { vectors: SignRequestVector[] };

	it("vector matrix carries the empty-authorization, append and documented cases", () => {
		const names = new Set(doc.vectors.map((v) => v.name));
		expect(doc.vectors.some((v) => v.authorization === "")).toBe(true);
		expect(doc.vectors.some((v) => v.append_only === true)).toBe(true);
		expect(names.has("doc_single_hop_example")).toBe(true);
		expect(names.has("doc_broker_example")).toBe(true);
	});

	for (const v of doc.vectors) {
		it(`${v.name}: signature base, Signature-Input and Signature are byte-identical to the Go oracle`, async () => {
			const result = await sign(v);
			expect(result.signatureBase).toBe(v.signature_base);
			expect(result.contentDigest).toBe(v.content_digest);
			expect(result.signatureInput).toBe(v.signature_input);
			expect(result.signature).toBe(v.signature);
		});

		it(`${v.name}: the emitted header set is the oracle's`, async () => {
			const result = await sign(v);
			const emitted: Record<string, string[]> = {
				authorization: [result.authorization],
				"content-digest": [result.contentDigest],
				signature: [result.signature],
				"signature-agent": [result.signatureAgent],
				"signature-input": [result.signatureInput],
			};
			expect(emitted).toEqual(v.emitted_headers);
		});

		it(`${v.name}: round-trips — the signature verifies over the base under the vector's key`, async () => {
			const result = await sign(v);
			const pub = await crypto.subtle.importKey("raw", b64urlToBytes(v.pubkey_b64url), { name: "Ed25519" }, false, [
				"verify",
			]);
			const raw = result.signature.replace(/^sig1=:/, "").replace(/:$/, "");
			const bin = atob(raw);
			const sig = Uint8Array.from(bin, (c) => c.charCodeAt(0));
			expect(await crypto.subtle.verify("Ed25519", pub, sig, new TextEncoder().encode(result.signatureBase))).toBe(true);
		});
	}
});
