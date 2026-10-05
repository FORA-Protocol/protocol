// Key-directory response signatures (WG-00 §5.5, Appendix B.1) against the shared Go
// oracle, sdk/go/helpers/testdata/directory-response-vectors.json.
//
// verifyDirectoryResponse must report exactly the thumbprints of the listed keys whose
// response signature verifies for the authority, and throw "digest_mismatch" or
// "unsigned" where the oracle does. signDirectoryResponse, given a vector's seeds,
// authority and window, must reproduce the oracle's three headers byte for byte — the
// documented example included.

import { describe, expect, it } from "vitest";
import {
	DirectoryResponseError,
	signDirectoryResponse,
	verifyDirectoryResponse,
} from "../core/directory-response.ts";
import { thumbprint } from "../src/thumbprint.ts";
import directoryVectors from "../../go/helpers/testdata/directory-response-vectors.json";
import { b64urlToBytes, hexToBytes } from "./wba-fixtures.ts";

type DirectoryVector = {
	name: string;
	authority: string;
	body: string;
	content_digest: string;
	signature_input: string;
	signature: string;
	keys: string[];
	signer_seeds_hex: string[] | null;
	created?: number;
	expires?: number;
	now: number;
	expected_verified: string[];
	expected_error: "" | "digest_mismatch" | "unsigned";
};

const vectors = (directoryVectors as { vectors: DirectoryVector[] }).vectors;

const utf8 = (s: string) => new TextEncoder().encode(s) as Uint8Array<ArrayBuffer>;

function headersOf(v: DirectoryVector): Record<string, string> {
	const h: Record<string, string> = {};
	if (v.content_digest !== "") h["content-digest"] = v.content_digest;
	if (v.signature_input !== "") h["signature-input"] = v.signature_input;
	if (v.signature !== "") h.signature = v.signature;
	return h;
}

async function signerOf(seedHex: string): Promise<{ privKey: CryptoKey; keyid: string }> {
	const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
	const seed = hexToBytes(seedHex);
	const der = new Uint8Array(prefix.length + seed.length);
	der.set(prefix, 0);
	der.set(seed, prefix.length);
	const privKey = await crypto.subtle.importKey("pkcs8", der, { name: "Ed25519" }, true, ["sign"]);
	const jwk = await crypto.subtle.exportKey("jwk", privKey);
	return { privKey, keyid: await thumbprint(b64urlToBytes(jwk.x ?? "")) };
}

describe("verifyDirectoryResponse matches the Go oracle", () => {
	it("the corpus carries the documented example and every refusal", () => {
		const names = new Set(vectors.map((v) => v.name));
		for (const want of [
			"doc_directory_example",
			"two_keys_one_signed",
			"expired",
			"created_in_the_future",
			"key_not_listed",
			"signed_for_another_authority",
			"body_changed",
			"unsigned",
			"wrong_tag",
			"no_authority_covered",
		]) {
			expect(names.has(want), want).toBe(true);
		}
	});

	for (const v of vectors) {
		it(`${v.name}: ${v.expected_error || `verifies ${v.expected_verified.length} key(s)`}`, async () => {
			const run = verifyDirectoryResponse(v.authority, headersOf(v), utf8(v.body), v.keys.map(b64urlToBytes), v.now);
			if (v.expected_error !== "") {
				const err = await run.catch((e: unknown) => e);
				expect(err).toBeInstanceOf(DirectoryResponseError);
				expect((err as DirectoryResponseError).reason).toBe(v.expected_error);
				return;
			}
			expect([...(await run)].sort()).toEqual(v.expected_verified);
		});
	}

	it("a response signature names the authority it was served under: another host verifies nothing", async () => {
		const v = vectors.find((x) => x.name === "doc_directory_example") as DirectoryVector;
		const verified = await verifyDirectoryResponse("evil.example", headersOf(v), utf8(v.body), v.keys.map(b64urlToBytes), v.now);
		expect(verified.size).toBe(0);
	});
});

describe("verifyDirectoryResponse verifies through an injected Ed25519 primitive", () => {
	const doc = (): DirectoryVector => vectors.find((x) => x.name === "doc_directory_example") as DirectoryVector;

	// corrupted flips one byte of every signature the Signature header carries, so the
	// WebCrypto default refuses each.
	function corrupted(v: DirectoryVector): Record<string, string> {
		const h = headersOf(v);
		const sig = h["signature"] as string;
		const flip = (b64: string): string => (b64.startsWith("A") ? `B${b64.slice(1)}` : `A${b64.slice(1)}`);
		return { ...h, signature: sig.replace(/:([^:]+):/g, (_m, b64: string) => `:${flip(b64)}:`) };
	}

	it("the default primitive refuses a corrupted signature", async () => {
		const v = doc();
		const verified = await verifyDirectoryResponse(v.authority, corrupted(v), utf8(v.body), v.keys.map(b64urlToBytes), v.now);
		expect(verified.size).toBe(0);
	});

	it("an injected primitive that always answers true accepts the corrupted signature", async () => {
		const v = doc();
		const calls: number[] = [];
		const verified = await verifyDirectoryResponse(v.authority, corrupted(v), utf8(v.body), v.keys.map(b64urlToBytes), v.now, {
			verifyEd25519: async (pub, sig, msg) => {
				calls.push(pub.length + sig.length + msg.length);
				return true;
			},
		});
		expect([...verified].sort()).toEqual(v.expected_verified);
		expect(calls.length).toBeGreaterThan(0);
	});

	it("an injected primitive that always answers false refuses the documented example", async () => {
		const v = doc();
		const verified = await verifyDirectoryResponse(v.authority, headersOf(v), utf8(v.body), v.keys.map(b64urlToBytes), v.now, {
			verifyEd25519: async () => false,
		});
		expect(verified.size).toBe(0);
	});
});

describe("signDirectoryResponse reproduces the Go oracle", () => {
	// The vectors Go produced through SignDirectoryResponse unaltered. The authority a
	// signed_for_another_authority vector was signed for is not recorded, so it is not
	// replayed.
	const RESIGNED = [
		"doc_directory_example",
		"two_keys_both_signed",
		"two_keys_one_signed",
		"expired",
		"created_in_the_future",
		"key_not_listed",
	];
	for (const v of vectors.filter((x) => RESIGNED.includes(x.name))) {
		it(`${v.name}: Content-Digest, Signature-Input and Signature are byte-identical`, async () => {
			const signers = await Promise.all((v.signer_seeds_hex ?? []).map(signerOf));
			const sig = await signDirectoryResponse(v.authority, utf8(v.body), signers, v.created ?? 0, v.expires ?? 0);
			expect(sig).toEqual({
				contentDigest: v.content_digest,
				signatureInput: v.signature_input,
				signature: v.signature,
			});
		});
	}

	it("refuses no authority, no signer, or a window that is not positive", async () => {
		const signer = await signerOf("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
		await expect(signDirectoryResponse("", utf8("{}"), [signer], 1, 2)).rejects.toThrow(/authority/);
		await expect(signDirectoryResponse("a.example", utf8("{}"), [], 1, 2)).rejects.toThrow(/signer/);
		await expect(signDirectoryResponse("a.example", utf8("{}"), [signer], 2, 2)).rejects.toThrow(/window/);
	});
});
