// sdk/ts multi-signature append+verify parity against the shared Go oracle, under the
// Web Bot Auth profile.
//
// Every signature on a request is verified on its own, against the key its keyid names
// in the directory its OWN covered Signature-Agent member names. A signature need not
// cover another (WG-00 §5.2.2: a forwarder MAY); one that does must cover the earlier
// signature's Signature member, its Signature-Input member and every component it
// lists, and may only cover a signature that appears before it. The hop budget counts
// every signature. Labels carry no meaning.
//
// Faces under test:
//   - core/sign-request.ts::appendSignature — adds a signature with its own label and
//     Signature-Agent member WITHOUT disturbing existing ones, covering the last earlier
//     signature only under coverPrevious;
//   - core/verify-multisig-request.ts::verifyMultisigRequestServer — the hop budget
//     FIRST (hop_budget), the completeness of any earlier coverage next (broken_chain),
//     then each signature (signature); returns the verified keyids and directories in
//     header order, never throws.
//
// The test resolver is keyed by (directory, keyid), the directory being the one the
// verifier resolved for that signature, so a port that resolves through the wrong member
// fails wrong_directory_member.

import { describe, expect, it } from "vitest";
import { appendSignature, type SignedRequest, signRequest } from "../core/sign-request.ts";
import { WebBotAuthError } from "../core/wba.ts";
import {
	type MultisigRejectReason,
	type MultisigVerifyHeaders,
	verifyMultisigRequestServer,
} from "../core/verify-multisig-request.ts";
import { readHeader } from "../core/verify-request.ts";
import multisigVectors from "../../go/helpers/testdata/multisig-chain-vectors.json";
import { b64urlToBytes, directoryResolver, hexToBytes, importSigningKey } from "./wba-fixtures.ts";

type MultisigHop = {
	keyid: string;
	pubkey_b64url: string;
	seed_hex: string;
	directory: string;
	nonce?: string;
	cover_previous?: boolean;
};

type MultisigChainVector = {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	authorization: string;
	signature_agent: string;
	created: number;
	expires: number;
	content_digest: string;
	signature_input: string;
	signature: string;
	hops: MultisigHop[];
	max_signatures: number;
	expected_verified: boolean;
	expected_keyids: string[] | null;
	expected_directories: string[] | null;
	expected_reason: string;
	omit_headers?: string[];
	extra_headers?: Record<string, string>;
};

const hopResolver = (hops: MultisigHop[]) =>
	directoryResolver(hops.map((h) => ({ directory: h.directory, keyid: h.keyid, pub: b64urlToBytes(h.pubkey_b64url) })));

const fixedClock = (nowUnix: number) => () => nowUnix;

// The header bag a vector describes: the base five, minus what the request does not
// carry, plus any extra field line spelled in another case. Extras land AFTER the base
// ones so the join order matches the order the oracle added them.
function headersFor(v: MultisigChainVector): MultisigVerifyHeaders {
	const headers: MultisigVerifyHeaders = {
		"content-digest": v.content_digest,
		"signature-input": v.signature_input,
		signature: v.signature,
		authorization: v.authorization,
		"signature-agent": v.signature_agent,
	};
	const bag = headers as Record<string, string | undefined>;
	for (const name of v.omit_headers ?? []) delete bag[name.toLowerCase()];
	for (const [name, value] of Object.entries(v.extra_headers ?? {})) bag[name] = value;
	return headers;
}

function verify(v: MultisigChainVector, headers: MultisigVerifyHeaders = headersFor(v)) {
	return verifyMultisigRequestServer({
		method: v.method,
		url: v.url,
		body: hexToBytes(v.body_hex),
		headers,
		resolve: hopResolver(v.hops),
		now: fixedClock(Math.floor((v.created + v.expires) / 2)),
		maxSignatures: v.max_signatures,
	});
}

// signHops replays a vector's hops in order: the first through signRequest, every later
// one through appendSignature with the hop's coverPrevious, each with its own directory.
async function signHops(v: MultisigChainVector, authorization: string): Promise<SignedRequest> {
	const body = hexToBytes(v.body_hex);
	let signed: SignedRequest | undefined;
	for (const hop of v.hops) {
		const opts = {
			method: v.method,
			url: v.url,
			body,
			authorization,
			signatureAgent: hop.directory,
			keyid: hop.keyid,
			created: v.created,
			expires: v.expires,
			nonce: hop.nonce ?? "",
			coverPrevious: hop.cover_previous ?? false,
		};
		const priv = await importSigningKey(hop.seed_hex);
		signed =
			signed === undefined
				? await signRequest(priv, opts)
				: await appendSignature(
						priv,
						{
							signatureInput: signed.signatureInput,
							signature: signed.signature,
							signatureAgent: signed.signatureAgent,
						},
						opts,
					);
	}
	if (signed === undefined) throw new Error(`${v.name} has no hops`);
	return signed;
}

describe("sdk/ts multi-signature append+verify mirrors the Go oracle", () => {
	const doc = multisigVectors as { vectors: MultisigChainVector[] };
	const byName = (n: string): MultisigChainVector => {
		const v = doc.vectors.find((x) => x.name === n);
		if (!v) throw new Error(`missing vector ${n}`);
		return v;
	};

	it("vector set covers the independent, covering, budget, coverage and directory cases", () => {
		const names = new Set(doc.vectors.map((v) => v.name));
		for (const want of [
			"positive_independent_two",
			"positive_covering_two",
			"positive_covering_three",
			"positive_covering_two_nonce",
			"hop_budget_three_independent_over_two",
			"hop_budget_three_covering_over_two",
			"broken_coverage_reordered",
			"broken_coverage_stripped",
			"broken_coverage_without_signature_input",
			"broken_coverage_missing_component",
			"wrong_directory_member",
			"legacy_form_on_two_signatures",
			"tampered_first_covered",
			"repointed_second_member",
			"absent_authorization_over_budget",
			"absent_signature_agent_reordered",
			"duplicate_bound_two",
			"canonical_case_two",
		]) {
			expect(names.has(want), want).toBe(true);
		}
	});

	// The reject and accept cases, DERIVED from the corpus rather than hand-listed, so
	// every row the emitter adds is driven the day it is committed.
	for (const v of doc.vectors.filter((x) => x.expected_verified)) {
		it(`${v.name} verifies and returns the Go-emitted keyids and directories`, async () => {
			const verdict = await verify(v);
			expect(verdict.valid, `${v.name}: ${verdict.reason}`).toBe(true);
			expect(verdict.keyids).toEqual(v.expected_keyids);
			expect(verdict.signatureAgents).toEqual(v.expected_directories);
		});
	}

	for (const v of doc.vectors.filter((x) => !x.expected_verified)) {
		it(`${v.name} rejects with the Go-emitted reason`, async () => {
			const verdict = await verify(v);
			expect(verdict.valid).toBe(false);
			expect(verdict.reason).toBe(v.expected_reason as MultisigRejectReason);
		});
	}

	// BYTE-IDENTITY: the vectors built only by sign and append, re-signed live under the
	// Go hop seeds, reproduce Signature-Input, Signature and Signature-Agent byte for
	// byte. A positive vector's authorization is the value the verifier reads (the join
	// of its field lines); a negative one was signed before its header was altered. A
	// reordered vector had its members swapped after signing, so it is not replayed.
	const RESIGNED = /^(positive_|hop_budget_|absent_|duplicate_|canonical_)/;
	for (const v of doc.vectors.filter((x) => RESIGNED.test(x.name) && !x.name.endsWith("_reordered"))) {
		it(`${v.name}: signRequest + appendSignature reproduce the Go headers`, async () => {
			const authorization = v.expected_verified
				? (readHeader(headersFor(v), "authorization") ?? "")
				: v.authorization;
			const signed = await signHops(v, authorization);
			expect(signed.signatureInput).toBe(v.signature_input);
			expect(signed.signature).toBe(v.signature);
			expect(signed.signatureAgent).toBe(v.signature_agent);
			expect(signed.contentDigest).toBe(v.content_digest);
		});
	}

	it("appendSignature to an unsigned request equals signRequest (N=1)", async () => {
		const v = byName("positive_independent_two");
		const h = v.hops[0] as MultisigHop;
		const opts = {
			method: v.method,
			url: v.url,
			body: hexToBytes(v.body_hex),
			authorization: v.authorization,
			signatureAgent: h.directory,
			keyid: h.keyid,
			created: v.created,
			expires: v.expires,
		};
		const priv = await importSigningKey(h.seed_hex);
		const signed = await signRequest(priv, opts);
		const appended = await appendSignature(priv, { signatureInput: "", signature: "" }, { ...opts, coverPrevious: true });
		expect(appended).toEqual(signed);
	});

	it("an append without coverPrevious covers no earlier signature", async () => {
		const signed = await signHops(byName("positive_independent_two"), "Bearer chain-token");
		expect(signed.signatureInput).not.toContain('"signature";key=');
		expect(signed.signatureAgent).toBe('sig1="https://agent.example", sig2="https://broker.example"');
	});

	it("tampering with the first signature breaks it and every signature covering it", async () => {
		const v = byName("positive_covering_three");
		const signature = v.signature.replace(/^sig1=:./, (m) => (m.endsWith("A") ? `${m.slice(0, -1)}B` : `${m.slice(0, -1)}A`));
		const verdict = await verify(v, { ...headersFor(v), signature });
		expect(verdict).toEqual({ valid: false, reason: "signature" });
	});

	describe("appendSignature refuses a label or a Signature-Agent it cannot extend", () => {
		const v = byName("positive_independent_two");
		const h = v.hops[1] as MultisigHop;
		const opts = {
			method: v.method,
			url: v.url,
			body: hexToBytes(v.body_hex),
			authorization: v.authorization,
			signatureAgent: h.directory,
			keyid: h.keyid,
			created: v.created,
			expires: v.expires,
		};

		it("takes the first sigN no signature and no Signature-Agent member uses", async () => {
			const prior = {
				signatureInput: v.signature_input.split(", sig2=")[0] as string,
				signature: v.signature.split(", sig2=")[0] as string,
				signatureAgent: 'sig1="https://agent.example", sig2="https://other.example"',
			};
			const appended = await appendSignature(await importSigningKey(h.seed_hex), prior, opts);
			expect(appended.signatureInput).toContain(", sig3=(");
			expect(appended.signatureAgent).toBe(`${prior.signatureAgent}, sig3="https://broker.example"`);
			await expect(
				appendSignature(await importSigningKey(h.seed_hex), prior, { ...opts, label: "sig1" }),
			).rejects.toMatchObject({ reason: "signature_label" });
		});

		it("refuses to append to the legacy String form, which cannot take a second member", async () => {
			const prior = {
				signatureInput: v.signature_input.split(", sig2=")[0] as string,
				signature: v.signature.split(", sig2=")[0] as string,
				signatureAgent: '"https://agent.example"',
			};
			const err = await appendSignature(await importSigningKey(h.seed_hex), prior, opts).catch((e: unknown) => e);
			expect(err).toBeInstanceOf(WebBotAuthError);
			expect((err as WebBotAuthError).reason).toBe("signature_agent_form");
		});
	});

	// Entitlement coverage is enforced on EVERY signature: a chain whose covered sets
	// never commit to x-entitlement-token, carrying that header, is refused and answered
	// with the Accept-Signature that asks for it.
	it("a chain carrying an uncovered X-Entitlement-Token header is rejected (signature)", async () => {
		const v = byName("positive_independent_two");
		expect((await verify(v)).valid).toBe(true);
		const verdict = await verify(v, { ...headersFor(v), "x-entitlement-token": "jwt:demo-unsigned-entitlement-token" });
		expect(verdict.valid).toBe(false);
		expect(verdict.reason).toBe("signature");
		expect(verdict.acceptSignature).toContain('"x-entitlement-token")');
	});

	it("a request carrying no signature is answered with Accept-Signature", async () => {
		const v = byName("positive_independent_two");
		const headers = headersFor(v);
		delete (headers as Record<string, string | undefined>)["signature-input"];
		const verdict = await verify(v, headers);
		expect(verdict.reason).toBe("signature");
		expect(verdict.acceptSignature).toMatch(/^sig1=\(/);
	});

	// The MaxSignatureAge clamp, enforced on EVERY signature exactly like the single-sig
	// path. The bound is inclusive; 0/undefined is unbounded.
	describe("per-signature MaxSignatureAge clamp on the multisig path", () => {
		const v = byName("positive_independent_two");
		const window = v.expires - v.created;

		async function verifyWithMaxAge(maxSignatureAge: number | undefined): Promise<MultisigRejectReason | "valid"> {
			const verdict = await verifyMultisigRequestServer({
				method: v.method,
				url: v.url,
				body: hexToBytes(v.body_hex),
				headers: headersFor(v),
				resolve: hopResolver(v.hops),
				now: fixedClock(Math.floor((v.created + v.expires) / 2)),
				...(maxSignatureAge !== undefined ? { maxSignatureAge } : {}),
			});
			return verdict.valid ? "valid" : (verdict.reason as MultisigRejectReason);
		}

		it("unbounded (undefined) accepts the chain's declared window", async () => {
			expect(await verifyWithMaxAge(undefined)).toBe("valid");
		});
		it("maxAge exactly equal to the window is accepted (inclusive bound)", async () => {
			expect(await verifyWithMaxAge(window)).toBe("valid");
		});
		it("maxAge below the window rejects the chain (signature)", async () => {
			expect(await verifyWithMaxAge(window - 1)).toBe("signature");
		});
	});
});
