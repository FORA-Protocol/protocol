// The Web Bot Auth profile pieces the signers and verifiers share, ported from
// sdk/go/helpers/wba_profile_test.go: what counts as an https origin, what no profile
// signature may carry, the Accept-Signature value, and which refusals a verifier
// answers with it.

import { describe, expect, it } from "vitest";
import {
	acceptSignature,
	buildSignatureBase,
	checkHttpsOrigin,
	MAX_SIGNATURE_LIFETIME,
	requestComponentValue,
	signatureInputInner,
	signRequest,
	WebBotAuthError,
} from "../core/sign-request.ts";
import { verifyMultisigRequestServer } from "../core/verify-multisig-request.ts";
import { verifyRequestServer, type VerifyVerdict } from "../core/verify-request.ts";
import { type CoveredComponent, keyed, plain } from "../core/wba.ts";
import { encodeBase64Url, stdBase64 } from "../src/base64url.ts";
import { POP_ACCEPT_SIGNATURE, verifyAgentBinding } from "../src/pop.ts";
import { thumbprint } from "../src/thumbprint.ts";
import { AGENT_DIRECTORY, b64urlToBytes, importSigningKey } from "./wba-fixtures.ts";

const SEED = "55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374";
// The public half of SEED, as the sign-request vectors record it.
const PUB = "rGv1a5oEriM-jaKs3KzrFzzn4Hb180dA4XuZ0bAs_gk";
const URL_ = "https://exchange.example/fora.v1.ExchangeService/DiscoverResources";
const CREATED = 1_700_000_000;
const BODY = new TextEncoder().encode("x") as Uint8Array<ArrayBuffer>;
const FORA_RPC = ["@method", "@target-uri", "content-digest", "authorization"].map(plain);

describe("checkHttpsOrigin", () => {
	for (const ok of [
		"https://agent.example",
		"https://agent.example:8443",
		"https://127.0.0.1",
		"https://[::1]:8443",
		"https://xn--bcher-kva.example",
		"https://a_b.example",
	]) {
		it(`accepts ${ok}`, () => {
			expect(() => checkHttpsOrigin(ok)).not.toThrow();
		});
	}
	for (const bad of [
		"",
		"agent.example",
		"http://agent.example",
		"HTTPS://agent.example",
		"https://Agent.example",
		"https://agent.example/",
		"https://agent.example/keys",
		"https://agent.example?x=1",
		"https://agent.example#f",
		"https://user@agent.example",
		"https://agent.example:443",
		"https://agent.example:0",
		"https://agent.example:99999",
		"https://agent.example:",
		"https://bücher.example",
		"https://",
		"https://a..example",
		"https://agent.example%2F",
		'https://agent.example"',
		"https://[::1",
		"https://agent.example:08443",
	]) {
		it(`refuses ${JSON.stringify(bad)}`, () => {
			let err: unknown;
			try {
				checkHttpsOrigin(bad);
			} catch (e) {
				err = e;
			}
			expect(err).toBeInstanceOf(WebBotAuthError);
			expect((err as WebBotAuthError).reason).toBe("signature_agent_not_origin");
		});
	}
});

describe("signRequest refuses what no profile signature carries", () => {
	const ok = {
		method: "POST",
		url: URL_,
		body: BODY,
		authorization: "",
		signatureAgent: AGENT_DIRECTORY,
		keyid: "agent.v1",
		created: CREATED,
		expires: CREATED + MAX_SIGNATURE_LIFETIME,
	};
	const cases: Array<[string, Partial<typeof ok> & { label?: string; nonce?: string }, string]> = [
		["no Signature-Agent", { signatureAgent: "" }, "signature_agent_required"],
		["plaintext origin", { signatureAgent: "http://agent.example" }, "signature_agent_not_origin"],
		["bare host", { signatureAgent: "agent.example" }, "signature_agent_not_origin"],
		["origin with a path", { signatureAgent: "https://agent.example/keys" }, "signature_agent_not_origin"],
		["six-minute window", { expires: CREATED + 360 }, "signature_lifetime"],
		["empty window", { expires: CREATED }, "signature_lifetime"],
		["no created", { created: 0 }, "signature_lifetime"],
		["label not a key", { label: "Sig1" }, "signature_label"],
		["nonce outside base64url", { nonce: 'a"b' }, "invalid_nonce"],
	];
	for (const [name, edit, reason] of cases) {
		it(name, async () => {
			await expect(signRequest(await importSigningKey(SEED), { ...ok, ...edit })).rejects.toMatchObject({ reason });
		});
	}

	it("signs a window of exactly MAX_SIGNATURE_LIFETIME under an explicit label", async () => {
		const signed = await signRequest(await importSigningKey(SEED), { ...ok, label: "agent" });
		expect(signed.signatureAgent).toBe(`agent="${AGENT_DIRECTORY}"`);
		expect(signed.signatureInput.startsWith('agent=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="agent")')).toBe(true);
	});
});

describe("acceptSignature", () => {
	it("is the value the authentication page shows", () => {
		expect(acceptSignature(false)).toBe(
			'sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"',
		);
		expect(acceptSignature(true)).toContain('"signature-agent";key="sig1" "x-entitlement-token")');
	});
});

// rawSigned signs a request whose covered set, label, tag and Signature-Agent the test
// chooses — the forms other Web Bot Auth signers send, or a refused one. The base is
// built by the same builder the SDK verifies with, so a refusal is the profile's, not a
// signature mismatch.
async function rawSigned(opts: {
	agentHeader: string;
	covered?: CoveredComponent[];
	label?: string;
	tag?: string;
}): Promise<VerifyVerdict> {
	const label = opts.label ?? "sig1";
	const covered = opts.covered ?? [...FORA_RPC, keyed("signature-agent", "sig1")];
	const digest = `sha-256=:${stdBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", BODY)))}:`;
	const headers: Record<string, string> = {
		"content-digest": digest,
		authorization: "",
		"signature-agent": opts.agentHeader,
	};
	const inner = signatureInputInner({
		covered,
		keyid: "agent.v1",
		alg: "ed25519",
		created: CREATED,
		expires: CREATED + 300,
		tag: opts.tag ?? "web-bot-auth",
	});
	let base: string;
	try {
		base = buildSignatureBase(
			covered,
			requestComponentValue({ method: "POST", url: URL_, header: (n) => headers[n] }),
			inner,
		);
	} catch {
		base = "unresolvable";
	}
	const raw = await crypto.subtle.sign("Ed25519", await importSigningKey(SEED), new TextEncoder().encode(base));
	headers["signature-input"] = `${label}=${inner}`;
	headers.signature = `${label}=:${stdBase64(new Uint8Array(raw))}:`;
	const pub = b64urlToBytes(PUB);
	return verifyRequestServer({
		method: "POST",
		url: URL_,
		body: BODY,
		headers,
		resolve: { resolve: (keyid, dir) => (keyid === "agent.v1" && dir === AGENT_DIRECTORY ? pub : undefined) },
		now: () => CREATED + 100,
	});
}

describe("the verifier accepts what WG-00 permits and refuses what the profile does not", () => {
	const member = `sig1="${AGENT_DIRECTORY}"`;
	const accepted: Array<[string, Parameters<typeof rawSigned>[0]]> = [
		["the SDK's own form", { agentHeader: member }],
		["legacy String form on a single signature", { agentHeader: `"${AGENT_DIRECTORY}"`, covered: [...FORA_RPC, plain("signature-agent")] }],
		["member key different from the label", { agentHeader: `agent="${AGENT_DIRECTORY}"`, covered: [...FORA_RPC, keyed("signature-agent", "agent")] }],
		["type=directory as a Token", { agentHeader: `${member};type=directory` }],
		["other members beside the signer's", { agentHeader: `x="https://x.example", ${member}` }],
	];
	for (const [name, opts] of accepted) {
		it(`accepts ${name}`, async () => {
			expect(await rawSigned(opts)).toEqual({ valid: true, keyid: "agent.v1", signatureAgent: AGENT_DIRECTORY });
		});
	}

	const accept = acceptSignature(false);
	const refused: Array<[string, Parameters<typeof rawSigned>[0], string | undefined]> = [
		["another tag", { agentHeader: member, tag: "fora" }, accept],
		["the dictionary covered as plain signature-agent", { agentHeader: member, covered: [...FORA_RPC, plain("signature-agent")] }, accept],
		["a member that is a token", { agentHeader: "sig1=agent" }, accept],
		[
			"two members covered, neither keyed to the label",
			{
				agentHeader: `a="${AGENT_DIRECTORY}", b="${AGENT_DIRECTORY}"`,
				covered: [...FORA_RPC, keyed("signature-agent", "a"), keyed("signature-agent", "b")],
			},
			accept,
		],
		["a member with a parameter other than key", { agentHeader: member, covered: [...FORA_RPC, { name: "signature-agent", params: [{ key: "bs", value: true }] }] }, accept],
		["no Signature-Agent covered", { agentHeader: member, covered: FORA_RPC }, accept],
		["authorization not covered", { agentHeader: member, covered: [...FORA_RPC.slice(0, 3), keyed("signature-agent", "sig1")] }, accept],
		["a plaintext origin", { agentHeader: 'sig1="http://agent.example"' }, accept],
		["an origin with a path", { agentHeader: 'sig1="https://agent.example/keys"' }, accept],
	];
	for (const [name, opts, want] of refused) {
		it(`refuses ${name}${want ? " and answers with Accept-Signature" : ", with no Accept-Signature"}`, async () => {
			const verdict = await rawSigned(opts);
			expect(verdict.valid).toBe(false);
			expect(verdict.reason).toBe("signature");
			expect(verdict.acceptSignature).toBe(want);
		});
	}
});

// A signature the test signs over exactly the components it chooses, through the SDK's
// own base builder, so the only refusal left is the profile rule under test.
async function rawProof(
	kp: CryptoKeyPair,
	url: string,
	covered: CoveredComponent[],
	headers: Record<string, string>,
	label = "sig1",
): Promise<{ input: string; signature: string }> {
	const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	const inner = signatureInputInner({
		covered,
		keyid: await thumbprint(raw),
		alg: "ed25519",
		created: CREATED,
		expires: CREATED + 300,
		tag: "web-bot-auth",
	});
	// A covered set the base builder cannot resolve, such as a parameter on @method, is
	// signed over a placeholder: the verifier must refuse it before the signature check.
	let base: string;
	try {
		base = buildSignatureBase(covered, requestComponentValue({ method: "GET", url, header: (n) => headers[n] }), inner);
	} catch {
		base = "unresolvable";
	}
	const sig = await crypto.subtle.sign("Ed25519", kp.privateKey, new TextEncoder().encode(base));
	return { input: `${label}=${inner}`, signature: `${label}=:${stdBase64(new Uint8Array(sig))}:` };
}

// proofFor signs a delivery proof over `covered` with a fresh key, then hands the
// request headers to `alter` (which may change or drop any of them) and verifies.
async function proofFor(
	covered: CoveredComponent[],
	alter: (h: Headers) => void = () => {},
): Promise<Awaited<ReturnType<typeof verifyAgentBinding>>> {
	const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
	const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
	const agentId = await thumbprint(raw);
	const url = `https://cdn.example/doc?agent_id=${agentId}`;
	const signed: Record<string, string> = {
		"signature-agent": `sig1="${AGENT_DIRECTORY}"`,
		"x-extra": "1",
		"x-fora-agent-key": encodeBase64Url(raw),
	};
	const proof = await rawProof(kp, url, covered, signed);
	const headers = new Headers({ ...signed, "signature-input": proof.input, signature: proof.signature });
	alter(headers);
	return verifyAgentBinding({ url, method: "GET", headers, agentId, now: () => (CREATED + 10) * 1000 });
}

describe("verifyAgentBinding accepts a covered set that includes the profile's", () => {
	const member = keyed("signature-agent", "sig1");
	const supersets: Array<[string, CoveredComponent[]]> = [
		["the profile's set and one more header", [plain("@method"), plain("@target-uri"), member, plain("x-extra")]],
		["@authority first, then the profile's set", [plain("@authority"), plain("@method"), plain("@target-uri"), member]],
		["the profile's set in another order with the presented-key header", [member, plain("x-fora-agent-key"), plain("@target-uri"), plain("@method")]],
	];
	for (const [name, covered] of supersets) {
		it(`accepts ${name}`, async () => {
			expect(await proofFor(covered)).toEqual({ ok: true, signatureAgent: AGENT_DIRECTORY });
		});
	}

	const missing: Array<[string, CoveredComponent[]]> = [
		["no @target-uri", [plain("@method"), member, plain("x-extra")]],
		["no @method", [plain("@authority"), plain("@target-uri"), member]],
		["no Signature-Agent member", [plain("@method"), plain("@target-uri"), plain("x-extra")]],
		["@method only with a parameter", [{ name: "@method", params: [{ key: "req", value: true }] }, plain("@target-uri"), member]],
	];
	for (const [name, covered] of missing) {
		it(`refuses ${name} as bad_covered_components and answers with Accept-Signature`, async () => {
			expect(await proofFor(covered)).toEqual({
				ok: false,
				reason: "bad_covered_components",
				acceptSignature: POP_ACCEPT_SIGNATURE,
			});
		});
	}

	it("refuses a covered header the request no longer carries as bad_covered_components, with Accept-Signature", async () => {
		const covered = [plain("@method"), plain("@target-uri"), member, plain("x-extra")];
		expect(await proofFor(covered, (h) => h.delete("x-extra"))).toEqual({
			ok: false,
			reason: "bad_covered_components",
			acceptSignature: POP_ACCEPT_SIGNATURE,
		});
	});

	it("refuses a proof covering x-missing-header, which the request never carried, as bad_covered_components with Accept-Signature", async () => {
		const covered = [plain("@method"), plain("@target-uri"), member, plain("x-missing-header")];
		expect(await proofFor(covered)).toEqual({
			ok: false,
			reason: "bad_covered_components",
			acceptSignature: POP_ACCEPT_SIGNATURE,
		});
	});

	it("refuses a covered Signature-Agent the request no longer carries as bad_covered_components", async () => {
		const result = await proofFor([plain("@method"), plain("@target-uri"), member], (h) => h.delete("signature-agent"));
		expect(result).toEqual({ ok: false, reason: "bad_covered_components", acceptSignature: POP_ACCEPT_SIGNATURE });
	});

	it("refuses a superset whose extra header changed after signing as pop_sig_invalid, with no Accept-Signature", async () => {
		const covered = [plain("@method"), plain("@target-uri"), member, plain("x-extra")];
		expect(await proofFor(covered, (h) => h.set("x-extra", "2"))).toEqual({ ok: false, reason: "pop_sig_invalid" });
	});

	it("answers an unsigned fetch, or one missing either signature header, with missing_sig and Accept-Signature", async () => {
		const covered = [plain("@method"), plain("@target-uri"), member];
		const want = { ok: false, reason: "missing_sig", acceptSignature: POP_ACCEPT_SIGNATURE };
		expect(await proofFor(covered, (h) => h.delete("signature-input"))).toEqual(want);
		expect(await proofFor(covered, (h) => h.delete("signature"))).toEqual(want);
	});

	it("refuses a Signature-Input that does not parse as malformed_sig_input, with no Accept-Signature", async () => {
		const result = await proofFor([plain("@method"), plain("@target-uri"), member], (h) => h.set("signature-input", "sig1=("));
		expect(result).toEqual({ ok: false, reason: "malformed_sig_input" });
	});

	it("refuses a member that is not an https origin as bad_signature_agent and answers with Accept-Signature", async () => {
		const covered = [plain("@method"), plain("@target-uri"), member];
		const result = await proofFor(covered, (h) => h.set("signature-agent", 'sig1="http://agent.example"'));
		expect(result).toEqual({ ok: false, reason: "bad_signature_agent", acceptSignature: POP_ACCEPT_SIGNATURE });
	});
});

describe("the legacy String form is accepted on one signature only", () => {
	it("refuses two signatures covering the legacy form as plain signature-agent, and asks for the dictionary", async () => {
		const covered = [...FORA_RPC, plain("signature-agent")];
		const legacy = `"${AGENT_DIRECTORY}"`;
		const digest = `sha-256=:${stdBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", BODY)))}:`;
		const fields: Record<string, string> = { "content-digest": digest, authorization: "", "signature-agent": legacy };
		const priv = await importSigningKey(SEED);
		const sign = async (label: string) => {
			const inner = signatureInputInner({ covered, keyid: "agent.v1", alg: "ed25519", created: CREATED, expires: CREATED + 300, tag: "web-bot-auth" });
			const base = buildSignatureBase(covered, requestComponentValue({ method: "POST", url: URL_, header: (n) => fields[n] }), inner);
			const sig = await crypto.subtle.sign("Ed25519", priv, new TextEncoder().encode(base));
			return { input: `${label}=${inner}`, signature: `${label}=:${stdBase64(new Uint8Array(sig))}:` };
		};
		const [a, b] = [await sign("sig1"), await sign("sig2")];
		// Both keys are published where the legacy value points, so only the form rule can
		// refuse the request.
		const verdict = await verifyMultisigRequestServer({
			method: "POST",
			url: URL_,
			body: BODY,
			headers: { ...fields, "signature-input": `${a.input}, ${b.input}`, signature: `${a.signature}, ${b.signature}` },
			resolve: { resolve: (keyid, dir) => (keyid === "agent.v1" && dir === AGENT_DIRECTORY ? b64urlToBytes(PUB) : undefined) },
			now: () => CREATED + 100,
		});
		expect(verdict).toEqual({ valid: false, reason: "signature", acceptSignature: acceptSignature(false) });
	});
});
