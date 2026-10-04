// sdk/ts single-signature SERVER-VERIFY parity against the shared Go oracle, under the
// Web Bot Auth profile.
//
// core/verify-request.ts mirrors sdk/go/connectserver semantics reason-for-reason: the
// profile (tag, Signature-Agent form, the signature's own member), the FORA RPC covered
// set, digest and window enforcement, replay detection via an INJECTED store, keys via
// an INJECTED resolver keyed by keyid and directory, time via an INJECTED clock, and the
// reject taxonomy exposed as a RETURNED verdict (never thrown).
//
// Oracle:
//   - every sign-request vector (the bytes the TS/Python/Go signers produce) verifies,
//     and the verdict reports the directory the signature's member names;
//   - every verify-request-accept vector — the forms other Web Bot Auth signers send,
//     which the SDK never emits — verifies and reports expected_signature_agent;
//   - every verify-request-neg vector is REJECTED with the reason the Go taxonomy
//     assigns, and answered with exactly the expected_accept_signature (none when the
//     vector omits it).

import { describe, expect, it } from "vitest";
import { signRequest } from "../core/sign-request.ts";
import {
	type RejectReason,
	type ReplayStore,
	type RequestKeyResolver,
	type VerifyRequestHeaders,
	verifyRequestServer,
} from "../core/verify-request.ts";
import signRequestVectors from "../../go/helpers/testdata/sign-request-vectors.json";
import acceptVerifyVectors from "../../go/helpers/testdata/verify-request-accept-vectors.json";
import negVerifyVectors from "../../go/helpers/testdata/verify-request-neg-vectors.json";
import {
	AGENT_DIRECTORY,
	b64urlToBytes,
	directoryResolver,
	hexToBytes,
	importSigningKey,
} from "./wba-fixtures.ts";

type SignRequestVector = {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	authorization: string;
	signature_agent: string;
	keyid: string;
	created: number;
	expires: number;
	pubkey_b64url: string;
	content_digest: string;
	signature_input: string;
	signature: string;
	emitted_headers: Record<string, string[]>;
};

// A Go-emitted verify vector: a fully-formed request, the key the resolver serves for
// resolver_keyid, the pinned clock, and the verdict. `signature_agent` is the
// Signature-Agent HEADER value.
type VerifyVector = {
	name: string;
	method: string;
	url: string;
	body_hex: string;
	authorization: string;
	signature_agent: string;
	content_digest: string;
	signature_input: string;
	signature: string;
	keyid: string;
	resolver_keyid?: string;
	resolver_pubkey_b64url?: string;
	now: number;
	expected_reason: RejectReason | "";
	expected_accept_signature?: string;
	expected_signature_agent?: string;
	// The same request is presented twice; the SECOND presentation must be "replay".
	replay?: boolean;
	// An X-Entitlement-Token value the signature does not cover.
	entitlement?: string;
	// Names the request does NOT carry — deleted after the base ones are set, so the face
	// sees a covered name with no field line rather than an empty one.
	omit_headers?: string[];
	// Field lines ADDED beside the base ones, spelled in a different case so an object
	// holds both; their values join before the base is rebuilt.
	extra_headers?: Record<string, string>;
};

// A keyid-keyed resolver that records every call — the injected-boundary probe for the
// vectors that carry no directory of their own.
function keyidResolver(keys: Record<string, Uint8Array<ArrayBuffer>>): RequestKeyResolver & { calls: string[] } {
	const calls: string[] = [];
	return {
		calls,
		resolve(keyid) {
			calls.push(keyid);
			return keys[keyid];
		},
	};
}

function memoryReplayStore(): ReplayStore {
	const seen = new Set<string>();
	return {
		async seenNonce(nonce) {
			return seen.has(nonce);
		},
		async seenOrAdd(nonce) {
			if (seen.has(nonce)) return true;
			seen.add(nonce);
			return false;
		},
	};
}

const fixedClock = (nowUnix: number) => () => nowUnix;

function headersFor(v: VerifyVector): VerifyRequestHeaders {
	const headers: VerifyRequestHeaders = {
		"content-digest": v.content_digest,
		"signature-input": v.signature_input,
		signature: v.signature,
		authorization: v.authorization,
		"signature-agent": v.signature_agent,
	};
	if (v.entitlement) headers["x-entitlement-token"] = v.entitlement;
	const bag = headers as Record<string, string | undefined>;
	for (const name of v.omit_headers ?? []) delete bag[name.toLowerCase()];
	// AFTER the base ones, so the join order matches the order the oracle added them.
	for (const [name, value] of Object.entries(v.extra_headers ?? {})) bag[name] = value;
	return headers;
}

function requestFor(v: VerifyVector, resolve: RequestKeyResolver, replayStore: ReplayStore) {
	return {
		method: v.method,
		url: v.url,
		body: hexToBytes(v.body_hex),
		headers: headersFor(v),
		resolve,
		replayStore,
		now: fixedClock(v.now),
	};
}

function resolverFor(v: VerifyVector): RequestKeyResolver & { calls: string[] } {
	const keys: Record<string, Uint8Array<ArrayBuffer>> = {};
	if (v.resolver_pubkey_b64url) keys[v.resolver_keyid ?? v.keyid] = b64urlToBytes(v.resolver_pubkey_b64url);
	return keyidResolver(keys);
}

const LIVE_SEED = "55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071727374";
const LIVE_PUB = "rGv1a5oEriM-jaKs3KzrFzzn4Hb180dA4XuZ0bAs_gk";
const LIVE_URL = "https://broker.example/fora.v1.BrokerService/Fetch";

describe("sdk/ts single-sig server-verify mirrors the Go connectserver oracle", () => {
	const signDoc = signRequestVectors as { vectors: SignRequestVector[] };
	const acceptDoc = acceptVerifyVectors as { vectors: VerifyVector[] };
	const negDoc = negVerifyVectors as { vectors: VerifyVector[] };

	it("the negative corpus covers every profile and covered-set refusal", () => {
		const names = new Set(negDoc.vectors.map((v) => v.name));
		for (const want of [
			"neg_bad_sig",
			"neg_replay",
			"neg_expired",
			"neg_wrong_key",
			"neg_tampered_authorization",
			"neg_entitlement_uncovered",
			"neg_absent_authorization",
			"neg_absent_signature_agent",
			"neg_duplicate_authorization",
			"neg_shadowed_entitlement",
			"neg_missing_tag",
			"neg_wrong_tag",
			"neg_bare_signature_agent",
			"neg_signature_agent_member_absent",
			"neg_signature_agent_type_not_directory",
			"neg_signature_agent_not_https_origin",
			"neg_signature_agent_not_an_origin",
			"neg_missing_fora_component",
			"neg_unsigned",
			"neg_repointed_signature_agent",
		]) {
			expect(names.has(want), want).toBe(true);
		}
	});

	// POSITIVE: every sign-request vector verifies when its key is published in the
	// directory its member names, and the verdict reports that directory.
	for (const v of signDoc.vectors) {
		it(`${v.name}: oracle-signed request verifies and reports its directory`, async () => {
			const resolver = directoryResolver([
				{ directory: v.signature_agent, keyid: v.keyid, pub: b64urlToBytes(v.pubkey_b64url) },
			]);
			const verdict = await verifyRequestServer({
				method: v.method,
				url: v.url,
				body: hexToBytes(v.body_hex),
				headers: {
					"content-digest": v.content_digest,
					"signature-input": v.signature_input,
					signature: v.signature,
					authorization: v.authorization,
					"signature-agent": v.emitted_headers["signature-agent"]?.[0] ?? "",
				},
				resolve: resolver,
				replayStore: memoryReplayStore(),
				now: fixedClock(Math.floor((v.created + v.expires) / 2)),
			});
			expect(verdict).toEqual({ valid: true, keyid: v.keyid, signatureAgent: v.signature_agent });
			expect(resolver.calls).toEqual([[v.signature_agent, v.keyid]]);
		});
	}

	// POSITIVE: the forms WG-00 permits that the SDK never emits.
	for (const v of acceptDoc.vectors) {
		it(`${v.name}: verifies and reports ${v.expected_signature_agent}`, async () => {
			const resolver = directoryResolver([
				{
					directory: v.expected_signature_agent ?? "",
					keyid: v.resolver_keyid ?? v.keyid,
					pub: b64urlToBytes(v.resolver_pubkey_b64url ?? ""),
				},
			]);
			const verdict = await verifyRequestServer(requestFor(v, resolver, memoryReplayStore()));
			expect(verdict.valid, verdict.reason).toBe(true);
			expect(verdict.signatureAgent).toBe(v.expected_signature_agent);
			expect(verdict.acceptSignature).toBeUndefined();
		});
	}

	// NEGATIVE: each Go-emitted refusal rejects with the taxonomy reason and exactly the
	// Accept-Signature the oracle answers with.
	for (const v of negDoc.vectors) {
		it(`${v.name}: rejected with reason "${v.expected_reason}" and its Accept-Signature`, async () => {
			const req = requestFor(v, resolverFor(v), memoryReplayStore());
			if (v.replay) {
				// The first presentation is accepted and records the nonce; the SECOND is
				// the one that must be rejected as "replay".
				expect((await verifyRequestServer(req)).valid).toBe(true);
			}
			const verdict = await verifyRequestServer(req);
			expect(verdict.valid).toBe(false);
			expect(verdict.reason).toBe(v.expected_reason);
			expect(verdict.acceptSignature).toBe(v.expected_accept_signature);
		});
	}

	async function liveSigned(created: number, expires: number) {
		const body = new TextEncoder().encode('{"uri":"https://cdn.example/live"}') as Uint8Array<ArrayBuffer>;
		const signed = await signRequest(await importSigningKey(LIVE_SEED), {
			method: "POST",
			url: LIVE_URL,
			body,
			authorization: "Bearer live-token",
			signatureAgent: AGENT_DIRECTORY,
			keyid: "mcp.v1",
			created,
			expires,
		});
		const headers: VerifyRequestHeaders = {
			"content-digest": signed.contentDigest,
			"signature-input": signed.signatureInput,
			signature: signed.signature,
			authorization: signed.authorization,
			"signature-agent": signed.signatureAgent,
		};
		return { body, headers };
	}

	it("a request signed live by core/sign-request.ts round-trips through the server face", async () => {
		const created = 1_700_000_000;
		const { body, headers } = await liveSigned(created, created + 300);
		const resolver = directoryResolver([{ directory: AGENT_DIRECTORY, keyid: "mcp.v1", pub: b64urlToBytes(LIVE_PUB) }]);
		const verdict = await verifyRequestServer({
			method: "POST",
			url: LIVE_URL,
			body,
			headers,
			resolve: resolver,
			replayStore: memoryReplayStore(),
			now: fixedClock(created + 100),
		});
		expect(verdict).toEqual({ valid: true, keyid: "mcp.v1", signatureAgent: AGENT_DIRECTORY });
	});

	it("a key published only in another directory is not found: the resolver is asked for the member's directory", async () => {
		const created = 1_700_000_000;
		const { body, headers } = await liveSigned(created, created + 300);
		const resolver = directoryResolver([
			{ directory: "https://other.example", keyid: "mcp.v1", pub: b64urlToBytes(LIVE_PUB) },
		]);
		const verdict = await verifyRequestServer({
			method: "POST",
			url: LIVE_URL,
			body,
			headers,
			resolve: resolver,
			now: fixedClock(created + 100),
		});
		expect(verdict).toEqual({ valid: false, reason: "signature" });
		expect(resolver.calls).toEqual([[AGENT_DIRECTORY, "mcp.v1"]]);
	});

	// The MaxSignatureAge lifetime clamp (mirrors Go enforceCreatedExpires with
	// opts.MaxSignatureAge): a live-signed 300-second window at several clamp settings.
	describe("single-sig MaxSignatureAge clamp", () => {
		const created = 1_700_000_000;
		const window = 300;

		async function verifyWithMaxAge(maxSignatureAge: number | undefined): Promise<RejectReason | "valid"> {
			const { body, headers } = await liveSigned(created, created + window);
			const verdict = await verifyRequestServer({
				method: "POST",
				url: LIVE_URL,
				body,
				headers,
				resolve: directoryResolver([{ directory: AGENT_DIRECTORY, keyid: "mcp.v1", pub: b64urlToBytes(LIVE_PUB) }]),
				replayStore: memoryReplayStore(),
				now: fixedClock(created + 100),
				...(maxSignatureAge !== undefined ? { maxSignatureAge } : {}),
			});
			return verdict.valid ? "valid" : (verdict.reason as RejectReason);
		}

		it("unbounded (undefined) accepts the declared window", async () => {
			expect(await verifyWithMaxAge(undefined)).toBe("valid");
		});
		it("maxAge equal to the window is accepted (inclusive bound)", async () => {
			expect(await verifyWithMaxAge(window)).toBe("valid");
		});
		it("maxAge above the window is accepted", async () => {
			expect(await verifyWithMaxAge(window + 1)).toBe("valid");
		});
		it("maxAge below the window rejects (signature)", async () => {
			expect(await verifyWithMaxAge(window - 1)).toBe("signature");
		});
	});
});
