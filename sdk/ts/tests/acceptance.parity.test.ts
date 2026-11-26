// sdk/ts offer-acceptance sign/verify parity against the shared Go oracle.
//
// The agent role must be buildable in TS (the 3-SDKs decision): an agent signs a
// DETACHED, content-bound acceptance over an accepted Offer, and the Exchange
// verifies it. Go (helpers.SignOfferAcceptance) and Python
// (core.sign_offer_acceptance_jcs) already ship this face; this suite pins the TS
// face byte-identical to the SAME oracle they verify against.
//
// The canonical form is JCS(protojson(AgentAcceptancePayload)) — snake_case,
// omit-unpopulated — so an empty idempotency_key is absent before JCS. Ed25519
// is deterministic (RFC 8032), so signOfferAcceptance MUST reproduce the oracle's
// signature_hex byte-for-byte, not merely verify.
//
// RED until sdk/ts/src/acceptance.ts exists; the implement step adds it.
import { describe, expect, it } from "vitest";
import acceptanceVectors from "../../go/helpers/testdata/acceptance-vectors.json";
import { acceptancePayload, signOfferAcceptance, verifyOfferAcceptance } from "../src/acceptance.ts";
import { hexToBytes, importSigningKey, importVerifyKey } from "./wba-fixtures.ts";

type AcceptanceVector = {
	name: string;
	offer_sig: string;
	requester_id: string;
	requester_domain: string;
	idempotency_key: string;
	canonical_jcs: string; // the exact JCS bytes the signature covers
	signature_hex: string; // Go-oracle Ed25519 signature (deterministic)
	pubkey_b64: string; // std-base64 raw 32-byte Ed25519 public key
	seed_hex: string; // 32-byte Ed25519 seed the oracle signed with
};

describe("sdk/ts offer-acceptance matches the shared Go oracle (byte-identical)", () => {
	const doc = acceptanceVectors as {
		canonicalization: string;
		vectors: AcceptanceVector[];
	};

	it("vector matrix is JCS-canonicalized and non-empty", () => {
		expect(doc.canonicalization).toBe("jcs");
		expect(doc.vectors.length).toBeGreaterThan(0);
	});

	for (const v of doc.vectors) {
		const input = {
			offerSig: v.offer_sig,
			requesterId: v.requester_id,
			requesterDomain: v.requester_domain,
			idempotencyKey: v.idempotency_key,
		};

		it(`${v.name}: canonical payload equals the oracle JCS`, () => {
			const got = new TextDecoder().decode(acceptancePayload(input));
			expect(got).toBe(v.canonical_jcs);
		});

		it(`${v.name}: TS signature is byte-identical to the Go oracle`, async () => {
			const priv = await importSigningKey(v.seed_hex);
			const sigHex = await signOfferAcceptance(input, priv);
			expect(sigHex).toBe(v.signature_hex);
		});

		it(`${v.name}: oracle signature verifies through the TS face`, async () => {
			const pub = await importVerifyKey(v.pubkey_b64);
			expect(await verifyOfferAcceptance(input, v.signature_hex, pub)).toBe(true);
		});

		it(`${v.name}: a tampered idempotency key fails verification`, async () => {
			const pub = await importVerifyKey(v.pubkey_b64);
			const tampered = { ...input, idempotencyKey: `${input.idempotencyKey}-x` };
			expect(await verifyOfferAcceptance(tampered, v.signature_hex, pub)).toBe(false);
		});
	}

	// An acceptance must name its requester: Requester.id and Requester.domain are both
	// REQUIRED. The oracle records one acceptance per requester field left empty, with the
	// bytes and raw signature a signer WITHOUT that check would produce. The canonicalizer
	// and the signer throw, and the verifier answers false although that signature
	// verifies over those bytes.
	const refused = (acceptanceVectors as { refused: (AcceptanceVector & { empty: string })[] }).refused;

	it("refused vectors cover each requester field", () => {
		expect(refused.map((v) => v.empty).sort()).toEqual(["requester_domain", "requester_id"]);
	});

	for (const v of refused) {
		const input = {
			offerSig: v.offer_sig,
			requesterId: v.requester_id,
			requesterDomain: v.requester_domain,
			idempotencyKey: v.idempotency_key,
		};

		it(`${v.name}: an acceptance naming an empty requester is refused`, async () => {
			expect((v as Record<string, string>)[v.empty]).toBe("");
			const pub = await importVerifyKey(v.pubkey_b64);
			// The recorded signature is genuine over the recorded bytes, so the refusals
			// below are about the empty requester, not about a bad signature.
			expect(
				await crypto.subtle.verify(
					"Ed25519",
					pub,
					hexToBytes(v.signature_hex),
					new TextEncoder().encode(v.canonical_jcs),
				),
			).toBe(true);
			expect(() => acceptancePayload(input)).toThrow(/empty requester/);
			const priv = await importSigningKey(v.seed_hex);
			await expect(signOfferAcceptance(input, priv)).rejects.toThrow(/empty requester/);
			expect(await verifyOfferAcceptance(input, v.signature_hex, pub)).toBe(false);
		});
	}

	it("an unsigned offer (empty offer_sig) is rejected fail-closed", () => {
		expect(() =>
			acceptancePayload({
				offerSig: "",
				requesterId: "a",
				requesterDomain: "a.example",
				idempotencyKey: "i",
			}),
		).toThrow();
	});
});
