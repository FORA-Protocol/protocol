import { describe, expect, it } from "vitest";
import vectors from "../../go/helpers/testdata/request-acceptance-vectors.json";
import { requestAcceptancePayload, signRequestAcceptance, verifyRequestAcceptance } from "../src/acceptance.ts";
import { importSigningKey as privateKey, importVerifyKey as publicKey } from "./wba-fixtures.ts";

describe("request acceptance matches the Go oracle", () => {
	for (const vector of vectors.vectors) {
		const input = {
			items: vector.items.map((item) => ({
				offerSig: item.offer_sig,
				exchange: item.exchange,
			})),
			requesterId: vector.requester_id,
			requesterDomain: vector.requester_domain,
			idempotencyKey: vector.idempotency_key,
		};

		it(`${vector.name}: canonical bytes and signature`, async () => {
			expect(new TextDecoder().decode(requestAcceptancePayload(input))).toBe(vector.canonical_jcs);
			expect(await signRequestAcceptance(input, await privateKey(vector.seed_hex))).toBe(vector.signature_hex);
			expect(await verifyRequestAcceptance(input, vector.signature_hex, await publicKey(vector.pubkey_b64))).toBe(true);
		});
	}

	// The request acceptance names the requester under the same rule as the offer
	// acceptance: the canonicalizer and the signer throw, and the verifier answers false
	// although the recorded signature verifies over the recorded bytes.
	it("refused vectors cover each requester field", () => {
		expect(vectors.refused.map((v) => v.empty).sort()).toEqual(["requester_domain", "requester_id"]);
	});

	for (const vector of vectors.refused) {
		const input = {
			items: vector.items.map((item) => ({
				offerSig: item.offer_sig,
				exchange: item.exchange,
			})),
			requesterId: vector.requester_id,
			requesterDomain: vector.requester_domain,
			idempotencyKey: vector.idempotency_key,
		};

		it(`${vector.name}: a payload naming an empty requester is refused`, async () => {
			expect((vector as Record<string, unknown>)[vector.empty]).toBe("");
			expect(() => requestAcceptancePayload(input)).toThrow(/empty requester/);
			await expect(signRequestAcceptance(input, await privateKey(vector.seed_hex))).rejects.toThrow(/empty requester/);
			expect(await verifyRequestAcceptance(input, vector.signature_hex, await publicKey(vector.pubkey_b64))).toBe(
				false,
			);
		});
	}

	it("signs item order", async () => {
		const vector = vectors.vectors[0]!;
		const input = {
			items: vector.items.map((item) => ({ offerSig: item.offer_sig, exchange: item.exchange })).reverse(),
			requesterId: vector.requester_id,
			requesterDomain: vector.requester_domain,
			idempotencyKey: vector.idempotency_key,
		};
		expect(await verifyRequestAcceptance(input, vector.signature_hex, await publicKey(vector.pubkey_b64))).toBe(false);
	});
});
