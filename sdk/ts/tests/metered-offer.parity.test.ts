// Metered offers (TypeScript side): which offers are metered, and the checks a
// verifier and a signer run.
//
// Mirror of the sdk/python sibling (sdk/python/tests/test_metered_offer_parity.py). A
// PER_UNIT offer is metered; it may state an estimate, positive when stated, and the
// term it sells carries no pricing.
import { describe, expect, it } from "vitest";
import {
	checkMeteredEstimate,
	checkOfferTermsUnpriced,
	isMeteredOffer,
} from "../src/money.ts";

describe("sdk/ts metered helpers", () => {
	const perUnit = { model: "PRICING_MODEL_PER_UNIT" };
	const flat = { model: "PRICING_MODEL_FLAT" };
	const cases: [string, Record<string, unknown>, boolean, boolean][] = [
		["estimated", { pricing: { ...perUnit, estimated_quantity: 1 } }, true, false],
		["string estimate", { pricing: { ...perUnit, estimated_quantity: "7" } }, true, false],
		// The estimate is optional; one that is stated is positive.
		["no estimate", { pricing: { ...perUnit } }, true, false],
		["null estimate is absent", { pricing: { ...perUnit, estimated_quantity: null } }, true, false],
		["zero estimate", { pricing: { ...perUnit, estimated_quantity: 0 } }, true, true],
		["negative estimate", { pricing: { ...perUnit, estimated_quantity: -3 } }, true, true],
		["fractional estimate", { pricing: { ...perUnit, estimated_quantity: 1.5 } }, true, true],
		// A priced term no longer makes an offer metered: Offer.pricing is the one price,
		// and checkOfferTermsUnpriced refuses the priced term instead.
		["term under flat pricing", { pricing: { ...flat }, terms: [{ pricing: { ...perUnit } }] }, false, false],
		["flat", { pricing: { ...flat } }, false, false],
		["no pricing", {}, false, false],
	];
	for (const [name, offer, metered, refused] of cases) {
		it(`metered estimate check: ${name}`, () => {
			expect(isMeteredOffer(offer)).toBe(metered);
			if (refused) {
				expect(() => checkMeteredEstimate(offer)).toThrow();
			} else {
				expect(() => checkMeteredEstimate(offer)).not.toThrow();
			}
		});
	}

	const unpricedCases: [string, Record<string, unknown>, boolean][] = [
		["unpriced term", { pricing: { ...flat }, terms: [{ semantics: "TERM_SEMANTICS_ENUMERATED" }] }, false],
		["no terms", { pricing: { ...flat } }, false],
		["null term pricing is absent", { pricing: { ...flat }, terms: [{ pricing: null }] }, false],
		["term repeating the offer price", { pricing: { ...flat }, terms: [{ pricing: { ...flat } }] }, true],
		["per-unit term under flat pricing", { pricing: { ...flat }, terms: [{ pricing: { ...perUnit } }] }, true],
		["empty term pricing", { pricing: { ...flat }, terms: [{ pricing: {} }] }, true],
	];
	for (const [name, offer, refused] of unpricedCases) {
		it(`offer terms unpriced check: ${name}`, () => {
			if (refused) {
				expect(() => checkOfferTermsUnpriced(offer)).toThrow(/Offer\.pricing/);
			} else {
				expect(() => checkOfferTermsUnpriced(offer)).not.toThrow();
			}
		});
	}
});
