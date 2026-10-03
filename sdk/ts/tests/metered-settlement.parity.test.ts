// Metered settlement parity (TypeScript side) against the Go oracle.
//
// Mirror of the sdk/python sibling (sdk/python/tests/test_metered_settlement_parity.py).
// The settlement of a metered purchase is arithmetic the agent and the Exchange must
// agree on to the last digit: the agent derives what it owes from the signed offer and
// its own report, and no amount travels on the wire to reconcile the two. Every row of
// sdk/go/helpers/testdata/metered-settlement-vectors.json is replayed through
// settleMeteredUsage and meteredSettlementCap. Two rows need 42 significant digits, far
// past what a JavaScript number holds, so a port that went through floating point
// would fail them.
import { describe, expect, it } from "vitest";
import {
	DEFAULT_ESTIMATE_TOLERANCE_BPS,
	checkMeteredEstimate,
	estimateToleranceBps,
	isMeteredOffer,
	meteredSettlementCap,
	settleMeteredUsage,
} from "../src/money.ts";
import vectorsFile from "../../go/helpers/testdata/metered-settlement-vectors.json";

type Expected = {
	accepted_amount: string;
	ceiling_quantity: string;
	ceiling_amount: string;
	charged_quantity: string;
	charged_amount: string;
	held_quantity: string;
	held_amount: string;
};
type SettlementVector = {
	name: string;
	pricing: Record<string, unknown>;
	consumed_quantity: number;
	error: boolean;
	cap_error: boolean;
	expected?: Expected;
};
type SettlementVectorsFile = {
	default_estimate_tolerance_bps: number;
	vectors: SettlementVector[];
};

const doc = vectorsFile as SettlementVectorsFile;

describe("sdk/ts metered settlement matches the sdk/go oracle vectors", () => {
	it("corpus carries both settleable and refused rows", () => {
		expect(doc.vectors.some((v) => v.error)).toBe(true);
		expect(doc.vectors.some((v) => !v.error)).toBe(true);
	});

	it("default tolerance matches the oracle", () => {
		expect(DEFAULT_ESTIMATE_TOLERANCE_BPS).toBe(
			doc.default_estimate_tolerance_bps,
		);
	});

	for (const v of doc.vectors) {
		it(v.name, () => {
			if (v.error) {
				expect(() => settleMeteredUsage(v.pricing, v.consumed_quantity)).toThrow();
				if (v.cap_error) {
					expect(() => meteredSettlementCap(v.pricing)).toThrow();
				} else {
					expect(() => meteredSettlementCap(v.pricing)).not.toThrow();
				}
				return;
			}
			const want = v.expected as Expected;
			const got = settleMeteredUsage(v.pricing, v.consumed_quantity);
			expect({
				accepted_amount: got.acceptedAmount,
				ceiling_quantity: got.ceilingQuantity,
				ceiling_amount: got.ceilingAmount,
				charged_quantity: got.chargedQuantity,
				charged_amount: got.chargedAmount,
				held_quantity: got.heldQuantity,
				held_amount: got.heldAmount,
			}).toEqual(want);
			expect(meteredSettlementCap(v.pricing)).toBe(want.ceiling_amount);
		});
	}
});

describe("sdk/ts metered helpers", () => {
	const pricing = {
		model: "PRICING_MODEL_PER_UNIT",
		rate: "0.00002",
		unit: "tokens",
		estimated_quantity: 2500,
	};

	it("applies the default tolerance and keeps an explicit zero", () => {
		expect(estimateToleranceBps({})).toBe(1000);
		expect(estimateToleranceBps({ estimate_tolerance_bps: 0 })).toBe(0);
		expect(estimateToleranceBps({ estimate_tolerance_bps: "250" })).toBe(250);
	});

	it("accepts a bigint quantity and refuses a fractional or unsafe one", () => {
		expect(settleMeteredUsage(pricing, 3000n).heldQuantity).toBe("250");
		expect(() => settleMeteredUsage(pricing, 1.5)).toThrow();
		expect(() => settleMeteredUsage(pricing, Number.MAX_SAFE_INTEGER + 2)).toThrow();
		expect(() => settleMeteredUsage(pricing, 2n ** 63n)).toThrow();
	});

	const perUnit = { model: "PRICING_MODEL_PER_UNIT" };
	const flat = { model: "PRICING_MODEL_FLAT" };
	const cases: [string, Record<string, unknown>, boolean, boolean][] = [
		["estimated", { pricing: { ...perUnit, estimated_quantity: 1 } }, true, false],
		["string estimate", { pricing: { ...perUnit, estimated_quantity: "7" } }, true, false],
		["no estimate", { pricing: { ...perUnit } }, true, true],
		["zero estimate", { pricing: { ...perUnit, estimated_quantity: 0 } }, true, true],
		["fractional estimate", { pricing: { ...perUnit, estimated_quantity: 1.5 } }, true, true],
		["term under flat pricing", { pricing: { ...flat }, terms: [{ pricing: { ...perUnit } }] }, true, true],
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
});
