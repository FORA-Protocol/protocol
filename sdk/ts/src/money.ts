// Money (ADR-020) — TS port of the sdk/go oracle (helpers/money.go). FORA money
// fields (Pricing.rate, Cost.amount, *.unit_cost) are exact decimal strings —
// never floats — constrained by protovalidate to the wire pattern below:
// non-negative, no sign, no exponent, optional fractional part, empty string
// for "unset". The Go oracle round-trips shopspring decimal (NewFromString then
// String); TS has no stdlib decimal, so the surface is a validated canonical
// STRING. canonicalizeMoney reproduces the Go bytes: strip insignificant
// LEADING integer zeros AND trailing fractional zeros + a bare trailing dot.

// moneyWire mirrors the protovalidate constraint `^([0-9]+([.][0-9]+)?)?$`
// exactly (kept in lockstep with fora.proto Pricing.rate). The empty string
// matches the pattern but is rejected by parseMoney as "unset".
const moneyWire = /^([0-9]+([.][0-9]+)?)?$/;

/**
 * parseMoney validates a canonical wire decimal string, rejecting the empty
 * (unset) string and any value the wire pattern forbids — signs, exponents, a
 * leading dot — so a value that would fail the server's protovalidate never
 * silently parses here. Returns the validated string (the TS decimal surface).
 */
export function parseMoney(s: string): string {
	if (s === "") {
		throw new Error("money: empty money string (field is unset)");
	}
	// Mirror protovalidate string.max_len = 32 (fora.proto Pricing.rate) so a
	// pattern-valid but over-length value is rejected here, not only server-side.
	if (s.length > 32) {
		throw new Error(`money: string length ${s.length} exceeds max 32`);
	}
	if (!moneyWire.test(s)) {
		throw new Error(
			`money: ${JSON.stringify(s)} is not a canonical money string`,
		);
	}
	return s;
}

/**
 * formatMoney renders a validated money string as the canonical wire form: no
 * sign, no exponent, insignificant LEADING integer zeros dropped ("007" -> "7",
 * "00.5" -> "0.5", "000" -> "0") and insignificant trailing fractional zeros +
 * a bare trailing dot stripped ("0.050" -> "0.05", "1.00" -> "1"). A negative
 * value is rejected — FORA money is non-negative.
 */
export function formatMoney(s: string): string {
	if (s.startsWith("-")) {
		throw new Error(
			`money: negative money ${JSON.stringify(s)} is not representable on the wire`,
		);
	}
	const dot = s.indexOf(".");
	let intPart = dot === -1 ? s : s.slice(0, dot);
	let fracPart = dot === -1 ? "" : s.slice(dot + 1);
	intPart = intPart.replace(/^0+/, "");
	if (intPart === "") intPart = "0";
	fracPart = fracPart.replace(/0+$/, "");
	return fracPart === "" ? intPart : `${intPart}.${fracPart}`;
}

/**
 * canonicalizeMoney normalizes a wire decimal string to its canonical form
 * (parse then format) — the convenience used when echoing a money value back
 * onto the wire without doing arithmetic.
 */
export function canonicalizeMoney(s: string): string {
	return formatMoney(parseMoney(s));
}

// ---- metered settlement ----------------------------------------------------
// Port of the sdk/go oracle (helpers/settlement.go); fora.proto Pricing states the
// rule. A PER_UNIT price is charged per unit consumed. The estimate E, the rate R
// and the tolerance T in basis points (1000 when absent) on the offer's own pricing
// fix what a metered purchase can cost: the agent accepts E x R at purchase, and the
// usage report settles the consumed quantity C at min(C, Q) x R, where the ceiling
// is Q = E x (10000 + T) / 10000. The quantity above Q is held for dispute, never
// charged automatically.
//
// TS has no decimal type, so the arithmetic runs on BigInt: a value is an integer
// count of units at a decimal scale. Multiplication adds scales, the division by
// 10000 adds four to the scale, and comparison and subtraction align the scales
// first — no step can round, whatever the size of the inputs.

/** The tolerance a metered price settles within when it states none: 10%. */
export const DEFAULT_ESTIMATE_TOLERANCE_BPS = 1000;

/** The largest tolerance the wire accepts: a ceiling of twice the estimate. */
export const MAX_ESTIMATE_TOLERANCE_BPS = 10000;

const PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT";
const INT64_MAX = 2n ** 63n - 1n;

/**
 * What a metered purchase settles to, every value a canonical decimal string.
 * Quantities are in the price's unit and may be fractional (`ceilingQuantity` and
 * what derives from it); amounts are in the price's currency. When the price
 * states no estimate there is no ceiling: `acceptedAmount`, `ceilingQuantity` and
 * `ceilingAmount` are undefined, the whole consumed quantity is charged, and
 * nothing is held.
 */
export interface MeteredSettlement {
	/** E x R: what the agent accepted at purchase. Undefined without an estimate. */
	readonly acceptedAmount: string | undefined;
	/** Q = E x (10000 + T) / 10000. Undefined without an estimate. */
	readonly ceilingQuantity: string | undefined;
	/**
	 * Q x R: the most the purchase is charged without a dispute. Undefined without
	 * an estimate.
	 */
	readonly ceilingAmount: string | undefined;
	/** min(C, Q), or C without an estimate. */
	readonly chargedQuantity: string;
	/** chargedQuantity x R: what the report settles to. */
	readonly chargedAmount: string;
	/** max(0, C - Q): the quantity held for dispute. Always 0 without an estimate. */
	readonly heldQuantity: string;
	/** heldQuantity x R: held for dispute, never charged automatically. */
	readonly heldAmount: string;
}

/** An exact non-negative decimal: units / 10^scale. */
interface Dec {
	readonly units: bigint;
	readonly scale: number;
}

function decOf(s: string): Dec {
	const dot = s.indexOf(".");
	if (dot === -1) return { units: BigInt(s), scale: 0 };
	return {
		units: BigInt(s.slice(0, dot) + s.slice(dot + 1)),
		scale: s.length - dot - 1,
	};
}

function decMul(a: Dec, b: Dec): Dec {
	return { units: a.units * b.units, scale: a.scale + b.scale };
}

function decAligned(a: Dec, b: Dec): [bigint, bigint, number] {
	const scale = Math.max(a.scale, b.scale);
	return [
		a.units * 10n ** BigInt(scale - a.scale),
		b.units * 10n ** BigInt(scale - b.scale),
		scale,
	];
}

function decMin(a: Dec, b: Dec): Dec {
	const [x, y] = decAligned(a, b);
	return x <= y ? a : b;
}

/** max(0, a - b). */
function decExcess(a: Dec, b: Dec): Dec {
	const [x, y, scale] = decAligned(a, b);
	return x > y ? { units: x - y, scale } : { units: 0n, scale: 0 };
}

function decFormat(d: Dec): string {
	const digits = d.units.toString().padStart(d.scale + 1, "0");
	const cut = digits.length - d.scale;
	return formatMoney(
		d.scale === 0 ? digits : `${digits.slice(0, cut)}.${digits.slice(cut)}`,
	);
}

/**
 * An int32/int64 proto-JSON value: a JSON integer, or the decimal string form
 * proto-JSON also accepts. undefined for anything else.
 */
function wireInt(v: unknown): bigint | undefined {
	if (typeof v === "number" && Number.isSafeInteger(v)) return BigInt(v);
	if (typeof v === "string" && /^-?[0-9]+$/.test(v)) return BigInt(v);
	return undefined;
}

function modelOf(pricing: unknown): string {
	if (typeof pricing !== "object" || pricing === null) return "";
	const model = (pricing as Record<string, unknown>).model;
	return typeof model === "string" ? model : "";
}

/**
 * isMeteredOffer reports whether `offer` (canonical proto-JSON) is metered: its
 * pricing is PER_UNIT. `Offer.pricing` is the offer's one price and the term it
 * sells carries none (fora.proto Offer, the offer.metered.estimate_positive and
 * offer.terms.pricing_unset rules), so a term is never consulted. TS peer of Go
 * `helpers.IsMeteredOffer`.
 */
export function isMeteredOffer(offer: Record<string, unknown>): boolean {
	return modelOf(offer.pricing) === PRICING_MODEL_PER_UNIT;
}

/**
 * checkOfferTermsUnpriced throws when any term of `offer` (canonical proto-JSON)
 * carries `pricing`, and returns otherwise. An offer states its price once, in
 * `Offer.pricing`, and the term it sells carries none (fora.proto Offer, the
 * offer.terms.pricing_unset rule). This is that rule as a standalone check, for a
 * signer or a verifier that runs without wire validation. A present `pricing`
 * counts whatever its value, as `has()` does; `null` is proto-JSON for absent. TS
 * peer of Go `helpers.CheckOfferTermsUnpriced`.
 */
export function checkOfferTermsUnpriced(offer: Record<string, unknown>): void {
	if (typeof offer !== "object" || offer === null) {
		throw new Error("money: offer is not an object");
	}
	const terms = offer.terms;
	if (!Array.isArray(terms)) return;
	terms.forEach((t, i) => {
		if (typeof t !== "object" || t === null) return;
		const pricing = (t as Record<string, unknown>).pricing;
		if (pricing !== undefined && pricing !== null) {
			throw new Error(
				`money: an offer's term carries pricing; the offer's price is Offer.pricing (terms[${i}])`,
			);
		}
	});
}

/**
 * The `estimated_quantity` `pricing` states, or undefined when it states none
 * (`null` is proto-JSON for absent). Throws for a stated estimate that is not a
 * positive integer: an estimate is optional, but one that is stated is positive.
 */
function statedEstimate(pricing: Record<string, unknown>): bigint | undefined {
	const raw = pricing.estimated_quantity;
	if (raw === undefined || raw === null) return undefined;
	const estimate = wireInt(raw);
	if (estimate === undefined || estimate <= 0n) {
		throw new Error(
			`money: metered pricing states an estimated_quantity that is not positive: ${JSON.stringify(raw)}`,
		);
	}
	return estimate;
}

/**
 * checkMeteredEstimate throws when `offer` is metered and its pricing states an
 * `estimated_quantity` that is not positive, and returns otherwise. A metered
 * offer that states no estimate passes: the estimate is optional, and without
 * one the purchase settles with no ceiling. The offer.metered.estimate_positive
 * rule as a standalone check, for a verifier that runs without wire validation;
 * a non-metered offer passes whatever its pricing says.
 */
export function checkMeteredEstimate(offer: Record<string, unknown>): void {
	if (typeof offer !== "object" || offer === null) {
		throw new Error("money: offer is not an object");
	}
	if (!isMeteredOffer(offer)) return;
	const pricing = offer.pricing;
	if (typeof pricing === "object" && pricing !== null) {
		statedEstimate(pricing as Record<string, unknown>);
	}
}

/**
 * estimateToleranceBps returns the tolerance `pricing` settles within: its
 * `estimate_tolerance_bps` when present (an explicit 0 included), else the 1000
 * default. Bounds are not checked here; settleMeteredUsage and
 * meteredSettlementCap do.
 */
export function estimateToleranceBps(pricing: Record<string, unknown>): number {
	const raw = pricing.estimate_tolerance_bps;
	if (raw === undefined || raw === null) return DEFAULT_ESTIMATE_TOLERANCE_BPS;
	const bps = wireInt(raw);
	if (bps === undefined) {
		throw new Error(
			`money: estimate_tolerance_bps ${JSON.stringify(raw)} is not an integer`,
		);
	}
	return Number(bps);
}

/**
 * Check `pricing` is a metered price that can settle; return E, R and Q. E and Q
 * are undefined when the price states no estimate.
 */
function meteredTerms(pricing: Record<string, unknown>): {
	estimate: Dec | undefined;
	rate: Dec;
	ceiling: Dec | undefined;
} {
	if (typeof pricing !== "object" || pricing === null) {
		throw new Error("money: pricing is not an object");
	}
	const model = modelOf(pricing);
	if (model !== PRICING_MODEL_PER_UNIT) {
		throw new Error(
			`money: pricing is not metered (PER_UNIT): model is ${JSON.stringify(model)}`,
		);
	}
	const estimate = statedEstimate(pricing);
	const rate = parseMoney(typeof pricing.rate === "string" ? pricing.rate : "");
	const bps = estimateToleranceBps(pricing);
	if (bps < 0 || bps > MAX_ESTIMATE_TOLERANCE_BPS) {
		throw new Error(
			`money: estimate_tolerance_bps ${bps} is outside 0..${MAX_ESTIMATE_TOLERANCE_BPS}`,
		);
	}
	if (estimate === undefined) {
		return { estimate: undefined, rate: decOf(rate), ceiling: undefined };
	}
	return {
		estimate: { units: estimate, scale: 0 },
		rate: decOf(rate),
		ceiling: { units: estimate * BigInt(10000 + bps), scale: 4 },
	};
}

/**
 * meteredSettlementCap returns Q x R for a metered price: the most a purchase
 * under it is charged without a dispute. Undefined when the price states no estimate: it then has no
 * ceiling, and nothing in it bounds the charge. Throws for a price that is not
 * PER_UNIT, states an estimate that is not positive, carries no valid rate, or
 * states a tolerance outside 0..10000.
 */
export function meteredSettlementCap(
	pricing: Record<string, unknown>,
): string | undefined {
	const { rate, ceiling } = meteredTerms(pricing);
	if (ceiling === undefined) return undefined;
	return decFormat(decMul(ceiling, rate));
}

/**
 * settleMeteredUsage settles a usage report of `consumedQuantity` against a
 * metered price — the offer's own pricing, which is the copy settlement reads.
 * Without an estimate the whole quantity is charged at the rate and nothing is
 * held. Throws for what meteredSettlementCap refuses, and for a quantity that is
 * negative, not an integer, or above the int64 range.
 */
export function settleMeteredUsage(
	pricing: Record<string, unknown>,
	consumedQuantity: number | bigint,
): MeteredSettlement {
	const { estimate, rate, ceiling } = meteredTerms(pricing);
	let consumedUnits: bigint;
	if (typeof consumedQuantity === "bigint") {
		consumedUnits = consumedQuantity;
	} else if (Number.isSafeInteger(consumedQuantity)) {
		consumedUnits = BigInt(consumedQuantity);
	} else {
		throw new Error(
			`money: consumed quantity ${String(consumedQuantity)} is not an integer`,
		);
	}
	if (consumedUnits < 0n || consumedUnits > INT64_MAX) {
		throw new Error(
			`money: consumed quantity ${consumedUnits} is outside 0..${INT64_MAX}`,
		);
	}
	const consumed: Dec = { units: consumedUnits, scale: 0 };
	if (estimate === undefined || ceiling === undefined) {
		return {
			acceptedAmount: undefined,
			ceilingQuantity: undefined,
			ceilingAmount: undefined,
			chargedQuantity: decFormat(consumed),
			chargedAmount: decFormat(decMul(consumed, rate)),
			heldQuantity: "0",
			heldAmount: "0",
		};
	}
	const charged = decMin(consumed, ceiling);
	const held = decExcess(consumed, ceiling);
	return {
		acceptedAmount: decFormat(decMul(estimate, rate)),
		ceilingQuantity: decFormat(ceiling),
		ceilingAmount: decFormat(decMul(ceiling, rate)),
		chargedQuantity: decFormat(charged),
		chargedAmount: decFormat(decMul(charged, rate)),
		heldQuantity: decFormat(held),
		heldAmount: decFormat(decMul(held, rate)),
	};
}
