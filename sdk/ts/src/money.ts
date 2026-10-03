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
 * what derives from it); amounts are in the price's currency.
 */
export interface MeteredSettlement {
	/** E x R: what the agent accepted at purchase. */
	readonly acceptedAmount: string;
	/** Q = E x (10000 + T) / 10000. */
	readonly ceilingQuantity: string;
	/** Q x R: the most the purchase is charged without a dispute. */
	readonly ceilingAmount: string;
	/** min(C, Q). */
	readonly chargedQuantity: string;
	/** min(C, Q) x R: what the report settles to. */
	readonly chargedAmount: string;
	/** max(0, C - Q): the quantity held for dispute. */
	readonly heldQuantity: string;
	/** max(0, C - Q) x R: held for dispute, never charged automatically. */
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
 * pricing or its term's pricing is PER_UNIT. The term counts because it is the
 * authoritative copy of the price (fora.proto Offer, the
 * offer.metered.requires_estimate rule).
 */
export function isMeteredOffer(offer: Record<string, unknown>): boolean {
	if (modelOf(offer.pricing) === PRICING_MODEL_PER_UNIT) return true;
	const terms = offer.terms;
	return (
		Array.isArray(terms) &&
		terms.some(
			(t) =>
				typeof t === "object" &&
				t !== null &&
				modelOf((t as Record<string, unknown>).pricing) ===
					PRICING_MODEL_PER_UNIT,
		)
	);
}

/**
 * checkMeteredEstimate throws when `offer` is metered and its pricing carries no
 * positive `estimated_quantity`, and returns otherwise. The
 * offer.metered.requires_estimate rule as a standalone check, for a verifier that
 * runs without wire validation; a non-metered offer passes whatever its pricing
 * says.
 */
export function checkMeteredEstimate(offer: Record<string, unknown>): void {
	if (typeof offer !== "object" || offer === null) {
		throw new Error("money: offer is not an object");
	}
	if (!isMeteredOffer(offer)) return;
	const pricing = offer.pricing;
	const estimate =
		typeof pricing === "object" && pricing !== null
			? wireInt((pricing as Record<string, unknown>).estimated_quantity)
			: undefined;
	if (estimate === undefined || estimate <= 0n) {
		throw new Error(
			"money: metered offer carries no positive estimated_quantity",
		);
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

/** Check `pricing` is a metered price that can settle; return E, R and Q. */
function meteredTerms(pricing: Record<string, unknown>): {
	estimate: Dec;
	rate: Dec;
	ceiling: Dec;
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
	const estimate = wireInt(pricing.estimated_quantity);
	if (estimate === undefined || estimate <= 0n) {
		throw new Error(
			"money: metered pricing carries no positive estimated_quantity",
		);
	}
	const rate = parseMoney(typeof pricing.rate === "string" ? pricing.rate : "");
	const bps = estimateToleranceBps(pricing);
	if (bps < 0 || bps > MAX_ESTIMATE_TOLERANCE_BPS) {
		throw new Error(
			`money: estimate_tolerance_bps ${bps} is outside 0..${MAX_ESTIMATE_TOLERANCE_BPS}`,
		);
	}
	return {
		estimate: { units: estimate, scale: 0 },
		rate: decOf(rate),
		ceiling: { units: estimate * BigInt(10000 + bps), scale: 4 },
	};
}

/**
 * meteredSettlementCap returns Q x R for a metered price: the most a purchase
 * under it is charged without a dispute, and the amount an agent budgets against
 * a spend cap. Throws for a price that is not PER_UNIT, carries no positive
 * estimate or no valid rate, or states a tolerance outside 0..10000.
 */
export function meteredSettlementCap(pricing: Record<string, unknown>): string {
	const { rate, ceiling } = meteredTerms(pricing);
	return decFormat(decMul(ceiling, rate));
}

/**
 * settleMeteredUsage settles a usage report of `consumedQuantity` against a
 * metered price — the offer's own pricing, which is the copy settlement reads.
 * Throws for what meteredSettlementCap refuses, and for a quantity that is
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
