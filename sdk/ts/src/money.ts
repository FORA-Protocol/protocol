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

// ---- metered offers ---------------------------------------------------------
// Port of the sdk/go oracle (helpers/metered.go); fora.proto Pricing states the
// rule. A PER_UNIT price is metered: the publisher states the rate and the unit,
// and the offer may also state an estimate. A metered purchase charges estimate x
// rate, or one unit's rate without an estimate, and the charge is final.

const PRICING_MODEL_PER_UNIT = "PRICING_MODEL_PER_UNIT";

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
 * one the purchase charges one unit at the rate (1 × R) instead of the estimate
 * times the rate (E × R). Either charge is final, and a usage report afterwards
 * is only a record. The offer.metered.estimate_positive rule as a standalone
 * check, for a verifier that runs without wire validation; a non-metered offer
 * passes whatever its pricing says.
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
