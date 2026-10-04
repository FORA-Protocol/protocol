package helpers

import (
	"errors"
	"fmt"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/shopspring/decimal"
)

// Metered settlement (fora.proto Pricing, "METERED SETTLEMENT"). A PER_UNIT
// price is charged per unit consumed. Up to three values on the offer's
// pricing fix what a metered purchase can cost — the rate R, the optional
// estimate E and the tolerance T in basis points (1000 when absent) — and the
// offer signature covers them. Without an estimate there is no ceiling: the
// agent accepts the rate, and the usage report settles the consumed quantity
// C at C × R. With one, the agent accepts E × R at purchase; the usage report
// settles C at min(C, Q) × R, where the ceiling is Q = E × (10000 + T) /
// 10000, and the quantity above Q is held for dispute, never charged
// automatically.
//
// Every value here is exact: the inputs are integers and decimal strings and
// the only division is by 10000, a decimal shift, so no step rounds. The
// results are canonical decimal strings in the money wire form (FormatMoney).

// DefaultEstimateToleranceBps is the tolerance a metered price settles within
// when it states none: 1000 basis points, 10% of the estimate.
const DefaultEstimateToleranceBps int32 = 1000

// MaxEstimateToleranceBps is the largest tolerance the wire accepts: 10000
// basis points, a ceiling of twice the estimate.
const MaxEstimateToleranceBps int32 = 10000

// bpsScale is the basis-point denominator; dividing by it is a shift of four
// decimal places.
const bpsScale = 10000

// ErrMeteredEstimateNotPositive signals a metered (PER_UNIT) offer or price
// that states an estimated_quantity of zero or less. An estimate is optional,
// but one that is stated is positive (the offer.metered.estimate_positive
// rule): a zero estimate would fix a ceiling of nothing.
var ErrMeteredEstimateNotPositive = errors.New("helpers: metered offer states an estimated_quantity that is not positive")

// ErrNotMetered signals a settlement asked of a price that is not PER_UNIT.
var ErrNotMetered = errors.New("helpers: pricing is not metered (PER_UNIT)")

// MeteredSettlement is what a metered purchase settles to, every value a
// canonical decimal string. Quantities are in the price's unit and may be
// fractional (CeilingQuantity, and the quantities derived from it); amounts are
// in the price's currency.
//
// When the price states no estimate, Estimated is false and there is no
// ceiling: AcceptedAmount, CeilingQuantity and CeilingAmount are empty, the
// whole consumed quantity is charged, and nothing is held.
type MeteredSettlement struct {
	// Estimated reports whether the price states an estimate, and so has an
	// accepted amount and a ceiling.
	Estimated bool
	// AcceptedAmount is E × R: what the agent accepted at purchase, and what
	// TransactionResultItem.cost carries for a metered item. Empty without an
	// estimate.
	AcceptedAmount string
	// CeilingQuantity is Q = E × (10000 + T) / 10000. Empty without an
	// estimate.
	CeilingQuantity string
	// CeilingAmount is Q × R: the most the purchase is charged without a
	// dispute. Empty without an estimate.
	CeilingAmount string
	// ChargedQuantity is min(C, Q), or C without an estimate.
	ChargedQuantity string
	// ChargedAmount is ChargedQuantity × R: what the report settles to.
	ChargedAmount string
	// HeldQuantity is max(0, C − Q): the quantity held for dispute. Always 0
	// without an estimate.
	HeldQuantity string
	// HeldAmount is HeldQuantity × R: held for dispute, never charged
	// automatically.
	HeldAmount string
}

// IsMeteredOffer reports whether offer is metered: its pricing is PER_UNIT.
// Offer.pricing is the offer's one price — the term it sells carries none
// (fora.proto Offer, the offer.metered.estimate_positive and
// offer.terms.pricing_unset rules) — so a term is never consulted.
func IsMeteredOffer(offer *forav1.Offer) bool {
	return offer.GetPricing().GetModel() == forav1.PricingModel_PRICING_MODEL_PER_UNIT
}

// CheckMeteredEstimate returns ErrMeteredEstimateNotPositive when offer is
// metered and its pricing states an estimated_quantity of zero or less, and
// nil otherwise. A metered offer that states no estimate passes: the estimate
// is optional, and without one the purchase settles with no ceiling. It is the
// offer.metered.estimate_positive rule as a standalone check, for a verifier
// that runs without wire validation; a non-metered offer passes whatever its
// pricing says.
func CheckMeteredEstimate(offer *forav1.Offer) error {
	if offer == nil {
		return errors.New("helpers: offer is nil")
	}
	if !IsMeteredOffer(offer) {
		return nil
	}
	if p := offer.GetPricing(); p.EstimatedQuantity != nil && p.GetEstimatedQuantity() <= 0 {
		return ErrMeteredEstimateNotPositive
	}
	return nil
}

// EstimateToleranceBps returns the tolerance pricing settles within: its
// estimate_tolerance_bps when present (an explicit 0 included), and
// DefaultEstimateToleranceBps when absent. It does not check the bounds;
// SettleMeteredUsage and MeteredSettlementCap do.
func EstimateToleranceBps(pricing *forav1.Pricing) int32 {
	if pricing == nil || pricing.EstimateToleranceBps == nil {
		return DefaultEstimateToleranceBps
	}
	return pricing.GetEstimateToleranceBps()
}

// meteredTerms holds the parsed settlement inputs of a metered price.
// estimated is false when the price states no estimate; estimate and ceiling
// are then unset.
type meteredTerms struct {
	estimated bool
	estimate  decimal.Decimal
	rate      decimal.Decimal
	ceiling   decimal.Decimal
}

// parseMeteredTerms checks pricing is a metered price that can settle and
// returns its rate, and its estimate and ceiling quantity when it states an
// estimate.
func parseMeteredTerms(pricing *forav1.Pricing) (meteredTerms, error) {
	if pricing == nil {
		return meteredTerms{}, errors.New("helpers: pricing is nil")
	}
	if pricing.GetModel() != forav1.PricingModel_PRICING_MODEL_PER_UNIT {
		return meteredTerms{}, fmt.Errorf("%w: model is %s", ErrNotMetered, pricing.GetModel())
	}
	if pricing.EstimatedQuantity != nil && pricing.GetEstimatedQuantity() <= 0 {
		return meteredTerms{}, ErrMeteredEstimateNotPositive
	}
	rate, err := ParseMoney(pricing.GetRate())
	if err != nil {
		return meteredTerms{}, fmt.Errorf("helpers: metered rate: %w", err)
	}
	bps := EstimateToleranceBps(pricing)
	if bps < 0 || bps > MaxEstimateToleranceBps {
		return meteredTerms{}, fmt.Errorf("helpers: estimate_tolerance_bps %d is outside 0..%d", bps, MaxEstimateToleranceBps)
	}
	if pricing.EstimatedQuantity == nil {
		return meteredTerms{rate: rate}, nil
	}
	estimate := decimal.NewFromInt(int64(pricing.GetEstimatedQuantity()))
	ceiling := estimate.Mul(decimal.NewFromInt(int64(bpsScale + bps))).Shift(-4)
	return meteredTerms{estimated: true, estimate: estimate, rate: rate, ceiling: ceiling}, nil
}

// MeteredSettlementCap returns Q × R for a metered price: the most a purchase
// under it is charged without a dispute, and the amount an agent budgets
// against a spend cap. capped is false, with an empty amount, when the price
// states no estimate: it then has no ceiling, and nothing in it bounds the
// charge. It refuses a price that is not PER_UNIT, states an estimate that is
// not positive, carries no valid rate, or states a tolerance outside
// 0..10000.
func MeteredSettlementCap(pricing *forav1.Pricing) (amount string, capped bool, err error) {
	terms, err := parseMeteredTerms(pricing)
	if err != nil {
		return "", false, err
	}
	if !terms.estimated {
		return "", false, nil
	}
	amount, err = FormatMoney(terms.ceiling.Mul(terms.rate))
	if err != nil {
		return "", false, err
	}
	return amount, true, nil
}

// SettleMeteredUsage settles a usage report of consumedQuantity against a
// metered price — the offer's own pricing, which is the copy settlement reads.
// Without an estimate the whole quantity is charged at the rate and nothing is
// held. It refuses what MeteredSettlementCap refuses, and a negative quantity.
func SettleMeteredUsage(pricing *forav1.Pricing, consumedQuantity int64) (MeteredSettlement, error) {
	terms, err := parseMeteredTerms(pricing)
	if err != nil {
		return MeteredSettlement{}, err
	}
	if consumedQuantity < 0 {
		return MeteredSettlement{}, fmt.Errorf("helpers: consumed quantity %d is negative", consumedQuantity)
	}
	consumed := decimal.NewFromInt(consumedQuantity)
	charged, held := consumed, decimal.Zero
	if terms.estimated {
		charged = decimal.Min(consumed, terms.ceiling)
		held = decimal.Max(decimal.Zero, consumed.Sub(terms.ceiling))
	}
	values := []decimal.Decimal{charged, charged.Mul(terms.rate), held, held.Mul(terms.rate)}
	if terms.estimated {
		values = append(values, terms.estimate.Mul(terms.rate), terms.ceiling, terms.ceiling.Mul(terms.rate))
	}
	out := make([]string, len(values))
	for i, v := range values {
		s, err := FormatMoney(v)
		if err != nil {
			return MeteredSettlement{}, err
		}
		out[i] = s
	}
	settlement := MeteredSettlement{
		Estimated:       terms.estimated,
		ChargedQuantity: out[0],
		ChargedAmount:   out[1],
		HeldQuantity:    out[2],
		HeldAmount:      out[3],
	}
	if terms.estimated {
		settlement.AcceptedAmount, settlement.CeilingQuantity, settlement.CeilingAmount = out[4], out[5], out[6]
	}
	return settlement, nil
}
