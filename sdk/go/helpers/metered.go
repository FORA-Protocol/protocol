package helpers

import (
	"errors"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// Metered offers (fora.proto Pricing, "METERED PRICE"). A PER_UNIT price is
// metered: the publisher states the rate and the unit, and the offer may also
// state an estimate. A metered purchase charges estimate × rate, or one unit,
// 1 × rate, without an estimate, and the charge is final.

// ErrMeteredEstimateNotPositive signals a metered (PER_UNIT) offer that states
// an estimated_quantity of zero or less. An estimate is optional, but one that
// is stated is positive (the offer.metered.estimate_positive rule): a zero
// estimate would price the purchase at nothing.
var ErrMeteredEstimateNotPositive = errors.New("helpers: metered offer states an estimated_quantity that is not positive")

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
// is optional. It is the offer.metered.estimate_positive rule as a standalone
// check, for a verifier that runs without wire validation; a non-metered offer
// passes whatever its pricing says.
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
