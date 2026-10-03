package helpers

import (
	"errors"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"google.golang.org/protobuf/proto"
)

// The settlement arithmetic is pinned by metered-settlement-vectors.json, which
// every SDK replays. These tests cover what the vectors do not: which offers are
// metered, the estimate check a verifier runs, and the tolerance default.

func meteredTestOffer(offerModel, termModel forav1.PricingModel, estimate *int32) *forav1.Offer {
	return &forav1.Offer{
		Pricing: &forav1.Pricing{Model: offerModel, EstimatedQuantity: estimate},
		Terms:   []*forav1.LicenseTerm{{Pricing: &forav1.Pricing{Model: termModel}}},
	}
}

func TestCheckMeteredEstimate(t *testing.T) {
	perUnit, flat := forav1.PricingModel_PRICING_MODEL_PER_UNIT, forav1.PricingModel_PRICING_MODEL_FLAT
	cases := []struct {
		name    string
		offer   *forav1.Offer
		metered bool
		wantErr bool
	}{
		{"per_unit_with_estimate", meteredTestOffer(perUnit, perUnit, proto.Int32(1)), true, false},
		{"per_unit_without_estimate", meteredTestOffer(perUnit, perUnit, nil), true, true},
		{"per_unit_zero_estimate", meteredTestOffer(perUnit, perUnit, proto.Int32(0)), true, true},
		{"per_unit_negative_estimate", meteredTestOffer(perUnit, perUnit, proto.Int32(-3)), true, true},
		{"per_unit_term_under_flat_pricing", meteredTestOffer(flat, perUnit, nil), true, true},
		{"per_unit_term_estimate_on_flat_pricing", meteredTestOffer(flat, perUnit, proto.Int32(10)), true, false},
		{"flat_without_estimate", meteredTestOffer(flat, flat, nil), false, false},
		{"no_pricing_at_all", &forav1.Offer{}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsMeteredOffer(c.offer); got != c.metered {
				t.Fatalf("IsMeteredOffer = %v, want %v", got, c.metered)
			}
			err := CheckMeteredEstimate(c.offer)
			if c.wantErr != (err != nil) {
				t.Fatalf("CheckMeteredEstimate = %v, want error %v", err, c.wantErr)
			}
			if c.wantErr && !errors.Is(err, ErrMeteredEstimateMissing) {
				t.Fatalf("CheckMeteredEstimate = %v, want ErrMeteredEstimateMissing", err)
			}
		})
	}
	if err := CheckMeteredEstimate(nil); err == nil {
		t.Fatal("CheckMeteredEstimate(nil) must refuse")
	}
}

func TestEstimateToleranceBps(t *testing.T) {
	if got := EstimateToleranceBps(nil); got != DefaultEstimateToleranceBps {
		t.Fatalf("nil pricing: got %d, want the default %d", got, DefaultEstimateToleranceBps)
	}
	if got := EstimateToleranceBps(&forav1.Pricing{}); got != 1000 {
		t.Fatalf("absent tolerance: got %d, want 1000", got)
	}
	if got := EstimateToleranceBps(&forav1.Pricing{EstimateToleranceBps: proto.Int32(0)}); got != 0 {
		t.Fatalf("explicit zero tolerance: got %d, want 0 (no tolerance, not the default)", got)
	}
}

func TestSettleMeteredUsageRefusesNotMetered(t *testing.T) {
	_, err := SettleMeteredUsage(&forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1"}, 1)
	if !errors.Is(err, ErrNotMetered) {
		t.Fatalf("FLAT pricing: got %v, want ErrNotMetered", err)
	}
	_, err = MeteredSettlementCap(&forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "1"})
	if !errors.Is(err, ErrMeteredEstimateMissing) {
		t.Fatalf("PER_UNIT without estimate: got %v, want ErrMeteredEstimateMissing", err)
	}
	if _, err := SettleMeteredUsage(nil, 1); err == nil {
		t.Fatal("nil pricing must refuse")
	}
}
