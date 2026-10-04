package helpers

import (
	"errors"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"google.golang.org/protobuf/proto"
)

// Which offers are metered, and the estimate check a verifier runs.

func meteredTestOffer(offerModel forav1.PricingModel, estimate *int32) *forav1.Offer {
	return &forav1.Offer{
		Pricing: &forav1.Pricing{Model: offerModel, EstimatedQuantity: estimate},
		Terms:   []*forav1.LicenseTerm{{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED}},
	}
}

func TestCheckMeteredEstimate(t *testing.T) {
	perUnit, flat := forav1.PricingModel_PRICING_MODEL_PER_UNIT, forav1.PricingModel_PRICING_MODEL_FLAT
	// A priced term no longer makes an offer metered: Offer.pricing is the
	// offer's one price, and a term carrying pricing is refused on its own
	// (CheckOfferTermsUnpriced), not read.
	pricedTerm := meteredTestOffer(flat, nil)
	pricedTerm.Terms[0].Pricing = &forav1.Pricing{Model: perUnit, EstimatedQuantity: proto.Int32(10)}
	cases := []struct {
		name    string
		offer   *forav1.Offer
		metered bool
		wantErr bool
	}{
		{"per_unit_with_estimate", meteredTestOffer(perUnit, proto.Int32(1)), true, false},
		{"per_unit_without_estimate_is_valid", meteredTestOffer(perUnit, nil), true, false},
		{"per_unit_zero_estimate", meteredTestOffer(perUnit, proto.Int32(0)), true, true},
		{"per_unit_negative_estimate", meteredTestOffer(perUnit, proto.Int32(-3)), true, true},
		{"per_unit_term_under_flat_pricing_is_not_metered", pricedTerm, false, false},
		{"flat_without_estimate", meteredTestOffer(flat, nil), false, false},
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
			if c.wantErr && !errors.Is(err, ErrMeteredEstimateNotPositive) {
				t.Fatalf("CheckMeteredEstimate = %v, want ErrMeteredEstimateNotPositive", err)
			}
		})
	}
	if err := CheckMeteredEstimate(nil); err == nil {
		t.Fatal("CheckMeteredEstimate(nil) must refuse")
	}
}

func TestCheckOfferTermsUnpriced(t *testing.T) {
	unpriced := meteredTestOffer(forav1.PricingModel_PRICING_MODEL_FLAT, nil)
	if err := CheckOfferTermsUnpriced(unpriced); err != nil {
		t.Fatalf("unpriced term: got %v, want nil", err)
	}
	if err := CheckOfferTermsUnpriced(&forav1.Offer{}); err != nil {
		t.Fatalf("no terms: got %v, want nil", err)
	}
	priced := meteredTestOffer(forav1.PricingModel_PRICING_MODEL_FLAT, nil)
	priced.Terms[0].Pricing = proto.Clone(priced.Pricing).(*forav1.Pricing)
	if err := CheckOfferTermsUnpriced(priced); !errors.Is(err, ErrOfferTermPriced) {
		t.Fatalf("term repeating the offer price: got %v, want ErrOfferTermPriced", err)
	}
	// An empty Pricing is still pricing present on the term.
	empty := meteredTestOffer(forav1.PricingModel_PRICING_MODEL_FLAT, nil)
	empty.Terms[0].Pricing = &forav1.Pricing{}
	if err := CheckOfferTermsUnpriced(empty); !errors.Is(err, ErrOfferTermPriced) {
		t.Fatalf("empty term pricing: got %v, want ErrOfferTermPriced", err)
	}
	if err := CheckOfferTermsUnpriced(nil); err == nil || errors.Is(err, ErrOfferTermPriced) {
		t.Fatalf("nil offer: got %v, want a refusal that is not ErrOfferTermPriced", err)
	}
	if _, err := SignOffer(make([]byte, 64), priced); !errors.Is(err, ErrOfferTermPriced) {
		t.Fatalf("SignOffer of a priced term: got %v, want ErrOfferTermPriced", err)
	}
}
