package helpers

// Metered-settlement golden-vector emitter.
//
// The settlement of a metered purchase is arithmetic every party must agree on
// to the last digit: the agent derives what it owes from the signed offer and
// its own report, and the Exchange charges it, with no amount on the wire to
// reconcile the two. Each row states the values its author worked out by hand,
// and the emitter refuses to write a file where the real SettleMeteredUsage or
// MeteredSettlementCap disagrees, so a face that drifted cannot publish its
// drift as the new expectation.
//
// The rows reach past every default precision a decimal library ships with:
// Python's Decimal context carries 28 significant digits, and two rows here
// need 42. A port that does not do the arithmetic exactly fails them.
//
// Verification no-op by default (asserts the committed file matches a fresh
// emit); (re)writes under FORA_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// settlementExpectation is MeteredSettlement as the corpus records it.
type settlementExpectation struct {
	AcceptedAmount  string `json:"accepted_amount"`
	CeilingQuantity string `json:"ceiling_quantity"`
	CeilingAmount   string `json:"ceiling_amount"`
	ChargedQuantity string `json:"charged_quantity"`
	ChargedAmount   string `json:"charged_amount"`
	HeldQuantity    string `json:"held_quantity"`
	HeldAmount      string `json:"held_amount"`
}

// settlementVector is one SettleMeteredUsage case. pricing is the offer's
// pricing in canonical proto-JSON. A row with error true is refused by both
// SettleMeteredUsage and MeteredSettlementCap, unless cap_error is false — a
// negative consumed quantity is the settlement's fault, not the price's.
type settlementVector struct {
	Name             string                 `json:"name"`
	Pricing          json.RawMessage        `json:"pricing"`
	ConsumedQuantity int64                  `json:"consumed_quantity"`
	Error            bool                   `json:"error"`
	CapError         bool                   `json:"cap_error"`
	Expected         *settlementExpectation `json:"expected,omitempty"`
}

func perToken(estimate, toleranceBps *int32, rate string) *forav1.Pricing {
	return &forav1.Pricing{
		Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: rate, Currency: "USD",
		Unit: proto.String("tokens"), EstimatedQuantity: estimate, EstimateToleranceBps: toleranceBps,
	}
}

func settled(accepted, ceilQ, ceilA, chargedQ, chargedA, heldQ, heldA string) *settlementExpectation {
	return &settlementExpectation{accepted, ceilQ, ceilA, chargedQ, chargedA, heldQ, heldA}
}

func buildSettlementVectors(t *testing.T) []settlementVector {
	t.Helper()
	const rate = "0.00002" // per token; E = 2500 accepts 0.05
	tiny := "0.00000000000000000000000001234"
	huge := "99999999999999999999999999999999"
	e := proto.Int32
	type row struct {
		name     string
		pricing  *forav1.Pricing
		consumed int64
		want     *settlementExpectation // nil: refused
		capOK    bool                   // a refused row whose price still yields a cap
	}
	rows := []row{
		// The three branches of the rule, at the default 10% tolerance (Q = 2750).
		{"below_estimate_charged_as_consumed", perToken(e(2500), nil, rate), 2000,
			settled("0.05", "2750", "0.055", "2000", "0.04", "0", "0"), false},
		{"zero_consumed_charges_nothing", perToken(e(2500), nil, rate), 0,
			settled("0.05", "2750", "0.055", "0", "0", "0", "0"), false},
		{"at_estimate", perToken(e(2500), nil, rate), 2500,
			settled("0.05", "2750", "0.055", "2500", "0.05", "0", "0"), false},
		{"within_default_tolerance_charged_in_full", perToken(e(2500), nil, rate), 2700,
			settled("0.05", "2750", "0.055", "2700", "0.054", "0", "0"), false},
		{"at_ceiling_inclusive", perToken(e(2500), nil, rate), 2750,
			settled("0.05", "2750", "0.055", "2750", "0.055", "0", "0"), false},
		{"above_ceiling_excess_held", perToken(e(2500), nil, rate), 3000,
			settled("0.05", "2750", "0.055", "2750", "0.055", "250", "0.005"), false},

		// A stated tolerance replaces the default; an explicit 0 is no tolerance.
		{"explicit_zero_tolerance_estimate_is_ceiling", perToken(e(2500), e(0), rate), 2600,
			settled("0.05", "2500", "0.05", "2500", "0.05", "100", "0.002"), false},
		{"explicit_max_tolerance_doubles_estimate", perToken(e(2500), e(10000), rate), 4000,
			settled("0.05", "5000", "0.1", "4000", "0.08", "0", "0"), false},
		{"odd_tolerance_fractional_ceiling", perToken(e(333), e(125), "0.0003"), 400,
			settled("0.0999", "337.1625", "0.10114875", "337.1625", "0.10114875", "62.8375", "0.01885125"), false},
		{"default_tolerance_fractional_ceiling", perToken(e(15), nil, "0.10"), 20,
			settled("1.5", "16.5", "1.65", "16.5", "1.65", "3.5", "0.35"), false},

		// Exactness past every default precision: 42 significant digits.
		{"exact_tiny_rate_large_quantities", perToken(e(2000000001), e(3), tiny), 2147483647,
			settled("0.00000000000000002468000001234", "2000600001.0003", "0.000000000000000024687404012343702",
				"2000600001.0003", "0.000000000000000024687404012343702",
				"146883645.9997", "0.000000000000000001812544191636298"), false},
		{"exact_huge_rate_large_quantities", perToken(e(2000000001), e(3), huge), 2147483647,
			settled("200000000099999999999999999999997999999999", "2000600001.0003",
				"200060000100029999999999999999997999399998.9997",
				"2000600001.0003", "200060000100029999999999999999997999399998.9997",
				"146883645.9997", "14688364599969999999999999999999853116354.0003"), false},

		// Refusals. Each is refused by the settlement; all but the last by the cap too.
		{"refused_not_metered", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"}, 1, nil, false},
		{"refused_free", &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FREE, Rate: "0"}, 1, nil, false},
		{"refused_missing_estimate", perToken(nil, nil, rate), 2500, nil, false},
		{"refused_zero_estimate", perToken(e(0), nil, rate), 2500, nil, false},
		{"refused_negative_estimate", perToken(e(-1), nil, rate), 2500, nil, false},
		{"refused_empty_rate", perToken(e(2500), nil, ""), 2500, nil, false},
		{"refused_malformed_rate", perToken(e(2500), nil, "1E-5"), 2500, nil, false},
		{"refused_tolerance_above_max", perToken(e(2500), e(10001), rate), 2500, nil, false},
		{"refused_negative_tolerance", perToken(e(2500), e(-1), rate), 2500, nil, false},
		{"refused_negative_consumed", perToken(e(2500), nil, rate), -1, nil, true},
	}

	marshal := protojson.MarshalOptions{UseProtoNames: true}
	out := make([]settlementVector, 0, len(rows))
	for _, r := range rows {
		pj, err := marshal.Marshal(r.pricing)
		if err != nil {
			t.Fatalf("%s: marshal pricing: %v", r.name, err)
		}
		got, setErr := SettleMeteredUsage(r.pricing, r.consumed)
		capAmount, capErr := MeteredSettlementCap(r.pricing)
		v := settlementVector{Name: r.name, Pricing: pj, ConsumedQuantity: r.consumed}
		if r.want == nil {
			if setErr == nil {
				t.Fatalf("%s: SettleMeteredUsage accepted a row its author marked refused: %+v", r.name, got)
			}
			if r.capOK != (capErr == nil) {
				t.Fatalf("%s: MeteredSettlementCap err = %v, author expected cap ok = %v", r.name, capErr, r.capOK)
			}
			v.Error, v.CapError = true, capErr != nil
			out = append(out, v)
			continue
		}
		if setErr != nil || capErr != nil {
			t.Fatalf("%s: refused a row its author marked settleable: settle %v, cap %v", r.name, setErr, capErr)
		}
		want := settlementExpectation(*r.want)
		if have := settlementExpectation(got); have != want {
			t.Fatalf("%s: SettleMeteredUsage = %+v, author expected %+v", r.name, have, want)
		}
		if capAmount != want.CeilingAmount {
			t.Fatalf("%s: MeteredSettlementCap = %s, author expected %s", r.name, capAmount, want.CeilingAmount)
		}
		v.Expected = &want
		out = append(out, v)
	}
	return out
}

func TestGenerateSettlementVectors(t *testing.T) {
	doc := map[string]any{
		"default_estimate_tolerance_bps": DefaultEstimateToleranceBps,
		"vectors":                        buildSettlementVectors(t),
	}
	path := filepath.Join("testdata", "metered-settlement-vectors.json")
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
