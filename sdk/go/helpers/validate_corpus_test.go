package helpers_test

import (
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/proto"

	// conformance owns the contract package list (contract.go), resolves a corpus
	// case's bare message name against it, and, by importing the generated packages,
	// registers their types so a case for any contract package resolves here.
	// Test-only dependency.
	"github.com/FORA-Protocol/protocol/conformance"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

type corpusCase struct {
	ID      string          `json:"id"`
	Message string          `json:"message"`
	Valid   bool            `json:"valid"`
	Rules   []string        `json:"rules"`
	JSON    json.RawMessage `json:"json"`
}

func loadCorpusFile(t *testing.T, path string) []corpusCase {
	t.Helper()
	var cs []corpusCase
	if err := vectorio.Load(path, &cs); err != nil {
		t.Fatalf("%v (run 'go run ./conformance/corpusgen')", err)
	}
	if len(cs) == 0 {
		t.Fatalf("%s is empty", path)
	}
	return cs
}

func unmarshalCase(t *testing.T, c corpusCase) proto.Message {
	t.Helper()
	m, err := conformance.UnmarshalContractMessage(c.Message, c.JSON)
	if err != nil {
		t.Fatalf("%s: %v", c.ID, err)
	}
	return m
}

// TestValidate_matchesCorpusVerdict proves the Go L1 validator reaches the SAME
// verdict as the protovalidate oracle on every field-level corpus case — i.e.
// helpers.Validate IS the requirement's executable form, no drift.
func TestValidate_matchesCorpusVerdict(t *testing.T) {
	for _, c := range loadCorpusFile(t, "../../../conformance/corpus/cases.json") {
		t.Run(c.ID, func(t *testing.T) {
			err := helpers.Validate(unmarshalCase(t, c))
			if c.Valid && err != nil {
				t.Errorf("corpus VALID but Validate rejects: %v", err)
			}
			if !c.Valid && err == nil {
				t.Errorf("corpus INVALID but Validate accepts")
			}
		})
	}
}

// TestValidate_enforcesCrossFieldCEL is the cross-field guardrail: every mutant
// in crossfield.json must be rejected by the L1 validator, with the recorded
// message-CEL rule id present. This is the gap field-level Zod/Pydantic miss; the
// Go L1 closes it via protovalidate, and this pins it to the oracle.
func TestValidate_enforcesCrossFieldCEL(t *testing.T) {
	cases := loadCorpusFile(t, "../../../conformance/corpus/crossfield.json")
	if len(cases) < 7 {
		t.Fatalf("expected >=7 cross-field mutants, got %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.Valid {
				t.Fatalf("crossfield case %s should be invalid", c.ID)
			}
			err := helpers.Validate(unmarshalCase(t, c))
			if err == nil {
				t.Fatalf("cross-field mutant %s was accepted (rule %v not enforced)", c.ID, c.Rules)
			}
			got := helpers.ValidationRuleIDs(err)
			for _, want := range c.Rules {
				if !contains(got, want) {
					t.Errorf("%s: expected rule %q in %v", c.ID, want, got)
				}
			}
		})
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
