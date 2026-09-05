package connectserver_test

// ClassifyReject is the SDK-owned single source of verify-gate reject
// classification: each meaningful cause maps to a distinct, stable audit token,
// keyed off the gate's own sentinels — so no consumer re-derives the mapping.

import (
	"errors"
	"fmt"
	"testing"

	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func TestClassifyReject_DistinctReasonPerSentinel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		err   error
		want  foraserver.RejectReason
		token string
	}{
		{"hop budget", helpers.ErrTooManyHops, foraserver.ReasonHopBudget, "hop_budget"},
		{"replay", foraserver.ErrReplayed, foraserver.ReasonReplay, "replay"},
		{"broken chain", helpers.ErrBrokenSignatureChain, foraserver.ReasonBrokenChain, "broken_chain"},
		{"signature", helpers.ErrSignatureVerify, foraserver.ReasonSignature, "signature"},
		{"unknown", errors.New("boom"), foraserver.ReasonSignature, "signature"},
		{"wrapped replay", fmt.Errorf("gate: %w", foraserver.ErrReplayed), foraserver.ReasonReplay, "replay"},
		{"wrapped chain", fmt.Errorf("x: %w", helpers.ErrBrokenSignatureChain), foraserver.ReasonBrokenChain, "broken_chain"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := foraserver.ClassifyReject(tc.err)
			if got != tc.want {
				t.Fatalf("ClassifyReject(%v) = %v, want %v", tc.err, got, tc.want)
			}
			if got.String() != tc.token {
				t.Fatalf("%v.String() = %q, want %q", got, got.String(), tc.token)
			}
		})
	}
}
