package connect_test

// The ADR-019 ErrorDetail↔Connect round-trip, split by direction: AsConnectError
// (emit) lives in the SERVER binding sdk/go/connectserver, ErrorDetailFrom (read)
// lives in the CLIENT binding sdk/go/connect; the neutral *forav1.ErrorDetail
// builders and the Reason accessor stay in sdk/go/helpers. This suite exercises the
// full loop — a server-emitted typed error detail (AsConnectError) read back and
// branched on by a client (ErrorDetailFrom + helpers.Reason) — assertions unchanged
// across the connect→(connect + connectserver) split.

import (
	"errors"
	"testing"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func TestErrorDetail_transactionDenialRoundTrip(t *testing.T) {
	detail := helpers.TransactionDenialDetail(
		"fora.v1.ExchangeService", "balance too low",
		forav1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE)

	cerr := foraserver.AsConnectError(connectrpc.CodeFailedPrecondition, detail)
	if connectrpc.CodeOf(cerr) != connectrpc.CodeFailedPrecondition {
		t.Errorf("code = %v", connectrpc.CodeOf(cerr))
	}

	got, ok := foraconnect.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatal("ErrorDetailFrom returned false")
	}
	if got.GetMessage() != "balance too low" || got.GetDomain() != "fora.v1.ExchangeService" {
		t.Errorf("envelope = %q %q", got.GetMessage(), got.GetDomain())
	}
	reason, ok := helpers.Reason(got).(forav1.DenialReason)
	if !ok || reason != forav1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE {
		t.Errorf("reason = %v (%T)", helpers.Reason(got), helpers.Reason(got))
	}
}

func TestErrorDetail_retrievalAuthFailureRoundTrip(t *testing.T) {
	detail := helpers.RetrievalAuthFailureDetail("fora.v1.Edge", "pop mismatch",
		forav1.RetrievalAuthFailureReason(1)) // first defined, non-zero
	cerr := foraserver.AsConnectError(connectrpc.CodePermissionDenied, detail)
	got, ok := foraconnect.ErrorDetailFrom(cerr)
	if !ok {
		t.Fatal("extract failed")
	}
	if _, ok := helpers.Reason(got).(forav1.RetrievalAuthFailureReason); !ok {
		t.Errorf("reason type = %T, want RetrievalAuthFailureReason", helpers.Reason(got))
	}
}

func TestErrorDetailFrom_nonConnectError(t *testing.T) {
	if _, ok := foraconnect.ErrorDetailFrom(errors.New("plain")); ok {
		t.Error("plain error should not yield a detail")
	}
}

func TestReason_unset(t *testing.T) {
	if r := helpers.Reason(&forav1.ErrorDetail{Message: "no reason"}); r != nil {
		t.Errorf("Reason of detail without oneof = %v, want nil", r)
	}
}

func TestErrorDetail_clientBranchesOnTypedReason(t *testing.T) {
	// Demonstrates the intended client usage: branch on the enum, not a string.
	detail := helpers.TransactionDenialDetail("d", "rate limited",
		forav1.DenialReason_DENIAL_REASON_RATE_LIMITED)
	cerr := foraserver.AsConnectError(connectrpc.CodeResourceExhausted, detail)

	ed, _ := foraconnect.ErrorDetailFrom(cerr)
	var handled bool
	switch r := helpers.Reason(ed).(type) {
	case forav1.DenialReason:
		if r == forav1.DenialReason_DENIAL_REASON_RATE_LIMITED {
			handled = true
		}
	}
	if !handled {
		t.Error("expected to branch on DenialReason_RATE_LIMITED")
	}
}
