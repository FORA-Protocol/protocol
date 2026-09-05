package connectserver_test

// Equivalence-gate suite for connectserver.EmitUnpopulatedJSONCodec()
// (yxaeb Step 2). This suite is a verbatim copy of
// internal/foracodec/jsoncodec_test.go PLUS the MarshalAppend case added by
// the architect's review finding (MEDIUM). All cases MUST fail today because
// connectserver.EmitUnpopulatedJSONCodec() and connectserver.WithEmitUnpopulated()
// do not exist yet — the compile error is the TDD-red state.
//
// The equivalence gate: every case here MUST pass against the SDK codec before
// internal/foracodec (and the two thin per-service forwarders) can be deleted.
// No case may be weakened or removed during implementation.
//
// Binding pin: snake_case names (UseProtoNames=true). The FORA wire is
// snake_case proto-JSON everywhere — the proto field names, the corpus, the
// generated clients, and this Connect codec. A stray UseProtoNames=false would
// split the naming and reintroduce camelCase; that is the regression this guards.

import (
	"strings"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"google.golang.org/protobuf/proto"
)

// TestSDKCodec_Marshal_EmitsZeroScalarsWithSnakeNames pins the two load-bearing
// marshal properties in one check: zero scalars present (EmitUnpopulated), and
// snake_case field names (UseProtoNames). SubscriptionQuotaInfo carries
// multi-word non-optional scalars (quota_limit, quota_used, ...) so the snake
// form is observable — a camelCase hump would leak as quotaLimit.
func TestSDKCodec_Marshal_EmitsZeroScalarsWithSnakeNames(t *testing.T) {
	t.Parallel()
	codec := foraserver.EmitUnpopulatedJSONCodec()

	got, err := codec.Marshal(&forav1.SubscriptionQuotaInfo{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"subscription_id":""`, `"quota_limit":0`, `"quota_used":0`, `"quota_remaining":0`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("marshal(SubscriptionQuotaInfo{}) = %s; want it to contain %s (EmitUnpopulated zero scalar, snake name)", got, want)
		}
	}
	for _, camel := range []string{"subscriptionId", "quotaLimit", "quotaUsed", "quotaRemaining"} {
		if strings.Contains(string(got), camel) {
			t.Errorf("marshal(SubscriptionQuotaInfo{}) = %s; camelCase name %q leaked — the wire is snake_case (UseProtoNames=true)", got, camel)
		}
	}
}

// TestSDKCodec_Marshal_OmitsUnsetExplicitPresence pins that proto3
// explicit-presence fields (optional scalars, message fields) stay ABSENT when
// unset even under EmitUnpopulated — the presence-based reads (unit_cost
// et al.) depend on absence meaning unset (ported from internal/foracodec
// TestMarshal_OmitsUnsetExplicitPresence).
func TestSDKCodec_Marshal_OmitsUnsetExplicitPresence(t *testing.T) {
	t.Parallel()
	codec := foraserver.EmitUnpopulatedJSONCodec()

	got, err := codec.Marshal(&forav1.Cost{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Cost.unit_cost is proto3 optional (explicit presence): unset => absent.
	if strings.Contains(string(got), "unit_cost") {
		t.Errorf("marshal(Cost{}) = %s; unset optional unit_cost must stay absent", got)
	}
}

// TestSDKCodec_Unmarshal_DiscardsUnknownFields pins the tolerant-reader half: a
// payload carrying an unknown field parses cleanly (dropped), so a newer peer
// does not break an older service (ported from internal/foracodec
// TestUnmarshal_DiscardsUnknownFields).
func TestSDKCodec_Unmarshal_DiscardsUnknownFields(t *testing.T) {
	t.Parallel()
	codec := foraserver.EmitUnpopulatedJSONCodec()

	var cost forav1.Cost
	payload := []byte(`{"amount":"1.50","currency":"USD","someFutureField":"x"}`)
	if err := codec.Unmarshal(payload, &cost); err != nil {
		t.Fatalf("unmarshal with unknown field: %v (DiscardUnknown must drop it)", err)
	}
	if cost.GetAmount() != "1.50" || cost.GetCurrency() != "USD" {
		t.Errorf("unmarshal = %+v; want amount=1.50 currency=USD", &cost)
	}
}

// TestSDKCodec_Unmarshal_RejectsZeroLengthPayload pins the loud empty-body
// rejection (ported from internal/foracodec TestUnmarshal_RejectsZeroLengthPayload).
func TestSDKCodec_Unmarshal_RejectsZeroLengthPayload(t *testing.T) {
	t.Parallel()
	codec := foraserver.EmitUnpopulatedJSONCodec()

	var cost forav1.Cost
	if err := codec.Unmarshal(nil, &cost); err == nil {
		t.Fatal("unmarshal(nil) = nil error; want zero-length payload rejected")
	}
}

// TestSDKCodec_MarshalRoundTrip pins that a populated message survives
// Marshal -> Unmarshal byte-for-byte at the field level (the codec pair is
// self-consistent) (ported from internal/foracodec TestMarshalRoundTrip).
func TestSDKCodec_MarshalRoundTrip(t *testing.T) {
	t.Parallel()
	codec := foraserver.EmitUnpopulatedJSONCodec()

	uc := "0.25"
	in := &forav1.Cost{Amount: "2.50", Currency: "EUR", UnitCost: &uc}
	raw, err := codec.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out forav1.Cost
	if err := codec.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !proto.Equal(in, &out) {
		t.Errorf("round-trip mismatch: in=%+v out=%+v", in, &out)
	}
}

// marshalAppender mirrors the connectrpc-internal marshalAppender extension
// interface so this test can assert MarshalAppend without importing the
// unexported connectrpc type. connect.Codec does not expose MarshalAppend
// publicly; the SDK codec's concrete type satisfies this interface.
type marshalAppender interface {
	MarshalAppend([]byte, any) ([]byte, error)
}

// TestSDKCodec_MarshalAppend_EmitsZeroScalarsWithSnakeNamesAndAppendsToPrefix
// pins MarshalAppend: (a) it emits zero scalars and snake_case names (same
// semantic contract as Marshal); (b) it appends the JSON bytes to a non-empty
// dst prefix rather than replacing it — the connect.Codec MarshalAppend
// contract requires append-to-dst semantics, not overwrite. This case was added
// by the architect's review (MEDIUM finding: equivalence gate was incomplete
// because MarshalAppend has its own implementation path in the app codec).
func TestSDKCodec_MarshalAppend_EmitsZeroScalarsWithSnakeNamesAndAppendsToPrefix(t *testing.T) {
	t.Parallel()
	raw := foraserver.EmitUnpopulatedJSONCodec()
	// MarshalAppend is not part of the public connect.Codec interface; the
	// concrete type implements it. Type-assert to the local marshalAppender
	// mirror so this guard exercises the real method path.
	codec, ok := raw.(marshalAppender)
	if !ok {
		t.Fatal("EmitUnpopulatedJSONCodec() does not implement MarshalAppend — interface regression")
	}

	prefix := []byte(`SENTINEL`)
	got, err := codec.MarshalAppend(prefix, &forav1.SubscriptionQuotaInfo{})
	if err != nil {
		t.Fatalf("MarshalAppend: %v", err)
	}

	// Append semantics: the sentinel must still be at the start.
	if !strings.HasPrefix(string(got), "SENTINEL") {
		t.Errorf("MarshalAppend result = %q; must start with the dst prefix %q (append, not overwrite)", got, prefix)
	}

	// The appended JSON must still honor EmitUnpopulated + snake_case.
	appended := string(got[len(prefix):])
	for _, want := range []string{`"subscription_id":""`, `"quota_limit":0`} {
		if !strings.Contains(appended, want) {
			t.Errorf("MarshalAppend appended portion = %q; must contain %q (EmitUnpopulated zero scalar, snake name)", appended, want)
		}
	}
	if strings.Contains(appended, "quotaLimit") {
		t.Errorf("MarshalAppend appended portion = %q; camelCase leaked — must be snake_case (UseProtoNames=true)", appended)
	}
}
