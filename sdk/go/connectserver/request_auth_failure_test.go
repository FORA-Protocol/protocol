package connectserver_test

// The typed reason a request-signature refusal carries. The contract tells a client
// to branch on ErrorDetail's typed reason, never on the message, so an Unauthenticated
// refusal from the verify seam carries a request_auth_failure block whose reason is
// one of three: SIGNATURE_MISSING, SIGNATURE_INVALID or SIGNATURE_STALE.
//
// The integration test drives a real refusal for each reason: a real ExchangeService
// handler behind the SDK server face, served over httptest, called by a real client,
// with the reason read back through the client's typed reading (ErrorDetailFrom, then
// helpers.Reason). The table test below it covers the mapping one sentinel at a time
// through the exported writer, because several sentinels share each reason and only
// one of them per reason is cheap to provoke end to end.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

const (
	reasonMissing = forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_MISSING
	reasonInvalid = forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID
	reasonStale   = forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_STALE
)

// requestAuthReasonOf reads the typed reason off a refused call the way a client
// does: ErrorDetailFrom, then helpers.Reason, type-asserted to the enum. It fails the
// test when the refusal carries no detail or a reason from another family.
func requestAuthReasonOf(t *testing.T, err error) forav1.RequestAuthFailureReason {
	t.Helper()
	if err == nil {
		t.Fatal("the call was not refused")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("code = %v, want unauthenticated (err=%v)", got, err)
	}
	detail, ok := foraconnect.ErrorDetailFrom(err)
	if !ok {
		t.Fatalf("the refusal carries no ErrorDetail: %v", err)
	}
	reason, ok := helpers.Reason(detail).(forav1.RequestAuthFailureReason)
	if !ok {
		t.Fatalf("reason = %v (%T), want a RequestAuthFailureReason", helpers.Reason(detail), helpers.Reason(detail))
	}
	return reason
}

// headerTransport sets fixed headers on every request, for the one refusal no SDK
// client produces: a signature header that does not parse.
type headerTransport struct {
	headers map[string]string
}

func (h headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// TestRequestAuthFailure_EachReasonFromARealRefusal sends one request per reason
// through the SDK server face and reads the reason back through the Go client. Two
// requests share each of MISSING and STALE on purpose: the reason names the remedy,
// so two different failed checks with one remedy must read the same.
func TestRequestAuthFailure_EachReasonFromARealRefusal(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	stranger := newServerFixture(t) // a signer the fixture's resolver does not know
	now := time.Now()
	window := func(at time.Time) foraconnect.ClientOption {
		return foraconnect.WithSignWindow(core.ClockWindow(func() time.Time { return at }, 5*time.Minute))
	}

	cases := []struct {
		name   string
		replay core.ReplayStore
		call   func(srvURL string) error
		want   forav1.RequestAuthFailureReason
	}{
		{
			name:   "unsigned request",
			replay: newCountingReplayStore(),
			call: func(u string) error {
				_, err := foraconnect.NewClient(u).Discover(context.Background(), &forav1.ResourceQuery{})
				return err
			},
			want: reasonMissing,
		},
		{
			name:   "signature headers that do not parse",
			replay: newCountingReplayStore(),
			call: func(u string) error {
				hc := &http.Client{Transport: headerTransport{headers: map[string]string{
					"Signature-Input": "sig1=(((",
					"Signature":       "sig1=:AAAA:",
				}}}
				_, err := forav1connect.NewExchangeServiceClient(hc, u).
					DiscoverResources(context.Background(), connectrpc.NewRequest(&forav1.ResourceQuery{}))
				return err
			},
			want: reasonMissing,
		},
		{
			name:   "signed by a key the resolver does not know",
			replay: newCountingReplayStore(),
			call: func(u string) error {
				_, err := foraconnect.NewClient(u, foraconnect.WithSigner(stranger.signer), foraconnect.WithSignatureAgent("https://agent.example")).
					Discover(context.Background(), &forav1.ResourceQuery{})
				return err
			},
			want: reasonInvalid,
		},
		{
			name:   "expired signature",
			replay: newCountingReplayStore(),
			call: func(u string) error {
				_, err := foraconnect.NewClient(u, foraconnect.WithSigner(f.signer), foraconnect.WithSignatureAgent("https://agent.example"), window(now.Add(-time.Hour))).
					Discover(context.Background(), &forav1.ResourceQuery{})
				return err
			},
			want: reasonStale,
		},
		{
			name:   "signature created in the future",
			replay: newCountingReplayStore(),
			call: func(u string) error {
				_, err := foraconnect.NewClient(u, foraconnect.WithSigner(f.signer), foraconnect.WithSignatureAgent("https://agent.example"), window(now.Add(time.Hour))).
					Discover(context.Background(), &forav1.ResourceQuery{})
				return err
			},
			want: reasonStale,
		},
		{
			name:   "replayed signature",
			replay: alwaysReplayStore{},
			call: func(u string) error {
				_, err := foraconnect.NewClient(u, foraconnect.WithSigner(f.signer), foraconnect.WithSignatureAgent("https://agent.example")).
					Discover(context.Background(), &forav1.ResourceQuery{})
				return err
			},
			want: reasonStale,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			origin := &echoExchange{}
			srv := serveHandler(t, origin, f.resolver, tc.replay)

			if got := requestAuthReasonOf(t, tc.call(srv.URL)); got != tc.want {
				t.Errorf("reason = %v, want %v", got, tc.want)
			}
			if origin.hitCount() != 0 {
				t.Errorf("the origin ran %d times on a refused request", origin.hitCount())
			}
		})
	}
}

// TestRequestAuthFailure_ASignedRequestCarriesNoRefusal is the control for the table
// above: the same fixture, signed correctly, is answered by the origin. Without it a
// fixture that refused everything would pass every row.
func TestRequestAuthFailure_ASignedRequestCarriesNoRefusal(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	srv := f.serve(t, newCountingReplayStore())

	_, err := foraconnect.NewClient(srv.URL, foraconnect.WithSigner(f.signer), foraconnect.WithSignatureAgent("https://agent.example")).
		Discover(context.Background(), &forav1.ResourceQuery{})
	if err != nil {
		t.Fatalf("a correctly signed request was refused: %v", err)
	}
	if f.origin.hitCount() != 1 {
		t.Fatalf("origin ran %d times, want 1", f.origin.hitCount())
	}
}

// TestRequestAuthFailure_EverySentinelMapsToOneReason covers the mapping one sentinel
// at a time, wrapped the way the verifier wraps them, through the exported writer and
// the generated client. The last rows are the default arm: a sentinel this mapping
// does not name, and an error nobody has defined, both read INVALID.
func TestRequestAuthFailure_EverySentinelMapsToOneReason(t *testing.T) {
	t.Parallel()
	wrap := func(sentinel error) error { return fmt.Errorf("%w: detail the reason must not carry", sentinel) }
	cases := []struct {
		name string
		err  error
		want forav1.RequestAuthFailureReason
	}{
		{"missing Signature-Input", helpers.ErrMissingSignatureInput, reasonMissing},
		{"missing Signature", helpers.ErrMissingSignature, reasonMissing},
		{"malformed Signature-Input", wrap(helpers.ErrMalformedSignatureInput), reasonMissing},
		{"expired", wrap(helpers.ErrExpired), reasonStale},
		{"created in the future", wrap(helpers.ErrFutureCreated), reasonStale},
		{"replayed", foraserver.ErrReplayed, reasonStale},
		{"bad signature", helpers.ErrSignatureVerify, reasonInvalid},
		{"content-digest mismatch", helpers.ErrDigestMismatch, reasonInvalid},
		{"missing Content-Digest", helpers.ErrMissingContentDigest, reasonInvalid},
		{"required covered component missing", wrap(helpers.ErrMissingRequiredComponent), reasonInvalid},
		{"unsupported algorithm", wrap(helpers.ErrUnsupportedAlgorithm), reasonInvalid},
		{"unresolvable key", wrap(helpers.ErrUnknownKey), reasonInvalid},
		{"missing created", helpers.ErrMissingCreated, reasonInvalid},
		{"missing expires", helpers.ErrMissingExpires, reasonInvalid},
		{"lifetime past the clamp", wrap(helpers.ErrSignatureLifetimeTooLong), reasonInvalid},
		{"broken signature chain", wrap(helpers.ErrBrokenSignatureChain), reasonInvalid},
		{"an error nobody defined", errors.New("replay store unreachable"), reasonInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				foraserver.WriteReject(w, foraserver.RejectCode(tc.err), tc.err)
			}))
			t.Cleanup(srv.Close)

			_, err := forav1connect.NewExchangeServiceClient(srv.Client(), srv.URL).
				DiscoverResources(context.Background(), connectrpc.NewRequest(&forav1.ResourceQuery{}))
			if got := requestAuthReasonOf(t, err); got != tc.want {
				t.Errorf("reason = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRequestAuthFailure_OnlyAnUnauthenticatedRefusalCarriesTheReason pins the
// negative side: a resource limit, and a code outside the two the writer models,
// carry no detail at all. A request_auth_failure block on a hop-budget refusal would
// send a correctly signed caller to re-sign a request whose only fault is its length.
func TestRequestAuthFailure_OnlyAnUnauthenticatedRefusalCarriesTheReason(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		code connectrpc.Code
		err  error
	}{
		{"hop budget", connectrpc.CodeResourceExhausted, helpers.ErrTooManyHops},
		{"body past the read cap", connectrpc.CodeResourceExhausted, &http.MaxBytesError{Limit: 1}},
		{"a code the writer does not model", connectrpc.CodeInvalidArgument, helpers.ErrMissingSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				foraserver.WriteReject(w, tc.code, tc.err)
			}))
			t.Cleanup(srv.Close)

			_, err := forav1connect.NewExchangeServiceClient(srv.Client(), srv.URL).
				DiscoverResources(context.Background(), connectrpc.NewRequest(&forav1.ResourceQuery{}))
			if err == nil {
				t.Fatal("the call was not refused")
			}
			if detail, ok := foraconnect.ErrorDetailFrom(err); ok {
				t.Errorf("a %v refusal carries %v; only a signature refusal has a reason block", tc.code, detail)
			}
		})
	}
}

// TestRequestAuthFailure_EnvelopeIsWhatConnectGoWrites holds the restated details
// encoding to connect-go's own. The writer cannot call connect-go's encoder, which is
// unexported, and its ErrorWriter would answer 429 where this binding answers 413. So
// the envelope is compared against what ErrorWriter emits for the same error and the
// same detail. A drift in either the binary value or the debug rendering, the field
// the JSON-only SDKs read, fails here.
func TestRequestAuthFailure_EnvelopeIsWhatConnectGoWrites(t *testing.T) {
	t.Parallel()
	refusal := fmt.Errorf("%w: @target-uri", helpers.ErrMissingRequiredComponent)

	ours := httptest.NewRecorder()
	foraserver.WriteReject(ours, connectrpc.CodeUnauthenticated, refusal)

	want := connectrpc.NewError(connectrpc.CodeUnauthenticated, refusal)
	if err := foraserver.AttachDetail(want, helpers.RequestAuthFailureDetail("", refusal.Error(), reasonInvalid)); err == nil {
		t.Fatal("AttachDetail returned nil")
	}
	req := httptest.NewRequest(http.MethodPost, "/fora.v1.ExchangeService/DiscoverResources", strings.NewReader("{}"))
	req.Header.Set("Content-Type", helpers.ContentTypeJSON)
	req.Header.Set(helpers.ConnectProtocolVersionHeader, helpers.ConnectProtocolVersion)
	theirs := httptest.NewRecorder()
	if err := connectrpc.NewErrorWriter().Write(theirs, req, want); err != nil {
		t.Fatalf("connect-go ErrorWriter: %v", err)
	}

	var gotBody, wantBody map[string]any
	if err := json.Unmarshal(ours.Body.Bytes(), &gotBody); err != nil {
		t.Fatalf("our envelope is not JSON: %v", err)
	}
	if err := json.Unmarshal(theirs.Body.Bytes(), &wantBody); err != nil {
		t.Fatalf("connect-go's envelope is not JSON: %v", err)
	}
	if !reflect.DeepEqual(gotBody, wantBody) {
		t.Errorf("envelope differs from connect-go's:\n ours   %s\n theirs %s", ours.Body.Bytes(), theirs.Body.Bytes())
	}
}
