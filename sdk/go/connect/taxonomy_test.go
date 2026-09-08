package connect_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// The failure taxonomy, and the branches of it a caller is told to act on.
//
// The two vocabularies are separate types over separate tiers, bridged in one
// place. Nothing enforced that the tokens they share stay the same word, and the
// classifications a caller is told to branch on had no test at all — which is how
// a transient failure could have been reported as a permanent verdict without
// anything going red.

// The shared tokens must stay identical across the two tiers. A caller that logs
// a reason and greps for it should not have to know which tier produced it, and
// the bridge between them maps the classes 1:1 with nothing else holding the
// words together.
func TestFailureTokens_AgreeAcrossTheTwoTiers(t *testing.T) {
	pairs := []struct {
		call  foraconnect.CallErrorKind
		fetch resolvers.FetchFailure
	}{
		{foraconnect.CallRefused, resolvers.FetchRefused},
		{foraconnect.CallUnreachable, resolvers.FetchUnreachable},
		{foraconnect.CallTooLarge, resolvers.FetchTooLarge},
		{foraconnect.CallNotSignable, resolvers.FetchNotSignable},
		{foraconnect.CallMalformed, resolvers.FetchMalformed},
	}
	for _, p := range pairs {
		if got, want := p.call.String(), p.fetch.String(); got != want {
			t.Errorf("token drift: CallErrorKind %q vs FetchFailure %q", got, want)
		}
	}
	// The value outside either set renders the same way too, so an unmapped
	// classification never prints a bare integer.
	if got := foraconnect.CallErrorKind(99).String(); got != "unknown" {
		t.Errorf("unnamed kind = %q, want \"unknown\"", got)
	}
	if got := resolvers.FetchFailure(99).String(); got != "unknown" {
		t.Errorf("unnamed failure = %q, want \"unknown\"", got)
	}
}

// A transient failure to reach the manifest is UNREACHABLE, not a refusal to
// send. The distinction is the whole point of the classification: a caller
// following the documented handling for a refusal would drop a usage report for
// good over a momentary outage.
func TestReportUsage_TransientResolveFailureIsUnreachable(t *testing.T) {
	// A closed port: the manifest fetch fails at the transport, which is exactly
	// the shape of a DNS blip or a restarting Exchange.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	domain := strings.TrimPrefix(dead.URL, "http://")
	dead.Close()

	sig := newSigningFixture(t)
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
	})
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != foraconnect.CallUnreachable {
		t.Errorf("kind = %v, want CallUnreachable — a transport failure is retryable, "+
			"and reporting it as a refusal tells a caller to give up", cerr.Kind)
	}
}

// An Exchange that answers the manifest but advertises no endpoint is a VERDICT,
// not a transport failure: it was reached, and it has nothing to offer. The
// opposite branch of the same classification.
func TestReportUsage_NoAdvertisedEndpointIsNotSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ver":"` + helpers.WellKnownManifestVersion + `"}`)) // a manifest with no endpoint
	}))
	defer srv.Close()

	sig := newSigningFixture(t)
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      strings.TrimPrefix(srv.URL, "http://"),
		TransactionId: "txn-1",
	})
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != foraconnect.CallNotSent {
		t.Errorf("kind = %v, want CallNotSent — the Exchange answered and advertises nothing", cerr.Kind)
	}
	if !errors.Is(err, resolvers.ErrNoEndpoint) {
		t.Error("the resolver's sentinel must stay reachable through the classification")
	}
}

// An Exchange whose manifest carries a document version this reader does not
// accept is a VERDICT too: the manifest was fetched and parsed, and the reader
// refuses to act on it. Nothing about a retry changes the version served.
func TestReportUsage_UnacceptedManifestVersionIsNotSent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ver":"2.0","endpoint":"` + "http://" + "exchange.invalid" + `"}`))
	}))
	defer srv.Close()

	sig := newSigningFixture(t)
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      strings.TrimPrefix(srv.URL, "http://"),
		TransactionId: "txn-1",
	})
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != foraconnect.CallNotSent {
		t.Errorf("kind = %v, want CallNotSent — the manifest was read and its version refused", cerr.Kind)
	}
	if !errors.Is(err, resolvers.ErrManifestVersionRefused) {
		t.Error("the resolver's version sentinel must stay reachable through the classification")
	}
}

// A peer that refuses because the response exceeds the read cap surfaces as
// CallTooLarge rather than as a generic refusal, so a caller can tell "raise your
// budget" from "the Exchange said no".
func TestSendError_ResourceExhaustedIsTooLarge(t *testing.T) {
	sig := newSigningFixture(t)
	domain, _ := loopbackManifestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"code":"resource_exhausted","message":"too big"}`))
	}))

	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer))...)

	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
	})
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != foraconnect.CallTooLarge {
		t.Errorf("kind = %v, want CallTooLarge for a resource-exhausted peer", cerr.Kind)
	}
	// The Connect error stays reachable underneath, so a caller that wants the
	// code rather than the SDK's class can still get it.
	var connErr *connectrpc.Error
	if !errors.As(err, &connErr) {
		t.Error("the Connect error must stay reachable through the wrapper")
	}
}

// A caller that cancels its own context has not been refused by anyone.
// connect-go stamps CodeCanceled on a locally cancelled call, and reporting that
// as CallRefused would tell the caller the Exchange declined a request the
// Exchange may never have finished reading — a final verdict, invented locally,
// about a peer that said nothing.
func TestSendError_CallerCancellationIsNotARefusal(t *testing.T) {
	sig := newSigningFixture(t)
	release, reached := make(chan struct{}), make(chan struct{})
	var once sync.Once
	domain, _ := loopbackManifestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		once.Do(func() { close(reached) })
		<-release
	}))
	// Registered AFTER the server's own cleanup so it runs BEFORE it: Close blocks
	// on the in-flight handler, which is parked on release until this fires.
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-reached // the RPC is on the wire; nothing has answered it
		cancel()
	}()

	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer))...)
	_, err := client.ReportUsage(ctx, &forav1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
	})

	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != foraconnect.CallUnreachable {
		t.Errorf("kind = %v, want CallUnreachable — the caller gave up; the peer did not refuse", cerr.Kind)
	}
}
