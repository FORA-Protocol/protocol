package connect_test

// WithPeerTransport, the injection point of the legs that dial a peer another party
// named: the injected round-tripper is dialed as given, and the https-only check
// stays above it.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
)

// errPeerRecorded is what peerRecorder answers, so a test can tell its own
// transport's answer from any refusal the client makes first.
var errPeerRecorded = errors.New("peer transport recorded the request")

// peerRecorder records the URL of each request it is handed and answers none.
type peerRecorder struct{ seen []string }

func (p *peerRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	p.seen = append(p.seen, req.URL.String())
	return nil, errPeerRecorded
}

// reportThrough sends a usage report for issuer.example, whose manifest is
// answered with endpoint, through a client dialing rt.
func reportThrough(t *testing.T, rt http.RoundTripper, endpoint string) error {
	t.Helper()
	sig := newSigningFixture(t)
	client := foraconnect.NewClient("https://home.invalid",
		foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"),
		foraconnect.WithEndpointResolver(fixedEndpoint{endpoint: endpoint}),
		foraconnect.WithPeerTransport(rt),
	)
	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      "issuer.example",
		TransactionId: "txn-1",
	})
	return err
}

func TestReportUsage_DialsAnInjectedPeerTransportAsGiven(t *testing.T) {
	rt := &peerRecorder{}
	err := reportThrough(t, rt, "https://issuer.example")
	if !errors.Is(err, errPeerRecorded) {
		t.Fatalf("error = %v, want the injected transport's own answer", err)
	}
	if len(rt.seen) != 1 || !strings.HasPrefix(rt.seen[0], "https://issuer.example/") {
		t.Errorf("injected transport saw %q, want one request to https://issuer.example/", rt.seen)
	}
}

// A plaintext endpoint is refused before the injected transport sees the signed
// call: the transport decides where a request goes, never whether a signature may
// travel over plaintext.
func TestReportUsage_RefusesPlaintextAboveAnInjectedPeerTransport(t *testing.T) {
	rt := &peerRecorder{}
	err := reportThrough(t, rt, "http://issuer.example")
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("error = %v, want a CallError from the scheme guard", err)
	}
	if len(rt.seen) != 0 {
		t.Errorf("injected transport saw %q; a plaintext endpoint must never reach it", rt.seen)
	}
}
