package connectserver_test

// A refusal for a missing component, or for a form the Web Bot Auth profile does
// not accept, answers 401 with an Accept-Signature field naming what the verifier
// requires (-01 §5.3), so a WBA library can add the components and sign again.
// A signature that is well formed but fails carries none.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func TestReject_AcceptSignatureNamesWhatTheVerifierRequires(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	stranger := newServerFixture(t)
	p := newRejectProbe(t, f)
	for _, tc := range []struct {
		name       string
		sign       func(*http.Request) error
		wantAccept bool
	}{
		{"unsigned", nil, true},
		{"the v1.0.8 bare Signature-Agent", rewriteAgent(p.signAs(f.signer), "https://agent.example"), true},
		{"a key the verifier does not know", p.signAs(stranger.signer), false},
		// Web Bot Auth -01: a covered member that carries a parameter is ignored,
		// which leaves the signature naming no directory, and a URL other than the
		// well-known key directory is refused. Both are fixable by signing again.
		// The member is rewritten after signing; the member rule runs before the
		// Ed25519 check, so Accept-Signature proves which rule refused it.
		{
			"a member carrying a parameter",
			rewriteAgent(p.signAs(f.signer), `sig1="`+wellKnownAgent+`";type=directory`), true,
		},
		{"a key set at another path", rewriteAgent(p.signAs(f.signer), `sig1="https://agent.example/jwks.json"`), true},
		{"a query", rewriteAgent(p.signAs(f.signer), `sig1="`+wellKnownAgent+`?v=1"`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := p.post(t, tc.sign)
			assertAcceptSignature(t, resp, tc.wantAccept)
		})
	}
}

// rejectProbe posts signed requests to one DiscoverResources endpoint.
type rejectProbe struct {
	url  string
	body []byte
	now  int64
}

func newRejectProbe(t *testing.T, f serverFixture) rejectProbe {
	t.Helper()
	srv := f.serve(t, newCountingReplayStore())
	return rejectProbe{
		url:  srv.URL + "/fora.v1.ExchangeService/DiscoverResources",
		body: []byte(`{}`),
		now:  time.Now().Unix(),
	}
}

// signAs signs as signer with the SDK signer, naming https://agent.example.
func (p rejectProbe) signAs(signer helpers.Signer) func(*http.Request) error {
	return func(req *http.Request) error {
		return helpers.SignRequest(context.Background(), req, p.body, signer,
			helpers.SignOptions{Created: p.now, Expires: p.now + 60, SignatureAgent: "https://agent.example"})
	}
}

// probeResponse is what a test reads from the server's answer.
type probeResponse struct {
	status int
	accept string
	body   []byte
}

// post sends the probe's request, signed by sign unless it is nil, and reads the
// answer.
func (p rejectProbe) post(t *testing.T, sign func(*http.Request) error) probeResponse {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, p.url, bytes.NewReader(p.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sign != nil {
		if err := sign(req); err != nil {
			t.Fatal(err)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return probeResponse{status: resp.StatusCode, accept: resp.Header.Get(helpers.AcceptSignatureHeader), body: body}
}

// assertAcceptSignature requires a 401 that carries the profile's Accept-Signature,
// or, for a refusal a re-signature cannot fix, none.
func assertAcceptSignature(t *testing.T, resp probeResponse, wantAccept bool) {
	t.Helper()
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.status)
	}
	got := resp.accept
	if wantAccept && got != helpers.AcceptSignature(false) {
		t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
	}
	if !wantAccept && got != "" {
		t.Errorf("Accept-Signature = %q on a refusal that a re-signature cannot fix", got)
	}
}

// wellKnownAgent is the key directory URL a Web Bot Auth -01 signer names.
const wellKnownAgent = "https://agent.example/.well-known/http-message-signatures-directory"

// rewriteAgent signs with sign and then replaces the Signature-Agent field.
func rewriteAgent(sign func(*http.Request) error, value string) func(*http.Request) error {
	return func(req *http.Request) error {
		if err := sign(req); err != nil {
			return err
		}
		req.Header.Set(helpers.SignatureAgentHeader, value)
		return nil
	}
}

// TestVerify_ReachesTheOriginWithTheKeyDirectory: a request naming the well-known
// key directory URL, and one naming the bare origin, both reach the origin service
// with the same verified directory.
func TestVerify_ReachesTheOriginWithTheKeyDirectory(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	p := newRejectProbe(t, f)
	// Both forms are written as the well-known URL, so each signature carries its
	// own nonce or the second would be refused as a replay of the first.
	for i, agent := range []string{wellKnownAgent, "https://agent.example"} {
		opts := helpers.SignOptions{Created: p.now, Expires: p.now + 60, SignatureAgent: agent, Nonce: fmt.Sprintf("n%d", i)}
		sign := func(req *http.Request) error {
			return helpers.SignRequest(context.Background(), req, p.body, f.signer, opts)
		}
		if resp := p.post(t, sign); resp.status != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", agent, resp.status)
		}
	}
	if got := f.origin.hitCount(); got != 2 {
		t.Errorf("origin hits = %d, want 2", got)
	}
}
