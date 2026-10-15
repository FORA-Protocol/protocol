package connectserver_test

// A refusal for a missing component, or for a form the Web Bot Auth profile does
// not accept, answers 401 with an Accept-Signature field naming what the verifier
// requires (WG-00 §5.3), so a WBA library can add the components and sign again.
// A signature that is well formed but fails carries none.

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func TestReject_AcceptSignatureNamesWhatTheVerifierRequires(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	stranger := newServerFixture(t)
	srv := f.serve(t, newCountingReplayStore())
	const procedure = "/fora.v1.ExchangeService/DiscoverResources"
	body := []byte(`{}`)
	now := time.Now().Unix()

	post := func(t *testing.T, sign func(*http.Request) error) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+procedure, bytes.NewReader(body))
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
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}
	signAs := func(signer helpers.Signer) func(*http.Request) error {
		return func(req *http.Request) error {
			return helpers.SignRequest(context.Background(), req, body, signer,
				helpers.SignOptions{Created: now, Expires: now + 60, SignatureAgent: "https://agent.example"})
		}
	}
	for _, tc := range []struct {
		name       string
		sign       func(*http.Request) error
		wantAccept bool
	}{
		{"unsigned", nil, true},
		{"the v1.0.8 bare Signature-Agent", func(req *http.Request) error {
			if err := signAs(f.signer)(req); err != nil {
				return err
			}
			req.Header.Set(helpers.SignatureAgentHeader, "https://agent.example")
			return nil
		}, true},
		{"a key the verifier does not know", signAs(stranger.signer), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := post(t, tc.sign)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			got := resp.Header.Get(helpers.AcceptSignatureHeader)
			if tc.wantAccept && got != helpers.AcceptSignature(false) {
				t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
			}
			if !tc.wantAccept && got != "" {
				t.Errorf("Accept-Signature = %q on a refusal that a re-signature cannot fix", got)
			}
		})
	}
}
