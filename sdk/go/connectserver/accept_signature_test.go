package connectserver_test

// A refusal for a missing component, or for a form the Web Bot Auth profile does
// not accept, answers 401 with an Accept-Signature field naming what the verifier
// requires (WG-01 §5.3), so a WBA library can add the components and sign again.
// A signature that is well formed but fails carries none.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := p.post(t, tc.sign)
			assertAcceptSignature(t, resp, tc.wantAccept)
		})
	}
}

// TestReject_TheMessageNamesTheSignatureAgentRule: under WG-01 a covered member
// that carries a parameter is ignored, which leaves the signature naming no
// directory, and a URL other than the well-known key directory is refused. Both
// are fixable by signing again, so both carry the same Accept-Signature, which
// cannot say which rule refused the member; the 401 message names it. The member
// is rewritten after signing, and the member rule runs before the Ed25519 check.
func TestReject_TheMessageNamesTheSignatureAgentRule(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	p := newRejectProbe(t, f)
	for _, tc := range []struct{ name, member, rule string }{
		{
			"a member carrying a parameter", `sig1="` + wellKnownAgent + `";type=directory`,
			helpers.ErrSignatureAgentIgnored.Error(),
		},
		{
			"a key set at another path", `sig1="https://agent.example/jwks.json"`,
			helpers.ErrSignatureAgentNotKeyDirectory.Error(),
		},
		{"a query", `sig1="` + wellKnownAgent + `?v=1"`, helpers.ErrSignatureAgentNotKeyDirectory.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := p.post(t, rewriteAgent(p.signAs(f.signer), tc.member))
			assertAcceptSignature(t, resp, true)
			var body struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal(resp.body, &body); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(body.Message, tc.rule) {
				t.Errorf("401 message = %q, want the rule %q", body.Message, tc.rule)
			}
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

// wellKnownAgent is the key directory URL a WG-01 signer names.
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

// baseCapture is a Signer that records the signature base it was asked to sign.
type baseCapture struct {
	helpers.Signer
	base string
}

func (c *baseCapture) Sign(ctx context.Context, base []byte) ([]byte, error) {
	c.base = string(base)
	return c.Signer.Sign(ctx, base)
}

// originFormSigner signs a request over the bare-origin member
// sig1="https://agent.example", the form SDK v1.2 and earlier sent.
// helpers.SignRequest now completes an origin to the well-known URL, so the request
// is signed through it, the member's line of the signature base is set back to the
// origin, and that base is signed again: every other byte is the production base
// builder's.
func originFormSigner(body []byte, signer helpers.Signer, opts helpers.SignOptions) func(*http.Request) error {
	return func(req *http.Request) error {
		capture := &baseCapture{Signer: signer}
		opts.SignatureAgent = "https://agent.example"
		if err := helpers.SignRequest(context.Background(), req, body, capture, opts); err != nil {
			return err
		}
		const memberLine = `"signature-agent";key="sig1": `
		base := strings.Replace(
			capture.base,
			memberLine+`"`+wellKnownAgent+`"`,
			memberLine+`"https://agent.example"`,
			1,
		)
		if base == capture.base {
			return fmt.Errorf("the signature base carries no well-known member line:\n%s", capture.base)
		}
		sig, err := signer.Sign(context.Background(), []byte(base))
		if err != nil {
			return err
		}
		req.Header.Set(helpers.SignatureAgentHeader, `sig1="https://agent.example"`)
		req.Header.Set("Signature", "sig1=:"+base64.StdEncoding.EncodeToString(sig)+":")
		return nil
	}
}

// TestVerify_ReachesTheOriginWithTheKeyDirectory: a request naming the well-known
// key directory URL, and one naming the bare origin (the SDK v1.2.x form, which
// WG-01 verifiers outside FORA would fetch as the key set), both reach the origin
// service, and the handler reads the same verified origin and key directory URL
// from its context for each.
func TestVerify_ReachesTheOriginWithTheKeyDirectory(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	p := newRejectProbe(t, f)
	// Each signature carries its own nonce, or the second would be refused as a
	// replay of the first.
	opts := helpers.SignOptions{Created: p.now, Expires: p.now + 60, SignatureAgent: wellKnownAgent, Nonce: "n0"}
	wellKnown := func(req *http.Request) error {
		return helpers.SignRequest(context.Background(), req, p.body, f.signer, opts)
	}
	withNonce := opts
	withNonce.Nonce = "n1"
	bareOrigin := originFormSigner(p.body, f.signer, withNonce)
	for form, sign := range map[string]func(*http.Request) error{"well-known URL": wellKnown, "bare origin": bareOrigin} {
		if resp := p.post(t, sign); resp.status != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", form, resp.status)
		}
	}
	calls := f.origin.verifiedCalls()
	if len(calls) != 2 {
		t.Fatalf("origin calls = %d, want 2", len(calls))
	}
	for i, vr := range calls {
		if vr.SignatureAgent != "https://agent.example" || vr.KeyDirectory != wellKnownAgent {
			t.Errorf("call %d verified (%q, %q), want (%q, %q)", i, vr.SignatureAgent, vr.KeyDirectory,
				"https://agent.example", wellKnownAgent)
		}
	}
}
