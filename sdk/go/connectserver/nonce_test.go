package connectserver_test

// The signing transport stamps a fresh RFC 9421 nonce on every signature.
// Ed25519 is deterministic and created/expires have one-second resolution, so
// without the nonce two identical requests in the same second sign to the same
// bytes and the replay store refuses the second one. These tests pin that the
// nonce removes that collision and that replay protection still holds.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

var nonceParam = regexp.MustCompile(`;nonce="([^"]*)"`)

// sentRequest is a signed request exactly as it left the signing transport.
type sentRequest struct {
	url    string
	header http.Header
	body   []byte
}

// recordingTransport keeps a copy of every request it forwards, so a test can
// read the emitted signature and resend the exact bytes later.
type recordingTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	sent []sentRequest
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	r.mu.Lock()
	r.sent = append(r.sent, sentRequest{url: req.URL.String(), header: req.Header.Clone(), body: body})
	r.mu.Unlock()
	return r.next.RoundTrip(req)
}

// rejectRecorder records the error the server face rejected each request with.
type rejectRecorder struct {
	mu   sync.Mutex
	errs []error
}

func (r *rejectRecorder) observe(_ *http.Request, err error) {
	r.mu.Lock()
	r.errs = append(r.errs, err)
	r.mu.Unlock()
}

func (r *rejectRecorder) last(t *testing.T) error {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.errs) == 0 {
		t.Fatal("no rejection was recorded")
	}
	return r.errs[len(r.errs)-1]
}

// send posts s through rt unchanged except for the header edit.
func send(t *testing.T, rt http.RoundTripper, s sentRequest, edit func(http.Header)) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url, bytes.NewReader(s.body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header = s.header.Clone()
	if edit != nil {
		edit(req.Header)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestSigningTransport_NonceMakesIdenticalRequestsUnique(t *testing.T) {
	agentPub, agentPriv, _ := ed25519.GenerateKey(nil)
	brokerPub, brokerPriv, _ := ed25519.GenerateKey(nil)
	agent, err := helpers.NewEd25519Signer("agent.test.v1", agentPriv)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := helpers.NewEd25519Signer(helpers.BrokerKeyIDPrefix+"test.v1", brokerPriv)
	if err != nil {
		t.Fatal(err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		agent.KeyID():  agentPub,
		broker.KeyID(): brokerPub,
	})
	rejects := &rejectRecorder{}
	srv := serveHandlerWithOpts(t, &echoExchange{}, resolver, newCountingReplayStore(),
		foraserver.WithMaxSignatureAge(5*time.Minute),
		foraserver.WithOnReject(rejects.observe))
	defer srv.Close()

	// One clock reading for every signature, so created and expires are the
	// same on both requests: the collision condition. The server checks
	// freshness against its own clock, so the reading must be a real instant.
	now := time.Now()
	window := core.ClockWindow(func() time.Time { return now }, 5*time.Minute)
	rec := &recordingTransport{next: http.DefaultTransport}
	client := forav1connect.NewExchangeServiceClient(
		&http.Client{Transport: core.NewSigningTransport(agent, rec, core.WithWindow(window))}, srv.URL)

	for i := range 2 {
		if _, err := client.DiscoverResources(context.Background(), connect.NewRequest(&forav1.ResourceQuery{})); err != nil {
			t.Fatalf("identical request %d refused: %v", i+1, err)
		}
	}
	first, second := rec.sent[0], rec.sent[1]

	nonce1 := nonceParam.FindStringSubmatch(first.header.Get("Signature-Input"))
	nonce2 := nonceParam.FindStringSubmatch(second.header.Get("Signature-Input"))
	if nonce1 == nil || nonce2 == nil {
		t.Fatalf("signature carries no nonce: %q", first.header.Get("Signature-Input"))
	}
	if raw, err := base64.RawURLEncoding.DecodeString(nonce1[1]); err != nil || len(raw) != 16 {
		t.Fatalf("nonce %q is not 16 bytes of base64url: %v", nonce1[1], err)
	}
	if nonce1[1] == nonce2[1] {
		t.Fatal("two signatures share a nonce")
	}
	if first.header.Get("Signature") == second.header.Get("Signature") {
		t.Fatal("two identical requests signed to the same bytes")
	}
	strip := func(s string) string { return nonceParam.ReplaceAllString(s, "") }
	if strip(first.header.Get("Signature-Input")) != strip(second.header.Get("Signature-Input")) {
		t.Fatalf("only the nonce may differ:\n%s\n%s", first.header.Get("Signature-Input"), second.header.Get("Signature-Input"))
	}

	t.Run("exact replay is rejected", func(t *testing.T) {
		if code := send(t, http.DefaultTransport, first, nil); code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", code)
		}
		if err := rejects.last(t); !errors.Is(err, foraserver.ErrReplayed) {
			t.Fatalf("reject = %v, want ErrReplayed", err)
		}
	})

	t.Run("changed nonce fails verification", func(t *testing.T) {
		code := send(t, http.DefaultTransport, second, func(h http.Header) {
			h.Set("Signature-Input", nonceParam.ReplaceAllString(h.Get("Signature-Input"), `;nonce="AAAAAAAAAAAAAAAAAAAAAA"`))
		})
		if code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", code)
		}
		if err := rejects.last(t); errors.Is(err, foraserver.ErrReplayed) {
			t.Fatal("rejected as a replay; the signature itself must fail")
		}
	})

	t.Run("removed nonce fails verification", func(t *testing.T) {
		code := send(t, http.DefaultTransport, second, func(h http.Header) {
			h.Set("Signature-Input", strip(h.Get("Signature-Input")))
		})
		if code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", code)
		}
		if err := rejects.last(t); errors.Is(err, foraserver.ErrReplayed) {
			t.Fatal("rejected as a replay; the signature itself must fail")
		}
	})

	t.Run("accepted sig1 cannot be replayed under a fresh sig2", func(t *testing.T) {
		relay := core.NewSigningTransport(broker, http.DefaultTransport,
			core.WithWindow(window), core.WithAppendSigner())
		if code := send(t, relay, first, nil); code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401", code)
		}
		if err := rejects.last(t); !errors.Is(err, foraserver.ErrReplayed) {
			t.Fatalf("reject = %v, want ErrReplayed", err)
		}
	})

	t.Run("legacy signature without nonce is accepted", func(t *testing.T) {
		body := discoverBody(t)
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+discoverProcedure, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		created, expires := window()
		if err := helpers.SignRequest(context.Background(), req, body, agent, helpers.SignOptions{Created: created, Expires: expires}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(req.Header.Get("Signature-Input"), "nonce") {
			t.Fatal("a helper call without a nonce must not emit one")
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d, want 200", resp.StatusCode)
		}
	})
}
