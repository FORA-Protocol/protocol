package core_test

// The SigningTransport options and the sigwindow constructors.
//
// Behavioral expectations are ported from:
//   - internal/signingtransport/transport.go  (WithAppendSigner, Signature-Agent
//     set-if-absent, path predicate, window injection)
//   - internal/sigwindow/window.go             (ClockWindow, MonotonicWindow)
//
// Transport-neutrality rule (TestCoreConnectrpcFree): this file imports NO
// connectrpc.com/* — core must stay Connect-free.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// ---------------------------------------------------------------------------
// Test doubles / factories.
// ---------------------------------------------------------------------------

// captureTransport records the last request it forwarded so tests can inspect
// headers stamped by the signing transport without needing a real server.
type captureTransport struct {
	req *http.Request
}

func (c *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req.Clone(req.Context())
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	return rec.Result(), nil
}

// bodiedRequest builds a minimal POST request with a non-empty body directed
// at the given path. The body must be non-nil for the signing transport to sign.
func bodiedRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example.com"+path,
		io.NopCloser(bytes.NewReader([]byte(`{"test":true}`))))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header = make(http.Header)
	return req
}

// testSigner returns a fresh signing keypair and its helpers.Signer for use in
// tests. The keyID is derived from the thumbprint so the signer is realistically
// constructed (not a fake string).
func testSigner(t *testing.T) helpers.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyID, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// testDir is the key-directory origin the transports under test sign as.
const testDir = "https://agent.example.com"

// fixedWindow returns a core.Window that always supplies the same pair of
// unix-seconds values. Used to assert that WithWindow injects the supplied
// values into the emitted Signature-Input.
func fixedWindow(created, expires int64) core.Window {
	return func() (int64, int64) { return created, expires }
}

// ---------------------------------------------------------------------------
// (a) WithWindow — injects created/expires into the produced Signature-Input.
// ---------------------------------------------------------------------------

// TestWithWindow_InjectsCreatedExpiresIntoSignatureInput pins that a transport
// constructed with WithWindow(fixedWindow(c,e)) produces a Signature-Input
// header whose created and expires values match c and e respectively.
func TestWithWindow_InjectsCreatedExpiresIntoSignatureInput(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	const wantCreated int64 = 1_700_000_000
	const wantExpires int64 = 1_700_000_300

	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir),
		core.WithWindow(fixedWindow(wantCreated, wantExpires)),
	)

	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	sigInput := cap.req.Header.Get("Signature-Input")
	if sigInput == "" {
		t.Fatal("Signature-Input must be present on a signed /fora.* request")
	}
	wantC := `created=1700000000`
	wantE := `expires=1700000300`
	if !strings.Contains(sigInput, wantC) {
		t.Errorf("Signature-Input = %q; want it to contain %q", sigInput, wantC)
	}
	if !strings.Contains(sigInput, wantE) {
		t.Errorf("Signature-Input = %q; want it to contain %q", sigInput, wantE)
	}
}

// ---------------------------------------------------------------------------
// (b) WithAppendSigner — always appends regardless of existing Signature.
// ---------------------------------------------------------------------------

// TestWithAppendSigner_AppendsSigOnPreSignedRequest pins that a transport built
// with WithAppendSigner always calls helpers.AppendSignature — even on a
// request that already carries an incoming Signature header — so the relayed
// chain grows by one, never replacing sig1.
func TestWithAppendSigner_AppendsSigOnPreSignedRequest(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir), core.WithAppendSigner())

	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	// Pre-stamp a synthetic sig1 to simulate a relayed request.
	req.Header.Set("Signature-Input", `sig1=("@method" "@target-uri");created=1700000000`)
	req.Header.Set("Signature", `sig1=:AAAA:`)
	req.Header.Set("Content-Digest", "sha-256=:AAAA:")

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	sigInput := cap.req.Header.Get("Signature-Input")
	sig := cap.req.Header.Get("Signature")
	// AppendSignature produces sig2; both sig1= and sig2= must appear.
	if !strings.Contains(sigInput, "sig1=") {
		t.Errorf("Signature-Input = %q; original sig1= must be preserved", sigInput)
	}
	if !strings.Contains(sigInput, "sig2=") {
		t.Errorf("Signature-Input = %q; appended sig2= must be present", sigInput)
	}
	if !strings.Contains(sig, "sig1=") || !strings.Contains(sig, "sig2=") {
		t.Errorf("Signature = %q; must contain both sig1 and sig2", sig)
	}
}

// TestWithAppendSigner_AppendsSigOnFreshRequest pins that WithAppendSigner on a
// fresh (unsigned) request still produces a valid sig1 — AppendSignature
// degrades to a fresh sig1 when no incoming signature is present.
func TestWithAppendSigner_AppendsSigOnFreshRequest(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir), core.WithAppendSigner())

	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	sigInput := cap.req.Header.Get("Signature-Input")
	if !strings.Contains(sigInput, "sig1=") {
		t.Errorf("Signature-Input = %q; fresh AppendSigner request must produce sig1", sigInput)
	}
}

// ---------------------------------------------------------------------------
// (c) WithSignatureAgent — every signature's own Signature-Agent member.
// ---------------------------------------------------------------------------

// TestWithSignatureAgent_StampsTheSignersMember pins that the directory becomes
// the signature's own dictionary member, covered by it.
func TestWithSignatureAgent_StampsTheSignersMember(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	const dir = "https://broker.example.com"
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(dir))

	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Agent"); got != `sig1="`+dir+`"` {
		t.Errorf("Signature-Agent = %q; want the one-member dictionary", got)
	}
	if got := cap.req.Header.Get("Signature-Input"); !strings.Contains(got, `"signature-agent";key="sig1"`) ||
		!strings.Contains(got, `tag="web-bot-auth"`) {
		t.Errorf("Signature-Input = %q; want the member covered and the Web Bot Auth tag", got)
	}
}

// TestWithSignatureAgent_AppendsBesideTheEarlierMember pins that a second signer
// adds its own member beside the agent's, which stays byte-for-byte untouched so
// the agent's signature still verifies.
func TestWithSignatureAgent_AppendsBesideTheEarlierMember(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	agent := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent("https://agent.example.com"))
	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := agent.RoundTrip(req); err != nil {
		t.Fatalf("agent RoundTrip: %v", err)
	}
	signed := cap.req.Clone(context.Background())
	signed.Body = io.NopCloser(bytes.NewReader([]byte(`{"test":true}`)))
	relay := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent("https://broker.example.com"))
	if _, err := relay.RoundTrip(signed); err != nil {
		t.Fatalf("relay RoundTrip: %v", err)
	}
	want := `sig1="https://agent.example.com", sig2="https://broker.example.com"`
	if got := cap.req.Header.Get("Signature-Agent"); got != want {
		t.Errorf("Signature-Agent = %q; want %q", got, want)
	}
}

// TestSigningTransport_RefusesWithoutADirectory pins that a request is never
// sent with a signature naming no directory: the transport returns the error and
// the base transport is not reached.
func TestSigningTransport_RefusesWithoutADirectory(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	for name, tr := range map[string]http.RoundTripper{
		"no directory":        core.NewSigningTransport(testSigner(t), cap),
		"not an https origin": core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent("http://agent.example.com")),
	} {
		_, err := tr.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources"))
		if !errors.Is(err, helpers.ErrSignatureAgentRequired) && !errors.Is(err, helpers.ErrSignatureAgentNotOrigin) {
			t.Errorf("%s: RoundTrip error = %v; want a Signature-Agent refusal", name, err)
		}
	}
	if cap.req != nil {
		t.Error("a refused request reached the base transport")
	}
}

// TestSigningTransport_NonceIs64Bytes pins the nonce length widely deployed Web
// Bot Auth verifiers require: 64 random bytes, 86 base64url characters.
func TestSigningTransport_NonceIs64Bytes(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir))
	if _, err := tr.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")); err != nil {
		t.Fatal(err)
	}
	in := cap.req.Header.Get("Signature-Input")
	i := strings.Index(in, `;nonce="`)
	if i < 0 {
		t.Fatalf("no nonce in %s", in)
	}
	nonce := in[i+len(`;nonce="`):]
	nonce = nonce[:strings.IndexByte(nonce, '"')]
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != 64 {
		t.Fatalf("nonce %q decodes to %d bytes (%v), want 64", nonce, len(raw), err)
	}
}

// TestWithSignerSource_SignsAsTheSourcesIdentity pins the per-request signer: the
// signature names the source's key and directory, and two identical requests from
// one source in the same second carry distinct signatures.
func TestWithSignerSource_SignsAsTheSourcesIdentity(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	signer := testSigner(t)
	src := func(_ context.Context, req *http.Request) (helpers.Signer, string, error) {
		return signer, "https://" + req.Header.Get("X-Tenant") + ".agents.example", nil
	}
	frozen := time.Unix(1_700_000_000, 0)
	tr := core.NewSigningTransport(nil, cap, core.WithSignerSource(src),
		core.WithWindow(core.ClockWindow(func() time.Time { return frozen }, time.Minute)))
	var sigs []string
	for range 2 {
		req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
		req.Header.Set("X-Tenant", "alice")
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip: %v", err)
		}
		if got := cap.req.Header.Get("Signature-Agent"); got != `sig1="https://alice.agents.example"` {
			t.Errorf("Signature-Agent = %q; want the source's directory", got)
		}
		if !strings.Contains(cap.req.Header.Get("Signature-Input"), `keyid="`+signer.KeyID()+`"`) {
			t.Errorf("Signature-Input does not name the source's key: %s", cap.req.Header.Get("Signature-Input"))
		}
		sigs = append(sigs, cap.req.Header.Get("Signature"))
	}
	if sigs[0] == sigs[1] {
		t.Error("two identical requests in one second carry the same signature; the second is a replay")
	}
}

// TestWithSignerSource_AnErrorSendsNothing pins that a source that fails, or
// names no signer, stops the request before the base transport.
func TestWithSignerSource_AnErrorSendsNothing(t *testing.T) {
	t.Parallel()
	for name, src := range map[string]core.SignerSource{
		"error": func(context.Context, *http.Request) (helpers.Signer, string, error) {
			return nil, "", errors.New("no identity for this caller")
		},
		"no signer": func(context.Context, *http.Request) (helpers.Signer, string, error) { return nil, testDir, nil },
	} {
		cap := &captureTransport{}
		tr := core.NewSigningTransport(nil, cap, core.WithSignerSource(src))
		if _, err := tr.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")); err == nil {
			t.Errorf("%s: RoundTrip succeeded", name)
		}
		if cap.req != nil {
			t.Errorf("%s: the request reached the base transport", name)
		}
	}
}

// TestWithCoverPrevious_CoversTheEarlierSignature pins the forwarder's option: an
// appended signature covers the earlier one's Signature and Signature-Input
// members and its components.
func TestWithCoverPrevious_CoversTheEarlierSignature(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	agent := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir))
	if _, err := agent.RoundTrip(bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")); err != nil {
		t.Fatal(err)
	}
	signed := cap.req.Clone(context.Background())
	signed.Body = io.NopCloser(bytes.NewReader([]byte(`{"test":true}`)))
	fwd := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent("https://relay.example.com"),
		core.WithAppendSigner(), core.WithCoverPrevious())
	if _, err := fwd.RoundTrip(signed); err != nil {
		t.Fatal(err)
	}
	in := cap.req.Header.Get("Signature-Input")
	sig2 := in[strings.Index(in, "sig2="):]
	for _, want := range []string{`"signature";key="sig1"`, `"signature-input";key="sig1"`, `"signature-agent";key="sig1"`} {
		if !strings.Contains(sig2, want) {
			t.Errorf("sig2 does not cover %s: %s", want, sig2)
		}
	}
}

// ---------------------------------------------------------------------------
// (d) WithSignPredicate — skips signing when predicate returns false.
// ---------------------------------------------------------------------------

// TestWithSignPredicate_SkipsSigningWhenFalse pins that a transport built with
// WithSignPredicate(neverSign) passes the request through unsigned when the
// predicate returns false, regardless of path or body presence.
func TestWithSignPredicate_SkipsSigningWhenFalse(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	neverSign := func(_ *http.Request) bool { return false }
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir), core.WithSignPredicate(neverSign))

	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Input"); got != "" {
		t.Errorf("Signature-Input = %q; want empty — predicate returned false so request must NOT be signed", got)
	}
}

// TestWithSignPredicate_SignsWhenTrue pins that a transport built with
// WithSignPredicate(alwaysSign) signs even a path that the default predicate
// would not sign (i.e. a non-/fora.* path).
func TestWithSignPredicate_SignsWhenTrue(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	alwaysSign := func(_ *http.Request) bool { return true }
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir), core.WithSignPredicate(alwaysSign))

	// /other.* path — default behavior would skip it, but predicate overrides.
	req := bodiedRequest(t, "/other.service/Method")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Input"); got == "" {
		t.Errorf("Signature-Input is empty; predicate returned true so request MUST be signed")
	}
}

// (e, compat) Default (no option) signs any bodied request — compat pin.
// ---------------------------------------------------------------------------

// TestDefaultBehavior_SignsBodiedRequest pins that a transport constructed with
// NO options still signs any bodied request, preserving the pre-option compat
// contract. This is the fail-open guard: adding new options must NOT change the
// default behavior.
func TestDefaultBehavior_SignsBodiedRequest(t *testing.T) {
	t.Parallel()
	cap := &captureTransport{}
	tr := core.NewSigningTransport(testSigner(t), cap, core.WithSignatureAgent(testDir)) // zero options

	req := bodiedRequest(t, "/fora.exchange.v1.ExchangeService/DiscoverResources")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := cap.req.Header.Get("Signature-Input"); got == "" {
		t.Error("Signature-Input must be present on a bodied request with the default (no-option) transport")
	}
}

// ---------------------------------------------------------------------------
// (e) ClockWindow / MonotonicWindow semantics.
// ---------------------------------------------------------------------------

// TestClockWindow_TTLArithmetic pins that ClockWindow(now, ttl) returns
// created = now.Unix() and expires = now.Unix()+ttl.Seconds() — both derived
// from a single clock reading so created <= expires.
func TestClockWindow_TTLArithmetic(t *testing.T) {
	t.Parallel()
	const ttl = 5 * time.Minute
	fixed := time.Unix(1_700_000_000, 0)
	w := core.ClockWindow(func() time.Time { return fixed }, ttl)

	created, expires := w()
	if created != fixed.Unix() {
		t.Errorf("created = %d; want %d (now.Unix)", created, fixed.Unix())
	}
	wantExpires := fixed.Unix() + int64(ttl.Seconds())
	if expires != wantExpires {
		t.Errorf("expires = %d; want %d (now.Unix + ttl)", expires, wantExpires)
	}
}

// TestMonotonicWindow_NeverStampsAheadOfTheClock pins the fix for the forward
// shift: a burst of a thousand calls inside one frozen second stamps every one at
// the clock's time, so no signature is created in the future, and each window is
// exactly ttl. Uniqueness comes from the nonce, not from the window.
func TestMonotonicWindow_NeverStampsAheadOfTheClock(t *testing.T) {
	t.Parallel()
	const ttl = 5 * time.Minute
	frozen := time.Unix(1_700_000_000, 0)
	w := core.MonotonicWindow(func() time.Time { return frozen }, ttl)
	for i := range 1000 {
		created, expires := w()
		if created != frozen.Unix() || expires != frozen.Unix()+int64(ttl.Seconds()) {
			t.Fatalf("call %d = (%d, %d); want (%d, %d) — a signature stamped ahead of the clock",
				i, created, expires, frozen.Unix(), frozen.Unix()+int64(ttl.Seconds()))
		}
	}
}
