package helpers_test

// The Web Bot Auth profile of a single request signature: what the signer emits,
// what it refuses to sign, and what the verifier accepts and refuses
// (draft-ietf-webbotauth-httpsig-protocol-00, profiled on the authentication
// page). The multi-signature rules are in multisig_test.go.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// signatureAgentSpyResolver delegates Resolve to a real KeyResolver and calls
// onResolve with the context so a test can inspect what the SDK threaded in.
type signatureAgentSpyResolver struct {
	delegate  helpers.KeyResolver
	onResolve func(ctx context.Context, keyID string)
}

func (s *signatureAgentSpyResolver) Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, error) {
	if s.onResolve != nil {
		s.onResolve(ctx, keyID)
	}
	return s.delegate.Resolve(ctx, keyID)
}

var _ helpers.KeyResolver = (*signatureAgentSpyResolver)(nil)

// profileRequest is a fresh FORA RPC request carrying an empty Authorization and
// the Content-Digest of body, ready for a hand-made signature.
func profileRequest(t *testing.T, body []byte, signatureAgent string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "https://exchange.example/fora.v1.ExchangeService/Execute", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "")
	req.Header.Set("Content-Digest", helpers.ContentDigest(body))
	if signatureAgent != "" {
		req.Header.Set(helpers.SignatureAgentHeader, signatureAgent)
	}
	return req
}

// rawSign signs req by hand with the FORA covered set, edited by edit, and the
// fixture window, nonce-free.
func rawSign(t *testing.T, req *http.Request, signer helpers.Signer, edit func(*helpers.RawSignature)) {
	t.Helper()
	raw := helpers.RawSignature{
		Label: "sig1", Covered: helpers.FORACovered(req, "sig1"),
		Created: tCreated, Expires: tExpires, Tag: helpers.WBATag,
	}
	if edit != nil {
		edit(&raw)
	}
	if err := helpers.SignRawForTest(req, signer, raw, false); err != nil {
		t.Fatalf("sign by hand: %v", err)
	}
}

func plainCovered(names ...string) []helpers.CoveredComponent {
	out := make([]helpers.CoveredComponent, 0, len(names))
	for _, n := range names {
		out = append(out, helpers.CoveredComponent{Name: n})
	}
	return out
}

func memberCovered(key string) helpers.CoveredComponent {
	return helpers.CoveredComponent{Name: "signature-agent", Params: []helpers.ComponentParam{{Key: "key", Val: key}}}
}

var foraRPC = []string{"@method", "@target-uri", "content-digest", "authorization"}

// TestSignRequest_emitsTheProfile pins the bytes of one signature: the dictionary
// Signature-Agent member, the covered set with that member last, and the
// parameters in the profile's order with the tag.
func TestSignRequest_emitsTheProfile(t *testing.T) {
	body := []byte(`{"offer_id":"of_1"}`)
	req, pub := signFixture(t, body, nil)

	if got := req.Header.Get(helpers.SignatureAgentHeader); got != `sig1="https://agent.example"` {
		t.Errorf("Signature-Agent = %q, want the one-member dictionary", got)
	}
	want := `sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1")` +
		`;created=1700000000;expires=1700000300;keyid="agent.v1";alg="ed25519";tag="web-bot-auth"`
	if got := req.Header.Get("Signature-Input"); got != want {
		t.Errorf("Signature-Input\n got %s\nwant %s", got, want)
	}
	if _, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow}); err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
}

// TestSignRequest_reproducesTheDocumentedExamples signs the authentication page's
// single-hop and Broker examples with the published test keys they use, and
// requires the page's exact headers. If the page and the SDK ever describe two
// wire formats, this fails.
func TestSignRequest_reproducesTheDocumentedExamples(t *testing.T) {
	agentSeed, _ := base64.RawURLEncoding.DecodeString("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	brokerSeed := mustDecodeHex(t, "9f8362f87a484a954e6e740c5b4c0e84229139a20aa8ab56ff66586f6a7d29c5")
	for _, tc := range []struct {
		name, origin, nonce, body, wantInput, wantSig string
		seed                                          []byte
		created                                       int64
	}{
		{
			name: "single hop", seed: agentSeed, origin: "https://research.acme.com", created: 1790812800,
			nonce:     "TsrHAzO3DzKC9fj7sOvG6npFB86tAdaQ1XH4pBDIAPmZ93MbjGmCgXXhEyx-lC4CG6yY3ZwTqAVPC6LEeNMXIg",
			body:      `{"ver":"1.0","exchange":"exchange.example","requester":{"id":"research-bot-42","domain":"research.acme.com","type":"REQUESTER_TYPE_AGENT"},"uris":["https://publisher.example/premium/ai-funding-roundup"]}`,
			wantInput: `sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1");created=1790812800;expires=1790813100;keyid="kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";alg="ed25519";nonce="TsrHAzO3DzKC9fj7sOvG6npFB86tAdaQ1XH4pBDIAPmZ93MbjGmCgXXhEyx-lC4CG6yY3ZwTqAVPC6LEeNMXIg";tag="web-bot-auth"`,
			wantSig:   "sig1=:pDSMjqSLlVFpCP9YsWvGE0AcqsU1JEWhq1fRryL9tC/SF42A4KIxItxZG5evIcQjraFVROW/zOdW2UhSXdjFBQ==:",
		},
		{
			name: "broker", seed: brokerSeed, origin: "https://broker.example", created: 1790812801,
			nonce:     "7jwqQ5Qo8ytp-rXrRXvOS6tktBBVNJ1Rds5Ypdvh2L3QwG_335-eo89DX7NoxoLuwpT-4uz2aEaIZEzqlKbNIg",
			body:      `{"ver":"1.0","exchange":"exchange.example","requester":{"id":"research-bot-42","domain":"research.acme.com","type":"REQUESTER_TYPE_AGENT"},"uris":["https://publisher.example/premium/ai-funding-roundup"],"deadline":"0.4s"}`,
			wantInput: `sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1");created=1790812801;expires=1790813101;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";nonce="7jwqQ5Qo8ytp-rXrRXvOS6tktBBVNJ1Rds5Ypdvh2L3QwG_335-eo89DX7NoxoLuwpT-4uz2aEaIZEzqlKbNIg";tag="web-bot-auth"`,
			wantSig:   "sig1=:TVAmOQwm7x09EoMAUGPifHsGEGOxV7hqN9CF12Wb7SsWp2Kx2BxAKu8N+8fjprpL3ipAxkGk2rhonqMxW8XIBg==:",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv := ed25519.NewKeyFromSeed(tc.seed)
			keyID, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			signer, err := helpers.NewEd25519Signer(keyID, priv)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodPost, "https://exchange.example/fora.v1.ExchangeService/DiscoverResources", nil)
			if err != nil {
				t.Fatal(err)
			}
			opts := helpers.SignOptions{
				Created: tc.created, Expires: tc.created + 300, Nonce: tc.nonce, SignatureAgent: tc.origin,
			}
			if err := helpers.SignRequest(context.Background(), req, []byte(tc.body), signer, opts); err != nil {
				t.Fatal(err)
			}
			if got := req.Header.Get(helpers.SignatureAgentHeader); got != `sig1="`+tc.origin+`"` {
				t.Errorf("Signature-Agent = %q", got)
			}
			if got := req.Header.Get("Signature-Input"); got != tc.wantInput {
				t.Errorf("Signature-Input\n got %s\nwant %s", got, tc.wantInput)
			}
			if got := req.Header.Get("Signature"); got != tc.wantSig {
				t.Errorf("Signature\n got %s\nwant %s", got, tc.wantSig)
			}
		})
	}
}

// TestSignRequest_refusesWhatNoProfileSignatureCarries: every Web Bot Auth
// signature names an https origin and lives at most five minutes, and its label
// is a structured-field key.
func TestSignRequest_refusesWhatNoProfileSignatureCarries(t *testing.T) {
	signer, _ := mustSigner(t, "agent.v1")
	ok := helpers.SignOptions{Created: tCreated, Expires: tExpires, SignatureAgent: tAgent}
	for _, tc := range []struct {
		name string
		edit func(*helpers.SignOptions)
		want error
	}{
		{"no Signature-Agent", func(o *helpers.SignOptions) { o.SignatureAgent = "" }, helpers.ErrSignatureAgentRequired},
		{"plaintext origin", func(o *helpers.SignOptions) { o.SignatureAgent = "http://agent.example" }, helpers.ErrSignatureAgentNotOrigin},
		{"bare host", func(o *helpers.SignOptions) { o.SignatureAgent = "agent.example" }, helpers.ErrSignatureAgentNotOrigin},
		{"origin with a path", func(o *helpers.SignOptions) { o.SignatureAgent = "https://agent.example/keys" }, helpers.ErrSignatureAgentNotOrigin},
		{"six-minute window", func(o *helpers.SignOptions) { o.Expires = o.Created + 360 }, helpers.ErrSignatureLifetime},
		{"empty window", func(o *helpers.SignOptions) { o.Expires = o.Created }, helpers.ErrSignatureLifetime},
		{"no created", func(o *helpers.SignOptions) { o.Created = 0 }, helpers.ErrSignatureLifetime},
		{"label not a key", func(o *helpers.SignOptions) { o.Label = "Sig1" }, helpers.ErrSignatureLabel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := ok
			tc.edit(&opts)
			req := profileRequest(t, []byte("x"), "")
			err := helpers.SignRequest(context.Background(), req, []byte("x"), signer, opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("SignRequest error = %v, want %v", err, tc.want)
			}
			if req.Header.Get("Signature") != "" {
				t.Error("a refused signing left a Signature header on the request")
			}
		})
	}
}

// TestCheckHTTPSOrigin pins what counts as the ASCII serialization of an https
// origin, the only value a Signature-Agent member carries.
func TestCheckHTTPSOrigin(t *testing.T) {
	for _, ok := range []string{
		"https://agent.example", "https://agent.example:8443", "https://127.0.0.1",
		"https://[::1]:8443", "https://xn--bcher-kva.example", "https://a_b.example",
	} {
		if err := helpers.CheckHTTPSOrigin(ok); err != nil {
			t.Errorf("CheckHTTPSOrigin(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"", "agent.example", "http://agent.example", "HTTPS://agent.example", "https://Agent.example",
		"https://agent.example/", "https://agent.example/keys", "https://agent.example?x=1",
		"https://agent.example#f", "https://user@agent.example", "https://agent.example:443",
		"https://agent.example:0", "https://agent.example:99999", "https://agent.example:",
		"https://bücher.example", "https://", "https://a..example", "https://agent.example%2F",
		`https://agent.example"`, "https://[::1", "https://agent.example:08443",
	} {
		if err := helpers.CheckHTTPSOrigin(bad); !errors.Is(err, helpers.ErrSignatureAgentNotOrigin) {
			t.Errorf("CheckHTTPSOrigin(%q) = %v, want ErrSignatureAgentNotOrigin", bad, err)
		}
	}
}

// TestVerifyRequest_acceptsWhatWG00Permits: the forms other Web Bot Auth signers
// send, which a FORA verifier accepts although the SDK never emits them.
func TestVerifyRequest_acceptsWhatWG00Permits(t *testing.T) {
	signer, pub := mustSigner(t, "agent.v1")
	body := []byte("x")
	member := `sig1="https://agent.example"`
	for _, tc := range []struct {
		name   string
		header string
		edit   func(*helpers.RawSignature)
	}{
		{"legacy String form on a single signature", `"https://agent.example"`, func(r *helpers.RawSignature) {
			r.Covered = plainCovered(append(foraRPC, "signature-agent")...)
		}},
		{"member key different from the label", `agent="https://agent.example"`, func(r *helpers.RawSignature) {
			r.Covered = append(plainCovered(foraRPC...), memberCovered("agent"))
		}},
		{"type=directory as a String", member + `;type="directory"`, nil},
		{"type=directory as a Token", member + `;type=directory`, nil},
		{"no nonce", member, nil},
		{"a nonce of another length", member, func(r *helpers.RawSignature) { r.Nonce = "AAECAwQFBgcICQoLDA0ODw" }},
		{"other members beside the signer's", `x="https://x.example", ` + member, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := profileRequest(t, body, tc.header)
			rawSign(t, req, signer, tc.edit)
			vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
			if err != nil {
				t.Fatalf("VerifyRequest: %v", err)
			}
			if vr.SignatureAgent != tAgent {
				t.Errorf("SignatureAgent = %q, want %q", vr.SignatureAgent, tAgent)
			}
		})
	}
}

// TestVerifyRequest_refusesWhatTheProfileDoesNot: each refusal names its cause,
// and the ones a Web Bot Auth library can fix by signing differently are answered
// with Accept-Signature.
func TestVerifyRequest_refusesWhatTheProfileDoesNot(t *testing.T) {
	signer, pub := mustSigner(t, "agent.v1")
	body := []byte("x")
	member := `sig1="https://agent.example"`
	plainAgent := func(r *helpers.RawSignature) { r.Covered = plainCovered(append(foraRPC, "signature-agent")...) }
	for _, tc := range []struct {
		name       string
		header     string
		edit       func(*helpers.RawSignature)
		want       error
		wantAccept bool
	}{
		{"no tag", member, func(r *helpers.RawSignature) { r.Tag = "" }, helpers.ErrSignatureTag, true},
		{"another tag", member, func(r *helpers.RawSignature) { r.Tag = "fora" }, helpers.ErrSignatureTag, true},
		{"the bare unquoted value v1.0.8 sent", "https://agent.example", plainAgent, helpers.ErrSignatureAgentForm, true},
		{"the dictionary covered as plain signature-agent", member, plainAgent, helpers.ErrSignatureAgentForm, true},
		{"the named member is absent", member, func(r *helpers.RawSignature) {
			r.Label = "swap" // signed over sig1's member, then the header loses it
		}, helpers.ErrSignatureAgentForm, true},
		{"a member whose type is not directory", member + `;type="jwks"`, nil, helpers.ErrSignatureAgentForm, true},
		{"a member that is a token", `sig1=agent`, nil, helpers.ErrSignatureAgentForm, true},
		{"two members covered, neither keyed to the label", `a="https://agent.example", b="https://agent.example"`,
			func(r *helpers.RawSignature) {
				r.Covered = append(plainCovered(foraRPC...), memberCovered("a"), memberCovered("b"))
			}, helpers.ErrSignatureAgentForm, true},
		{"a plaintext origin", `sig1="http://agent.example"`, nil, helpers.ErrSignatureAgentNotOrigin, true},
		{"an origin with a path", `sig1="https://agent.example/keys"`, nil, helpers.ErrSignatureAgentNotOrigin, true},
		{"no Signature-Agent covered", member, func(r *helpers.RawSignature) { r.Covered = plainCovered(foraRPC...) },
			helpers.ErrMissingRequiredComponent, true},
		{"authorization not covered", member, func(r *helpers.RawSignature) {
			r.Covered = append(plainCovered("@method", "@target-uri", "content-digest"), memberCovered("sig1"))
		}, helpers.ErrMissingRequiredComponent, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := profileRequest(t, body, tc.header)
			swap := false
			rawSign(t, req, signer, func(r *helpers.RawSignature) {
				if tc.edit != nil {
					tc.edit(r)
				}
				if r.Label == "swap" {
					r.Label, swap = "sig1", true
				}
			})
			if swap {
				req.Header.Set(helpers.SignatureAgentHeader, `agent2="https://agent.example"`)
			}
			_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyRequest error = %v, want %v", err, tc.want)
			}
			accept, ok := helpers.AcceptSignatureFor(err)
			if ok != tc.wantAccept {
				t.Fatalf("AcceptSignatureFor answered %v (%q), want %v", ok, accept, tc.wantAccept)
			}
		})
	}
}

// TestAcceptSignature_value pins the field a refusal carries, the one the
// authentication page shows.
func TestAcceptSignature_value(t *testing.T) {
	want := `sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"`
	if got := helpers.AcceptSignature(false); got != want {
		t.Errorf("AcceptSignature(false)\n got %s\nwant %s", got, want)
	}
	if got := helpers.AcceptSignature(true); !strings.Contains(got, `"signature-agent";key="sig1" "x-entitlement-token")`) {
		t.Errorf("AcceptSignature(true) does not ask for x-entitlement-token: %s", got)
	}
	if got, ok := helpers.AcceptSignatureFor(&helpers.MissingComponentError{Component: "x-entitlement-token"}); !ok ||
		got != helpers.AcceptSignature(true) {
		t.Errorf("a missing entitlement is answered %q, %v", got, ok)
	}
	if _, ok := helpers.AcceptSignatureFor(helpers.ErrSignatureVerify); ok {
		t.Error("a signature that fails to verify is answered with Accept-Signature")
	}
}

// TestVerifyRequestResolved_resolvesInTheMemberDirectory: the resolver is handed
// the origin of the member the signature covers, never another member's.
func TestVerifyRequestResolved_resolvesInTheMemberDirectory(t *testing.T) {
	signer, pub := mustSigner(t, "agent.v1")
	body := []byte("x")
	req := profileRequest(t, body, `other="https://other.example", sig1="https://agent.example"`)
	rawSign(t, req, signer, nil)

	var captured string
	spy := &signatureAgentSpyResolver{
		delegate:  helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{"agent.v1": pub}),
		onResolve: func(ctx context.Context, _ string) { captured = helpers.SignatureAgentFromContext(ctx) },
	}
	if _, err := helpers.VerifyRequestResolved(context.Background(), req, body, spy, helpers.VerifyOptions{Now: tNow}); err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	if captured != tAgent {
		t.Errorf("resolver saw %q, want the covered member's origin %q", captured, tAgent)
	}
}

// TestVerifyRequest_maxSignatureAgeUnchanged keeps the verifier's own lifetime
// clamp independent of the signer's five-minute limit: a verifier may accept a
// longer window from another signer unless it sets MaxSignatureAge.
func TestVerifyRequest_maxSignatureAgeUnchanged(t *testing.T) {
	signer, pub := mustSigner(t, "agent.v1")
	body := []byte("x")
	req := profileRequest(t, body, `sig1="https://agent.example"`)
	rawSign(t, req, signer, func(r *helpers.RawSignature) { r.Expires = r.Created + 3600 })
	if _, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow}); err != nil {
		t.Fatalf("an hour-long window without a clamp: %v", err)
	}
	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow, MaxSignatureAge: 5 * time.Minute})
	if !errors.Is(err, helpers.ErrSignatureLifetimeTooLong) {
		t.Fatalf("with a five-minute clamp: %v, want ErrSignatureLifetimeTooLong", err)
	}
}
