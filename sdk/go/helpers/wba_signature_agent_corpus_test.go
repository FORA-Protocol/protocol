package helpers_test

// Replays testdata/wba-signature-agent-vectors.json through the public verify
// faces, the way the Python and TypeScript ports will: every row's request is
// rebuilt from its columns alone, verified, and held to the recorded key directory
// URL, origin and identity, or to the recorded typed refusal and Accept-Signature.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

type wbaCorpusRow struct {
	Name                    string            `json:"name"`
	Method                  string            `json:"method"`
	URL                     string            `json:"url"`
	BodyHex                 string            `json:"body_hex"`
	Authorization           string            `json:"authorization"`
	SignatureAgent          string            `json:"signature_agent"`
	ContentDigest           string            `json:"content_digest"`
	SignatureInput          string            `json:"signature_input"`
	Signature               string            `json:"signature"`
	ResolverKeyID           string            `json:"resolver_keyid"`
	ResolverPubkeyB64URL    string            `json:"resolver_pubkey_b64url"`
	Now                     int64             `json:"now"`
	ExpectedReason          string            `json:"expected_reason"`
	ExpectedAcceptSignature string            `json:"expected_accept_signature"`
	ExpectedSignatureAgent  string            `json:"expected_signature_agent"`
	ExpectedKeyDirectory    string            `json:"expected_key_directory"`
	ExpectedIdentity        string            `json:"expected_identity"`
	ExpectedRefusal         string            `json:"expected_refusal"`
	ExtraHeaders            map[string]string `json:"extra_headers"`
}

type wbaCorpus struct {
	Draft    string            `json:"draft"`
	Refusals map[string]string `json:"refusals"`
	Vectors  []wbaCorpusRow    `json:"vectors"`
}

// wbaRefusalErrors maps each refusal token to the error a Go caller matches it
// with.
var wbaRefusalErrors = map[string]error{
	"member_ignored":    helpers.ErrSignatureAgentIgnored,
	"not_key_directory": helpers.ErrSignatureAgentNotKeyDirectory,
	"not_https_origin":  helpers.ErrSignatureAgentNotOrigin,
	"form":              helpers.ErrSignatureAgentForm,
	"missing_component": helpers.ErrMissingRequiredComponent,
	"required":          helpers.ErrSignatureAgentRequired,
}

func loadWBACorpus(t *testing.T) wbaCorpus {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "wba-signature-agent-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c wbaCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Vectors) == 0 {
		t.Fatal("the corpus has no vectors")
	}
	return c
}

// wbaCorpusRequest rebuilds a row's request: the base headers from the columns,
// then each extra field line added beside them.
func wbaCorpusRequest(t *testing.T, r wbaCorpusRow) (*http.Request, []byte) {
	t.Helper()
	body, err := hex.DecodeString(r.BodyHex)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), r.Method, r.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"Content-Digest": r.ContentDigest, "Authorization": r.Authorization,
		helpers.SignatureAgentHeader: r.SignatureAgent, "Signature-Input": r.SignatureInput, "Signature": r.Signature,
	} {
		req.Header.Set(name, value)
	}
	names := make([]string, 0, len(r.ExtraHeaders))
	for name := range r.ExtraHeaders {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		req.Header.Add(name, r.ExtraHeaders[name])
	}
	return req, body
}

func TestWBASignatureAgentCorpus_Replay(t *testing.T) {
	c := loadWBACorpus(t)
	if c.Draft != "draft-ietf-webbotauth-httpsig-protocol-01" {
		t.Fatalf("draft = %q", c.Draft)
	}
	for token := range c.Refusals {
		if wbaRefusalErrors[token] == nil {
			t.Errorf("the corpus documents refusal %q, which this replay cannot match", token)
		}
	}
	for _, r := range c.Vectors {
		t.Run(r.Name, func(t *testing.T) { replayWBARow(t, r) })
	}
}

// replayWBARow holds one row to the key directory, origin and identity it
// records, or to its typed refusal and Accept-Signature.
func replayWBARow(t *testing.T, r wbaCorpusRow) {
	t.Helper()
	vr, resolvedIn, err := verifyWBARow(t, r)
	if r.ExpectedRefusal == "" {
		assertWBAAccepted(t, r, vr, err, resolvedIn)
		return
	}
	assertWBARefusal(t, r, err)
	if resolvedIn != "" {
		t.Errorf("a refused signature still resolved a key in %q", resolvedIn)
	}
}

// verifyWBARow verifies a row's request through VerifyRequestResolved with a
// resolver that records the directory origin it was handed.
func verifyWBARow(t *testing.T, r wbaCorpusRow) (vr *helpers.VerifiedRequest, resolvedIn string, err error) {
	t.Helper()
	pub, err := base64.RawURLEncoding.DecodeString(r.ResolverPubkeyB64URL)
	if err != nil {
		t.Fatal(err)
	}
	spy := &signatureAgentSpyResolver{
		delegate:  helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{r.ResolverKeyID: pub}),
		onResolve: func(ctx context.Context, _ string) { resolvedIn = helpers.SignatureAgentFromContext(ctx) },
	}
	req, body := wbaCorpusRequest(t, r)
	vr, err = helpers.VerifyRequestResolved(context.Background(), req, body, spy,
		helpers.VerifyOptions{Now: time.Unix(r.Now, 0)})
	return vr, resolvedIn, err
}

// assertWBAAccepted holds an accepted row to its key directory URL, origin and
// identity, and to the origin the resolver was handed.
func assertWBAAccepted(t *testing.T, r wbaCorpusRow, vr *helpers.VerifiedRequest, err error, resolvedIn string) {
	t.Helper()
	if err != nil {
		t.Fatalf("VerifyRequestResolved: %v", err)
	}
	identity, err := helpers.HostOf(vr.KeyDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if vr.KeyDirectory != r.ExpectedKeyDirectory || vr.SignatureAgent != r.ExpectedSignatureAgent ||
		identity != r.ExpectedIdentity {
		t.Errorf("verified (%q, %q, %q), want (%q, %q, %q)", vr.KeyDirectory, vr.SignatureAgent, identity,
			r.ExpectedKeyDirectory, r.ExpectedSignatureAgent, r.ExpectedIdentity)
	}
	if resolvedIn != r.ExpectedSignatureAgent {
		t.Errorf("the resolver was handed %q, want the directory origin %q", resolvedIn, r.ExpectedSignatureAgent)
	}
}

// assertWBARefusal holds a refusal to the recorded token and Accept-Signature. A
// "form" row must not match any of the more specific Signature-Agent sentinels.
func assertWBARefusal(t *testing.T, r wbaCorpusRow, err error) {
	t.Helper()
	want := wbaRefusalErrors[r.ExpectedRefusal]
	if want == nil {
		t.Fatalf("unknown refusal token %q", r.ExpectedRefusal)
	}
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	for token, other := range wbaRefusalErrors {
		if token != r.ExpectedRefusal && token != "form" && errors.Is(err, other) {
			t.Errorf("err = %v also matches %s", err, token)
		}
	}
	if accept, _ := helpers.AcceptSignatureFor(err); accept != r.ExpectedAcceptSignature {
		t.Errorf("Accept-Signature = %q, want %q", accept, r.ExpectedAcceptSignature)
	}
}
