package helpers

// Signature-Agent golden-vector emitter for WG-01
// (draft-ietf-webbotauth-httpsig-protocol-01).
//
// Under WG-01 a Signature-Agent member is the URL of the signer's key set, and a
// member that carries parameters is ignored. FORA accepts exactly one URL, the
// origin's well-known key directory, and completes a bare https origin to it. This
// corpus pins, for each wire value, the key directory URL and the identity the Go
// verifier reads from it, or the typed refusal it answers with, so the Python and
// TypeScript readers can be ported against it.
//
// Every row is a real signature over the fixed request the single-signature verify
// corpora use (seed 0x77), made by the SDK signer or, for the forms the signer
// refuses, by hand. The member is signed as it appears on the wire, so a refusal
// comes from the member rule and never from the Ed25519 check. Each case states
// the refusal its author intends, and the emitter refuses to write a file where the
// REAL Go verifier disagrees with it: the corpus is derived, never hand-typed.
//
// The signer section pins what a signer configured with a value sends: every
// signing path completes an origin to its well-known URL. core's corpus test
// replays it through the real transport.
//
// This table is the one list of Signature-Agent reader and signer cases: the Go
// profile tests keep only what a row cannot express, so a case added here reaches
// all three SDKs.
//
// Like TestGenerateVectors this test is a verification no-op by default (it asserts
// the committed file matches a fresh emit) and (re)writes under FORA_UPDATE_VECTORS=1.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/wbadir"
)

// wbaSignatureAgentVectorsFile is the committed -01 Signature-Agent corpus.
const wbaSignatureAgentVectorsFile = "wba-signature-agent-vectors.json"

// The refusal tokens the corpus records, one per typed refusal the reader answers
// with. They are the names the Python and TypeScript SDKs already give these
// refusals (the Python verify reason, the TypeScript WebBotAuthError reason), so a
// replay compares the port's own name to the token without a translation table.
const (
	wbaRefusalIgnored          = "signature_agent_ignored"
	wbaRefusalNotKeyDirectory  = "signature_agent_not_key_directory"
	wbaRefusalNotHTTPSOrigin   = "signature_agent_not_origin"
	wbaRefusalForm             = "signature_agent_form"
	wbaRefusalMissingComponent = "missing_component"
	wbaRefusalRequired         = "signature_agent_required"
)

// wbaRefusalSentinels documents each token with the Go sentinel it stands for, in
// the corpus itself, so a port need not read Go to map them.
var wbaRefusalSentinels = map[string]string{
	wbaRefusalIgnored: "ErrSignatureAgentIgnored: the covered member carries parameters, " +
		"which WG-01 §5.2.1 has a verifier ignore, so the signature names no key directory",
	wbaRefusalNotKeyDirectory: "ErrSignatureAgentNotKeyDirectory: an https origin followed by " +
		"another path, a query or a fragment",
	wbaRefusalNotHTTPSOrigin: "ErrSignatureAgentNotOrigin: the scheme is not https, or the authority " +
		"is not a lowercase ASCII origin without credentials or a default port",
	wbaRefusalForm: "ErrSignatureAgentForm: any other form the profile refuses, such as a member " +
		"that is not a String or is absent",
	wbaRefusalMissingComponent: "MissingComponentError: the signature does not cover Signature-Agent, " +
		"or the request carries none",
	wbaRefusalRequired: "ErrSignatureAgentRequired: a signer configured with no value",
}

// classifyWBARefusal returns the corpus token for a Signature-Agent refusal, "" for
// none. The specific sentinels are tested before ErrSignatureAgentForm, which
// ErrSignatureAgentIgnored wraps.
func classifyWBARefusal(err error) string {
	var missing *MissingComponentError
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrSignatureAgentIgnored):
		return wbaRefusalIgnored
	case errors.Is(err, ErrSignatureAgentNotKeyDirectory):
		return wbaRefusalNotKeyDirectory
	case errors.Is(err, ErrSignatureAgentNotOrigin):
		return wbaRefusalNotHTTPSOrigin
	case errors.Is(err, ErrSignatureAgentRequired):
		return wbaRefusalRequired
	case errors.Is(err, ErrSignatureAgentForm):
		return wbaRefusalForm
	case errors.As(err, &missing):
		return wbaRefusalMissingComponent
	default:
		return "unexpected: " + err.Error()
	}
}

// wbaSignatureAgentVector is one verifier case. It has the single-signature verify
// corpora's shape, so a port replays it with the machinery it already has, plus
// what WG-01 adds: the key directory URL, the identity and the typed refusal.
type wbaSignatureAgentVector struct {
	verifyRequestNegVector
	// ExpectedKeyDirectory is the key directory URL an accepted signature names
	// (VerifiedRequest.KeyDirectory), with a bare origin completed to it.
	// ExpectedSignatureAgent is that directory's origin.
	ExpectedKeyDirectory string `json:"expected_key_directory,omitempty"`
	// ExpectedIdentity is the host of that URL, port included when there is one:
	// the identity the signature proves, which Requester.domain must name.
	ExpectedIdentity string `json:"expected_identity,omitempty"`
	// ExpectedRefusal is the typed refusal token (see the refusals map), "" for an
	// accepted request.
	ExpectedRefusal string `json:"expected_refusal,omitempty"`
	// Supersedes names the WG-00 corpus row that carries this exact request with
	// the outcome WG-01 reverses, as "<corpus>#<row>": the corpus name without
	// .json, the form the pending lists use.
	Supersedes string `json:"supersedes,omitempty"`
}

// wbaSignerVector is one signer case: the value a signer is configured with, and
// the Signature-Agent it sends or the refusal it signs nothing with.
type wbaSignerVector struct {
	Name       string `json:"name"`
	Configured string `json:"configured"`
	// SignatureAgent is the Signature-Agent header of the signed request.
	SignatureAgent       string `json:"signature_agent,omitempty"`
	ExpectedKeyDirectory string `json:"expected_key_directory,omitempty"`
	ExpectedRefusal      string `json:"expected_refusal,omitempty"`
}

type wbaSignatureAgentDoc struct {
	Draft    string                    `json:"draft"`
	Refusals map[string]string         `json:"refusals"`
	Vectors  []wbaSignatureAgentVector `json:"vectors"`
	Signer   []wbaSignerVector         `json:"signer"`
}

// wbaWellKnown is the key directory URL served from negAgent.
const wbaWellKnown = negAgent + wbadir.Path

// wbaCase is one verifier case as its author writes it: the Signature-Agent field
// lines, how the signature covers the member, and the intended refusal.
type wbaCase struct {
	name  string
	lines []string
	// sdk signs with the SDK signer, configured with lines[0]'s member value;
	// otherwise the case is signed by hand with the production parameters.
	sdk        string
	edit       func(*sigParams)
	refusal    string
	supersedes string
}

// legacyCovered covers Signature-Agent as plain "signature-agent", the legacy
// String form.
func legacyCovered(p *sigParams) {
	p.Covered = append(plainComponents(requiredCoveredComponents...), CoveredComponent{Name: signatureAgentLower})
}

func noEdit(*sigParams) {}

// signWBACase signs the fixed verify request for c and returns its wire columns.
// Field lines after the first are added beside it, as a proxy that splits the
// field would send them.
func signWBACase(t *testing.T, seed []byte, c wbaCase) verifyRequestNegVector {
	t.Helper()
	sign := signWBACaseByHand
	if c.sdk != "" {
		sign = signWBACaseWithSDK
	}
	r := sign(t, seed, c)
	if got := r.signatureAgent; got != c.lines[0] {
		t.Fatalf("%s: the signed request carries Signature-Agent %q, the case %q", c.name, got, c.lines[0])
	}
	v := verifyRequestNegVector{
		Name: c.name, Method: r.method, URL: r.url, BodyHex: hex.EncodeToString(r.body),
		Authorization: r.authorization, SignatureAgent: r.signatureAgent,
		ContentDigest: r.contentDigest, SignatureInput: r.sigInput, Signature: r.sig,
		KeyID: negKeyID, ResolverKeyID: negKeyID,
		ResolverPubkeyB64URL: b64urlNoPad(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)),
		Now:                  negFreshNow,
	}
	switch len(c.lines) {
	case 1:
	case 2:
		// The replay writes signature_agent under the lowercase name, so the second
		// line is spelled in another case to land beside it (assertExtraHeaderSpelling).
		v.ExtraHeaders = map[string]string{"Signature-Agent": c.lines[1]}
	default:
		t.Fatalf("%s: a case carries at most two field lines", c.name)
	}
	return v
}

// signWBACaseWithSDK signs the fixed verify request through the SDK signer,
// configured with c.sdk.
func signWBACaseWithSDK(t *testing.T, seed []byte, c wbaCase) negRequest {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), negMethod, negURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "")
	signer, err := NewEd25519SignerFromSeed(negKeyID, seed)
	if err != nil {
		t.Fatal(err)
	}
	opts := SignOptions{Created: negCreated, Expires: negExpires, SignatureAgent: c.sdk}
	if err := SignRequest(context.Background(), req, negBody, signer, opts); err != nil {
		t.Fatalf("%s: sign: %v", c.name, err)
	}
	return negFrom(req, "")
}

// signWBACaseByHand signs the fixed verify request with the production parameters
// over c's field lines as written, c.edit applied: the forms the signer refuses.
func signWBACaseByHand(t *testing.T, seed []byte, c wbaCase) negRequest {
	t.Helper()
	req, signer, p := negHandBase(t, seed, c.lines[0])
	for _, line := range c.lines[1:] {
		req.Header.Add(SignatureAgentHeader, line)
	}
	c.edit(&p)
	if err := signWithParams(context.Background(), req, p, signer, sigWriteSet); err != nil {
		t.Fatalf("%s: sign by hand: %v", c.name, err)
	}
	return negFrom(req, "")
}

// wbaOracle runs v through the REAL Go verifier and returns every expectation the
// corpus records for it.
func wbaOracle(t *testing.T, v verifyRequestNegVector) (out wbaSignatureAgentVector) {
	t.Helper()
	out.verifyRequestNegVector = v
	req, body := negVectorRequest(t, v)
	resolver := NewStaticKeyResolver(map[string]ed25519.PublicKey{v.ResolverKeyID: resolverPubOf(t, v)})
	sigs, err := VerifyMultisigRequestResolved(context.Background(), req, body, resolver,
		VerifyOptions{Now: time.Unix(v.Now, 0)})
	if err != nil {
		out.ExpectedReason = classifyNegReason(err)
		out.ExpectedAcceptSignature, _ = AcceptSignatureFor(err)
		out.ExpectedRefusal = classifyWBARefusal(err)
		return out
	}
	identity, err := HostOf(sigs[0].KeyDirectory)
	if err != nil {
		t.Fatalf("%s: the key directory %q names no host: %v", v.Name, sigs[0].KeyDirectory, err)
	}
	out.ExpectedSignatureAgent = sigs[0].SignatureAgent
	out.ExpectedKeyDirectory = sigs[0].KeyDirectory
	out.ExpectedIdentity = identity
	return out
}

// buildWBASignatureAgentVectors signs every case, takes its expectations from the
// REAL Go verifier, and refuses a case whose outcome is not the one its author
// intended.
func buildWBASignatureAgentVectors(t *testing.T) []wbaSignatureAgentVector {
	t.Helper()
	seed := fixedSeed(0x77)
	cases := wbaCases()
	out := make([]wbaSignatureAgentVector, 0, len(cases))
	for _, c := range cases {
		v := signWBACase(t, seed, c)
		assertExtraHeaderSpelling(t, v.Name, v.ExtraHeaders)
		w := wbaOracle(t, v)
		if w.ExpectedRefusal != c.refusal {
			t.Fatalf("%s: the verifier answers refusal %q, the case intends %q", c.name, w.ExpectedRefusal, c.refusal)
		}
		// The shared replay shape must agree: a port that replays this row with
		// its single-signature verify machinery reaches the same outcome.
		reason, accept, dir := oracleNegOutcome(t, v)
		if reason != w.ExpectedReason || accept != w.ExpectedAcceptSignature || dir != w.ExpectedSignatureAgent {
			t.Fatalf("%s: the replay oracle (%q, %q, %q) and the -01 oracle disagree", c.name, reason, accept, dir)
		}
		if c.refusal != "" && accept == "" {
			t.Fatalf("%s: a Signature-Agent refusal must carry Accept-Signature", c.name)
		}
		w.Supersedes = c.supersedes
		out = append(out, w)
	}
	return out
}

// buildWBASignerVectors records what a signer configured with each value sends,
// through the REAL SignRequest: an origin completed to its well-known URL.
func buildWBASignerVectors(t *testing.T) []wbaSignerVector {
	t.Helper()
	signer, err := NewEd25519SignerFromSeed(negKeyID, fixedSeed(0x77))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, configured, refusal string }{
		{"origin_completed", negAgent, ""},
		{"well_known_url_as_given", wbaWellKnown, ""},
		{"origin_with_port_completed", "https://relay.example:8443", ""},
		{"no_value", "", wbaRefusalRequired},
		{"http_origin", "http://agent.example", wbaRefusalNotHTTPSOrigin},
		{"bare_host", "agent.example", wbaRefusalNotHTTPSOrigin},
		{"http_well_known_url", "http://agent.example" + wbadir.Path, wbaRefusalNotHTTPSOrigin},
		{"other_path", negAgent + "/jwks.json", wbaRefusalNotKeyDirectory},
		{"query", wbaWellKnown + "?v=1", wbaRefusalNotKeyDirectory},
		{"fragment", negAgent + "#k", wbaRefusalNotKeyDirectory},
	}
	out := make([]wbaSignerVector, 0, len(cases))
	for _, c := range cases {
		req, err := http.NewRequestWithContext(context.Background(), negMethod, negURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		opts := SignOptions{Created: negCreated, Expires: negExpires, SignatureAgent: c.configured}
		err = SignRequest(context.Background(), req, negBody, signer, opts)
		v := wbaSignerVector{Name: c.name, Configured: c.configured, ExpectedRefusal: classifyWBARefusal(err)}
		if v.ExpectedRefusal != c.refusal {
			t.Fatalf("signer %s: refusal %q, the case intends %q", c.name, v.ExpectedRefusal, c.refusal)
		}
		if err == nil {
			v.SignatureAgent = req.Header.Get(SignatureAgentHeader)
			vr, verr := VerifyRequest(
				req,
				negBody,
				ed25519.NewKeyFromSeed(fixedSeed(0x77)).Public().(ed25519.PublicKey),
				VerifyOptions{Now: time.Unix(negFreshNow, 0)},
			)
			if verr != nil {
				t.Fatalf("signer %s: the verifier refuses what the signer sent: %v", c.name, verr)
			}
			v.ExpectedKeyDirectory = vr.KeyDirectory
		}
		out = append(out, v)
	}
	return out
}

// TestGenerateWBASignatureAgentVectors emits the -01 Signature-Agent corpus and is
// its own drift gate.
func TestGenerateWBASignatureAgentVectors(t *testing.T) {
	doc := wbaSignatureAgentDoc{
		Draft:    "draft-ietf-webbotauth-httpsig-protocol-01",
		Refusals: wbaRefusalSentinels,
		Vectors:  buildWBASignatureAgentVectors(t),
		Signer:   buildWBASignerVectors(t),
	}
	path := filepath.Join("testdata", wbaSignatureAgentVectorsFile)
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
