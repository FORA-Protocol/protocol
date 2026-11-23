package helpers

// The delivery-proof (retrieval proof of possession) golden-vector emitter:
// pop-vectors.json, the proofs the sdk/ts and sdk/python verify faces replay.
// Positive proofs are made by the SHIPPED SignAgentBinding; the shapes it refuses
// to make are signed by hand over the verbatim URL. Every expectation is taken
// from the REAL VerifyAgentBinding. TestGenerateVectors writes and drift-gates it.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// popVector mirrors the PopVector shape the TS/py parity tests read.
type popVector struct {
	Name               string `json:"name"`
	Method             string `json:"method"`
	URL                string `json:"url"`
	AgentID            string `json:"agent_id"`
	PresentedKeyB64URL string `json:"presented_key_b64url"`
	// SignerSeedHex is the raw Ed25519 seed of the key that PRODUCED the
	// vector's signature, so a sign-face port can re-sign and byte-compare
	// against the stored Signature (the same self-contained-oracle shape
	// acceptance-vectors.json uses via seed_hex).
	SignerSeedHex string `json:"signer_seed_hex"`
	// AgentDirectory is the https origin the proof names as the agent's key
	// directory, and Nonce the nonce it signed with ("" for none): the inputs a
	// sign-face port needs beyond the seed to reproduce the stored bytes.
	AgentDirectory string `json:"agent_directory"`
	Nonce          string `json:"nonce,omitempty"`
	// SignatureAgent is the Signature-Agent header the fetch carries.
	SignatureAgent string `json:"signature_agent"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
	NowUnix        int64  `json:"now_unix"`
	ExpectedValid  bool   `json:"expected_valid"`
	// ExpectedReason is the PoPFailure token the REAL Go VerifyAgentBinding refuses
	// the proof with ("" when it verifies), and ExpectedAcceptSignature the
	// Accept-Signature value the refusal carries ("" for none).
	ExpectedReason          string `json:"expected_reason"`
	ExpectedAcceptSignature string `json:"expected_accept_signature,omitempty"`
}

// popSpec names one agent-binding proof: the inputs to the shipped signer, or, for
// a proof the signer refuses to make, the covered set and parameters to sign by
// hand.
type popSpec struct {
	name, url      string
	seed           []byte
	keyID          string
	directory      string
	nonce          string
	signatureAgent string             // header value; "" means the signer's own sig1="<directory>"
	covered        []CoveredComponent // nil means the shipped signer
	tag            string
	alg            sigAlg            // the alg of a proof signed by hand
	presented      ed25519.PublicKey // nil means the signing key's public half
	unsigned       bool              // no Signature-Input, Signature or Signature-Agent at all
	now            int64
	valid          bool
}

// signEdgePoP produces a positive PoP proof through the SHIPPED signer, so the
// goldens the other two languages replay are the bytes production emits rather
// than a second implementation living in a test.
func signEdgePoP(t *testing.T, priv ed25519.PrivateKey, sp popSpec, created, expires int64) AgentBinding {
	t.Helper()
	signer, err := NewEd25519Signer(sp.keyID, priv)
	if err != nil {
		t.Fatalf("%s: build agent-binding signer: %v", sp.name, err)
	}
	binding, err := SignAgentBinding(context.Background(), signer, priv.Public().(ed25519.PublicKey), PoPOptions{
		URL: sp.url, KeyID: sp.keyID, Created: created, Expires: expires, Method: http.MethodGet,
		SignatureAgent: sp.directory, Nonce: sp.nonce,
	})
	if err != nil {
		t.Fatalf("%s: sign agent binding: %v", sp.name, err)
	}
	return binding
}

// signEdgePoPByHand builds a proof the shipped signer refuses to make — a keyid
// that is not the signing key's thumbprint, no tag, a covered set the profile does
// not allow — over the verbatim URL. It reproduces what a hostile or outdated
// fetcher would actually put on the wire, which is what the edge verifier has to
// reject (or, for the legacy String form, accept).
func signEdgePoPByHand(priv ed25519.PrivateKey, sp popSpec, created, expires int64) (sigInput, sig string) {
	p := sigParams{
		Covered: sp.covered, KeyID: sp.keyID,
		Created: created, Expires: expires, Nonce: sp.nonce, Tag: sp.tag,
	}
	inner := innerWithAlg(p, sp.alg)
	lines := make([]string, 0, len(sp.covered)+1)
	for _, c := range sp.covered {
		switch {
		case c.Name == "@method":
			lines = append(lines, `"@method": GET`)
		case c.Name == "@target-uri":
			lines = append(lines, `"@target-uri": `+sp.url)
		case c.Name == "@authority":
			lines = append(lines, `"@authority": cdn.example`)
		case c.Name == "x-fora-agent-key":
			lines = append(lines, `"x-fora-agent-key": `+b64urlNoPad(priv.Public().(ed25519.PublicKey)))
		case len(c.Params) == 0:
			lines = append(lines, `"signature-agent": `+sp.signatureAgent)
		default:
			lines = append(lines, renderComponent(c)+`: "`+sp.directory+`"`)
		}
	}
	base := strings.Join(append(lines, `"@signature-params": `+inner), "\n")
	raw := ed25519.Sign(priv, []byte(base))
	return popLabel + "=" + inner, popLabel + "=:" + base64.StdEncoding.EncodeToString(raw) + ":"
}

// handSignedAgentHeader is the Signature-Agent header a hand-signed proof carries:
// sp.signatureAgent when set, none for "-", else the one member sig1=<directory>.
func (sp popSpec) handSignedAgentHeader() string {
	switch sp.signatureAgent {
	case "":
		return signatureAgentMember(popLabel, sp.directory)
	case "-":
		return ""
	default:
		return sp.signatureAgent
	}
}

func buildPopVectors(t *testing.T) []popVector {
	t.Helper()
	const (
		created   = int64(1_700_000_000)
		expires   = int64(1_700_000_300)
		freshNow  = int64(1_700_000_100)
		staleNow  = int64(1_700_000_400) // after expires
		directory = "https://agent.example"
		nonce     = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"
	)
	agentSeed := fixedSeed(0x33)
	agentPub := ed25519.NewKeyFromSeed(agentSeed).Public().(ed25519.PublicKey)
	agentTP, err := Thumbprint(agentPub)
	if err != nil {
		t.Fatal(err)
	}
	// The agent_id lives in the URL query (agent_id=<thumbprint>); the edge
	// @target-uri is the full URL including that param, so the signer signs the
	// same string the verifier reconstructs.
	url := "https://cdn.example/doc?agent_id=" + agentTP
	member := signatureAgentComponent(popLabel)
	wbaCovered := []CoveredComponent{{Name: "@method"}, {Name: "@target-uri"}, member}
	base := popSpec{url: url, seed: agentSeed, keyID: agentTP, directory: directory, nonce: nonce, now: freshNow}
	specs := popProfileSpecs(base, wbaCovered, staleNow)
	out := make([]popVector, 0, len(specs))
	for _, sp := range specs {
		out = append(out, emitPopVector(t, sp, created, expires))
	}
	return out
}

// popProfileSpecs are the delivery proofs that pin the Web Bot Auth profile: the
// signer's own proofs, the refused shapes, the legacy String form, the superset
// covered sets and the alg cases. Each is base with one edit.
func popProfileSpecs(base popSpec, wbaCovered []CoveredComponent, staleNow int64) []popSpec {
	member := signatureAgentComponent(popLabel)
	directory := base.directory
	with := func(name string, edit func(*popSpec)) popSpec {
		sp := base
		sp.name = name
		edit(&sp)
		return sp
	}
	return []popSpec{
		with("valid", func(sp *popSpec) { sp.valid = true }),
		// Verifiers do not require a nonce: WG-00 sets no nonce requirement.
		with("valid_no_nonce", func(sp *popSpec) { sp.nonce = ""; sp.valid = true }),
		with("expired", func(sp *popSpec) { sp.now = staleNow }),
		// An actor presents a DIFFERENT key + a self-signature naming the agent's
		// thumbprint. Its thumbprint != agent_id, so the 3-way identity check rejects it.
		with("wrong_key_thumbprint_mismatch", func(sp *popSpec) {
			sp.seed = fixedSeed(0x44)
			sp.covered = wbaCovered
			sp.tag = WBATag
		}),
		// The v1.0.8 proof: @method and @target-uri only, no Signature-Agent member,
		// no tag. Not a Web Bot Auth signature, so refused.
		with("v108_method_and_target_uri_only", func(sp *popSpec) {
			sp.covered = plainComponents("@method", "@target-uri")
			sp.signatureAgent = "-"
		}),
		with("missing_tag", func(sp *popSpec) { sp.covered = wbaCovered }),
		with("wrong_tag", func(sp *popSpec) { sp.covered = wbaCovered; sp.tag = "other" }),
		// The bare unquoted value the v1.0.8 SDKs sent, covered as plain
		// signature-agent: neither a dictionary nor a String.
		with("bare_signature_agent", func(sp *popSpec) {
			sp.covered = append(plainComponents("@method", "@target-uri"), CoveredComponent{Name: signatureAgentLower})
			sp.tag = WBATag
			sp.signatureAgent = directory
		}),
		// The legacy String form, covered as plain signature-agent: accepted on a
		// direct single-hop call, which a delivery fetch is.
		with("legacy_string_signature_agent", func(sp *popSpec) {
			sp.covered = append(plainComponents("@method", "@target-uri"), CoveredComponent{Name: signatureAgentLower})
			sp.tag = WBATag
			sp.signatureAgent = `"` + directory + `"`
			sp.valid = true
		}),
		// A member that names a plaintext origin is not a key directory.
		with("member_not_https_origin", func(sp *popSpec) {
			sp.covered = wbaCovered
			sp.tag = WBATag
			sp.directory = "http://agent.example"
		}),
		// A proof covers AT LEAST the profile's components: a Web Bot Auth library
		// that also covers @authority, or a header, makes a proof that verifies.
		with("superset_authority", func(sp *popSpec) {
			sp.covered = append(append([]CoveredComponent{}, wbaCovered...), CoveredComponent{Name: "@authority"})
			sp.tag = WBATag
			sp.valid = true
		}),
		with("superset_authority_first_and_agent_key", func(sp *popSpec) {
			sp.covered = []CoveredComponent{
				{Name: "@authority"}, {Name: "@target-uri"}, {Name: "@method"}, member, {Name: "x-fora-agent-key"},
			}
			sp.tag = WBATag
			sp.valid = true
		}),
		// The superset rule still requires every profile component.
		with("superset_without_method", func(sp *popSpec) {
			sp.covered = []CoveredComponent{{Name: "@authority"}, {Name: "@target-uri"}, member}
			sp.tag = WBATag
		}),
		// A fetch that carries no signature at all.
		with("unsigned", func(sp *popSpec) { sp.unsigned = true }),
		// A proof with no alg verifies: the key, which is Ed25519, decides the
		// algorithm. An alg that is present must name ed25519, so an empty one and
		// another algorithm are refused.
		with("valid_no_alg", func(sp *popSpec) {
			sp.covered, sp.tag, sp.alg, sp.valid = wbaCovered, WBATag, algOmitted, true
		}),
		with("empty_alg", func(sp *popSpec) { sp.covered, sp.tag, sp.alg = wbaCovered, WBATag, algEmpty }),
		with("unsupported_alg", func(sp *popSpec) { sp.covered, sp.tag, sp.alg = wbaCovered, WBATag, algOther }),
	}
}

// emitPopVector signs sp (through the shipped signer, or by hand when it names a
// covered set) and records the vector.
func emitPopVector(t *testing.T, sp popSpec, created, expires int64) popVector {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(sp.seed)
	presented := sp.presented
	if presented == nil {
		presented = priv.Public().(ed25519.PublicKey)
	}
	var sigInput, sig, agentHeader string
	switch {
	case sp.unsigned:
		// Nothing but the presented key.
	case sp.covered == nil:
		b := signEdgePoP(t, priv, sp, created, expires)
		sigInput, sig, agentHeader = b.SignatureInput, b.Signature, b.SignatureAgent
	default:
		sigInput, sig = signEdgePoPByHand(priv, sp, created, expires)
		agentHeader = sp.handSignedAgentHeader()
	}
	v := popVector{
		Name: sp.name, Method: http.MethodGet, URL: sp.url, AgentID: sp.keyID,
		PresentedKeyB64URL: b64urlNoPad(presented), SignerSeedHex: hex.EncodeToString(sp.seed),
		AgentDirectory: sp.directory, Nonce: sp.nonce, SignatureAgent: agentHeader,
		SignatureInput: sigInput, Signature: sig, NowUnix: sp.now, ExpectedValid: sp.valid,
	}
	v.ExpectedReason, v.ExpectedAcceptSignature = popOracle(t, v)
	if (v.ExpectedReason == "") != sp.valid {
		t.Fatalf(
			"pop vector %s: the oracle answered %q, the case expects valid=%v",
			sp.name,
			v.ExpectedReason,
			sp.valid,
		)
	}
	return v
}

// popOracle runs the REAL Go VerifyAgentBinding over a pop vector, returning the
// refusal's PoPFailure token ("" when the proof verifies) and its
// Accept-Signature value.
func popOracle(t *testing.T, v popVector) (string, string) {
	t.Helper()
	h := http.Header{}
	h.Set(AgentKeyHeader, v.PresentedKeyB64URL)
	for name, value := range map[string]string{
		SignatureAgentHeader: v.SignatureAgent, "Signature-Input": v.SignatureInput, "Signature": v.Signature,
	} {
		if value != "" {
			h.Set(name, value)
		}
	}
	_, err := VerifyAgentBinding(v.Method, v.URL, h, v.AgentID, PoPVerifyOptions{Now: time.Unix(v.NowUnix, 0)})
	if err == nil {
		return "", ""
	}
	var perr *PoPError
	if !errors.As(err, &perr) {
		t.Fatalf("pop vector %s: not a PoPError: %v", v.Name, err)
	}
	return string(perr.Reason), perr.AcceptSignature
}
