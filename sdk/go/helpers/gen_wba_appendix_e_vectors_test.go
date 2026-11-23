package helpers

// The Web Bot Auth draft's own test vectors, as a shared corpus the Python and
// TypeScript faces replay: the request vectors of
// draft-ietf-webbotauth-httpsig-protocol-01 Appendix E (E.1.1 to E.2.2), copied from
// the draft, and the JSON vector file its Appendix F.3 points to, vendored byte for
// byte under testdata/third_party/web-bot-auth/.
//
// The draft gives each vector's signature base and headers, but no verifier
// outcome, so the outcome each SDK must reach is stated here, by hand, and this
// emitter fails rather than records when the Go SDK disagrees:
//
//   - every SDK rebuilds expected_base byte for byte from the request and its
//     Signature-Input;
//   - an Ed25519 vector's signature verifies over that base under the key the
//     vector carries, injected: the vectors' Signature-Agent host,
//     signature-agent.test, does not resolve;
//   - an RSASSA-PSS vector is refused for its algorithm, because the SDKs verify
//     Ed25519 only. This test still checks, with crypto/rsa, that the draft's RSA
//     signature verifies over expected_base, so the base the SDKs must rebuild is
//     the one the signer signed;
//   - the FORA request verifier (VerifyRequest, and the Python and TypeScript
//     functions the symbol map pairs with it) refuses every request vector, the RSA
//     ones for their algorithm and the Ed25519 ones for want of @method: the vectors
//     cover @authority and at most Signature-Agent, the minimum the draft requires,
//     and a FORA RPC signature must cover more.
//
// E.2.3, the signed directory response, is a directory-response vector: it is
// emitted into directory-response-vectors.json as e2_3_signed_directory_response,
// with the base the draft states, and verifies through the directory-response
// verifier. The draft -00 copies of E.2.1 and E.2.2 this corpus replaces were
// pinned by Go alone; the -00 copy of E.2.3 was replayed by all three SDKs from the
// directory-response corpus, under the name wg00_appendix_e23.
//
// These vectors do not pin how a verifier reads Signature-Agent: the signature
// base takes the member's serialized value, whatever directory it names.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	appendixEDraft    = "draft-ietf-webbotauth-httpsig-protocol-01"
	appendixEDraftURL = "https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-01.txt"
	// The Appendix F.3 file at the upstream commit it was copied from, and the
	// SHA-256 of its bytes, so an edit to the vendored copy fails here.
	appendixF3URL    = "https://github.com/cloudflare/web-bot-auth/blob/ce5e54fd7e05dd8ae14fd56198cfcba7acb6082e/packages/web-bot-auth/test/test_data/web_bot_auth_architecture_v2.json"
	appendixF3SHA256 = "d0c8dbb7631dcc22639d12318af2b1ac0a339e4fa5aa4ef6df67ca45b0094576"
	appendixF3Path   = "testdata/third_party/web-bot-auth/web_bot_auth_architecture_v2.json"

	// RFC 9421 Appendix B.2's test-request, the request the draft signs. Only its
	// authority is covered.
	appendixEMethod = http.MethodPost
	appendixEURL    = "https://example.com/foo?param=Value&Pet=dog"
	// The F.3 file names a target URL and no method; only the authority is covered.
	appendixF3Method = http.MethodGet

	// Inside every request vector's window, including the one-hour legacy ones.
	appendixENow = int64(1735689700)
)

// The outcomes a vector pins.
const (
	appendixVerified         = "verified"
	appendixUnsupportedAlg   = "unsupported_alg"
	appendixMissingComponent = "missing_component"
)

// The keyids the draft's vectors name: the RFC 7638 thumbprints of the RFC 9421
// Appendix B.1.2 RSA-PSS key and the Appendix B.1.4 Ed25519 key.
const (
	appendixRSAKeyID = "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA"
	appendixEdKeyID  = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
)

// appendixERequestVector is one signed request.
type appendixERequestVector struct {
	Name string `json:"name"`
	// Section is where the vector comes from: "E.1.1" ... "E.2.2", or "F.3".
	Section        string `json:"section"`
	Method         string `json:"method"`
	URL            string `json:"url"`
	SignatureAgent string `json:"signature_agent,omitempty"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
	// PubKeyB64URL is the Ed25519 key an Ed25519 vector verifies under, the RFC
	// 9421 Appendix B.1.4 key. An RSA vector carries none: the verifier is handed
	// an all-zero Ed25519 key, and refuses the alg before using any key.
	PubKeyB64URL string `json:"pubkey_b64url,omitempty"`
	Now          int64  `json:"now"`
	ExpectedBase string `json:"expected_base"`
	// ExpectedSignature is "verified" (Ed25519, over expected_base, under the
	// injected key) or "unsupported_alg" (the SDKs do not implement the alg).
	ExpectedSignature string `json:"expected_signature"`
	// ExpectedVerifyRequestRefusal is the FORA request verifier's refusal:
	// "unsupported_alg", or "missing_component" with the component named. Go reports
	// it as ErrUnsupportedAlgorithm or a MissingComponentError, Python as
	// verify_request's reason and missing_component, and TypeScript as
	// verifyRequestServer's refusal (its reason is "signature" for both).
	ExpectedVerifyRequestRefusal string `json:"expected_verify_request_refusal"`
	ExpectedMissingComponent     string `json:"expected_missing_component,omitempty"`
}

type appendixESource struct {
	Draft     string `json:"draft"`
	DraftURL  string `json:"draft_url"`
	Sections  string `json:"sections"`
	F3URL     string `json:"f3_url"`
	F3SHA256  string `json:"f3_sha256"`
	Outcomes  string `json:"outcomes"`
	Unwrapped string `json:"unwrapped"`
}

// withEd25519Outcome states what an Ed25519 request vector must reach: its
// signature verifies under pub, and the FORA request verifier refuses it for want of
// @method, since the vectors cover @authority and at most Signature-Agent.
func (v appendixERequestVector) withEd25519Outcome(pub string) appendixERequestVector {
	v.PubKeyB64URL = pub
	v.ExpectedSignature, v.ExpectedVerifyRequestRefusal = appendixVerified, appendixMissingComponent
	v.ExpectedMissingComponent = "@method"
	return v
}

// withRSAOutcome states what an RSASSA-PSS request vector must reach: the SDKs and
// the FORA request verifier both refuse it for its alg.
func (v appendixERequestVector) withRSAOutcome() appendixERequestVector {
	v.ExpectedSignature, v.ExpectedVerifyRequestRefusal = appendixUnsupportedAlg, appendixUnsupportedAlg
	return v
}

// The Appendix E request vectors, copied from the draft with its RFC 8792 line
// wrapping undone. Every one is signed by the RFC 9421 Appendix B.1.2 RSA-PSS key
// or the Appendix B.1.4 Ed25519 key.
func appendixERequests() []appendixERequestVector {
	const (
		rsaKeyID = `keyid="` + appendixRSAKeyID + `"`
		edKeyID  = `keyid="` + appendixEdKeyID + `"`
		dictBase = `"@authority": example.com` + "\n" +
			`"signature-agent";key="sig2": "https://signature-agent.test"` + "\n" +
			`"@signature-params": `
		legacyBase = `"@authority": example.com` + "\n" +
			`"signature-agent": "https://signature-agent.test"` + "\n" +
			`"@signature-params": `
		dictAgent   = `sig2="https://signature-agent.test"`
		legacyAgent = `"https://signature-agent.test"`
	)
	e11 := `("@authority" "signature-agent";key="sig2");created=1735689600;` + rsaKeyID +
		`;alg="rsa-pss-sha512";expires=4889289600;nonce="wcfPQPh7SzkvrIVvhD00vNk9PkxJNY2NVbYl2PVBB4zmUoluSwE7W6bPtF60QA3k8g06FU7PPCD+J58YofY1zg==";tag="web-bot-auth"`
	e12 := `("@authority" "signature-agent");created=1735689600;` + rsaKeyID +
		`;alg="rsa-pss-sha512";expires=1735693200;nonce="XSHtZVCThSIAksXsH9WBs6AtxtXC0eQGiIcUGSoJstFs8lAWakjhrfwzLhyjtme5iXMZvmFWqDEs6cT3Jf+BbQ==";tag="web-bot-auth"`
	e21 := `("@authority" "signature-agent";key="sig2");created=1735689600;` + edKeyID +
		`;alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"`
	e22 := `("@authority" "signature-agent");created=1735689600;` + edKeyID +
		`;alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"`
	edPub := b64urlNoPad(ed25519.NewKeyFromSeed(rfc9421Seed).Public().(ed25519.PublicKey))
	vector := func(name, section, agent, inner, base, sig string) appendixERequestVector {
		return appendixERequestVector{
			Name: name, Section: section, Method: appendixEMethod, URL: appendixEURL,
			SignatureAgent: agent, SignatureInput: "sig2=" + inner, Signature: "sig2=:" + sig + ":",
			Now: appendixENow, ExpectedBase: base + inner,
		}
	}
	rsaVector := func(name, section, agent, inner, base, sig string) appendixERequestVector {
		return vector(name, section, agent, inner, base, sig).withRSAOutcome()
	}
	edVector := func(name, section, agent, inner, base, sig string) appendixERequestVector {
		return vector(name, section, agent, inner, base, sig).withEd25519Outcome(edPub)
	}
	return []appendixERequestVector{
		rsaVector("e1_1_rsa_pss_sha512_dictionary", "E.1.1", dictAgent, e11, dictBase,
			"iOCCPgZeV5D5KlfZLXIFQOZR2njqFiCMZIrb5HRRLrFZR5Wtpsn7HwbKfWYHqW3dYU7HV/RohjNg7fuyQ1Mdy2J4mya9JnQCZtCcIcOK/LM9Yc6g6ZTw0onurllrzEzuNQIFFkBTgPJZlA3rHioFrmDmn+nnN7HaC+it/PA2iGfENHYq9D3Ud7ZeDICmF1s5bsMgc+y+MxTPFQHxOEyhbCDjZbT5yeSkGP1Czczg7Cpf0Fz/wuF3mJJ7TL1mzQk3PPizXFr/EnjdUWri1/W8M/f93d389BFF+qbkISzAvOHEk5TqOoyrzzotTn3xmYN6SCGTHG42fK4rA4Ei0qCnnA=="),
		rsaVector("e1_2_rsa_pss_sha512_legacy", "E.1.2", legacyAgent, e12, legacyBase,
			"I1QWNzGXdP1a4dSvOHLCVOOanEYHDk+ZsVxM9MLX/p4ko69ghKwR5EOtAD96g7g4GWP7lmpM/jFAf9q8EFRDTPLjUXySwMv4YPgabv2LQihTJG2y8a2m6IGltyruwQNiqSJVUuRaG9+b17CGmAMFZh30X6GXLdQJrCARpeTqPwp2DC+a8haDE/VE5EruqzjA5/2mKwvrkzkSqeW5tOVtFwWRRHIOidquf/8Je6kM9mhgkg4arudLA5SL4wyyYE1jURIgcOl8agrfdJ5Def23DIRtiOLRa8jT9cpTLFAuFHN+mrZA/LH9h0gSIg1cPb+0cMASee5uku1KjWcFer7jWA=="),
		edVector("e2_1_ed25519_dictionary", "E.2.1", dictAgent, e21, dictBase,
			"CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ=="),
		edVector("e2_2_ed25519_legacy", "E.2.2", legacyAgent, e22, legacyBase,
			"jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA=="),
	}
}

// appendixEDirectoryName names the E.2.3 vector in directory-response-vectors.json.
const appendixEDirectoryName = "e2_3_signed_directory_response"

// appendixEDirectory is Appendix E.2.3, the signed directory response, copied
// from the draft, as a directory-response vector. Its signature carries no alg. The
// signer's seed is the RFC 9421 Appendix B.1.4 key's; the verified keys are left to
// the directory-response oracle.
func appendixEDirectory() directoryResponseVector {
	const (
		inner   = `("@authority";req "content-digest");created=1735689600;expires=4889289600;keyid="` + appendixEdKeyID + `";tag="http-message-signatures-directory"`
		digest  = "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"
		created = int64(1735689600)
		expires = int64(4889289600)
	)
	return directoryResponseVector{
		Name: appendixEDirectoryName, Section: "E.2.3", Authority: "signature-agent.test",
		Body:           `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + appendixEdKeyID + `","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs","use":"sig"}]}`,
		ContentDigest:  digest,
		SignatureInput: "binding=" + inner,
		Signature:      "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:",
		Keys:           []string{b64urlNoPad(ed25519.NewKeyFromSeed(rfc9421Seed).Public().(ed25519.PublicKey))},
		SignerSeedsHex: []string{hexOf(rfc9421Seed)},
		Created:        created, Expires: expires, Now: appendixENow,
		ExpectedBase: `"@authority";req: signature-agent.test` + "\n" +
			`"content-digest": ` + digest + "\n" +
			`"@signature-params": ` + inner,
	}
}

// appendixF3Entry is one entry of the Appendix F.3 file, the fields this corpus
// reads. The file also carries each private key, which nothing here uses.
type appendixF3Entry struct {
	Key               json.RawMessage `json:"key"`
	TargetURL         string          `json:"target_url"`
	Label             string          `json:"label"`
	Signature         string          `json:"signature"`
	SignatureInput    string          `json:"signature_input"`
	SignatureAgent    string          `json:"signature_agent"`
	SignatureAgentKey string          `json:"signature_agent_key"`
}

// appendixF3 reads the vendored Appendix F.3 file and returns its entries with
// their decoded keys. It fails if the file's bytes are not the upstream ones.
func appendixF3(t *testing.T) ([]appendixF3Entry, []jose.JSONWebKey) {
	t.Helper()
	raw := readFile(t, filepath.FromSlash(appendixF3Path))
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != appendixF3SHA256 {
		t.Fatalf("%s is not the upstream file: sha256 %x", appendixF3Path, sum)
	}
	var entries []appendixF3Entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	keys := make([]jose.JSONWebKey, 0, len(entries))
	for _, e := range entries {
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(e.Key); err != nil {
			t.Fatalf("F.3 key: %v", err)
		}
		keys = append(keys, k)
	}
	return entries, keys
}

// appendixF3Requests turns each F.3 entry into a request vector. The file states
// no signature base, so the expected one is written out here from the entry's
// own Signature-Input: the authority, the Signature-Agent member when the entry
// covers one, and the verbatim parameters. The signature verifying over it, under
// the entry's key, is what shows it is right.
func appendixF3Requests(t *testing.T) []appendixERequestVector {
	t.Helper()
	entries, keys := appendixF3(t)
	out := make([]appendixERequestVector, 0, len(entries))
	for i, e := range entries {
		label, inner, ok := strings.Cut(e.SignatureInput, "=")
		if !ok || label != e.Label {
			t.Fatalf("F.3 entry %d: Signature-Input %q", i, e.SignatureInput)
		}
		base := `"@authority": example.com` + "\n"
		shape := "authority_only"
		if e.SignatureAgent != "" {
			base += `"signature-agent";key="` + e.SignatureAgentKey + `": "https://signature-agent.test"` + "\n"
			shape = "signature_agent"
		}
		v := appendixERequestVector{
			Section: "F.3", Method: appendixF3Method, URL: e.TargetURL,
			SignatureAgent: e.SignatureAgent, SignatureInput: e.SignatureInput, Signature: e.Signature,
			Now: appendixENow, ExpectedBase: base + `"@signature-params": ` + inner,
		}
		switch pub := keys[i].Public().Key.(type) {
		case ed25519.PublicKey:
			v.Name = "f3_ed25519_" + shape
			v = v.withEd25519Outcome(b64urlNoPad(pub))
		case *rsa.PublicKey:
			v.Name = "f3_rsa_pss_sha512_" + shape
			v = v.withRSAOutcome()
		default:
			t.Fatalf("F.3 entry %d: key type %T", i, pub)
		}
		out = append(out, v)
	}
	return out
}

// appendixRSAKey is the RFC 9421 Appendix B.1.2 RSA-PSS public key, read from the
// F.3 file, which carries it. Its RFC 7638 thumbprint is the keyid the E.1
// vectors name.
func appendixRSAKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	_, keys := appendixF3(t)
	for _, k := range keys {
		if pub, ok := k.Public().Key.(*rsa.PublicKey); ok {
			tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatal(err)
			}
			if got := b64urlNoPad(tp); got != appendixRSAKeyID {
				t.Fatalf("F.3 RSA key thumbprint %s, want the E.1 keyid", got)
			}
			return pub
		}
	}
	t.Fatal("F.3 file carries no RSA key")
	return nil
}

func (v appendixERequestVector) request(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequest(v.Method, v.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.SignatureAgent != "" {
		req.Header.Set(SignatureAgentHeader, v.SignatureAgent)
	}
	req.Header.Set("Signature-Input", v.SignatureInput)
	req.Header.Set("Signature", v.Signature)
	return req
}

// checkAppendixERequest holds the Go SDK to everything v states.
func checkAppendixERequest(t *testing.T, v appendixERequestVector, rsaKey *rsa.PublicKey) {
	t.Helper()
	req := v.request(t)
	all, sigs, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("%s: parse: %v", v.Name, err)
	}
	base, err := buildSignatureBase(req, all[0])
	if err != nil {
		t.Fatalf("%s: base: %v", v.Name, err)
	}
	if base != v.ExpectedBase {
		t.Fatalf("%s: signature base\n%q\nwant\n%q", v.Name, base, v.ExpectedBase)
	}
	sig := sigs[all[0].Label]
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	switch v.ExpectedSignature {
	case appendixVerified:
		pub = mustB64URL(v.PubKeyB64URL)
		if !all[0].algAccepted() || !ed25519.Verify(pub, []byte(base), sig) {
			t.Fatalf("%s: the Ed25519 signature does not verify over the base", v.Name)
		}
	case appendixUnsupportedAlg:
		if all[0].algAccepted() {
			t.Fatalf("%s: alg %q accepted", v.Name, all[0].Alg)
		}
		digest := sha512.Sum512([]byte(base))
		if err := rsa.VerifyPSS(rsaKey, crypto.SHA512, digest[:], sig, &rsa.PSSOptions{SaltLength: 64}); err != nil {
			t.Fatalf("%s: the RSA-PSS signature does not verify over the stated base: %v", v.Name, err)
		}
	default:
		t.Fatalf("%s: expected_signature %q", v.Name, v.ExpectedSignature)
	}
	_, err = VerifyRequest(req, nil, pub, VerifyOptions{Now: time.Unix(v.Now, 0)})
	var missing *MissingComponentError
	switch {
	case v.ExpectedVerifyRequestRefusal == appendixUnsupportedAlg && errors.Is(err, ErrUnsupportedAlgorithm):
	case v.ExpectedVerifyRequestRefusal == appendixMissingComponent && errors.As(err, &missing) &&
		missing.Component == v.ExpectedMissingComponent:
	default:
		t.Fatalf("%s: VerifyRequest answered %v, want %s %s", v.Name, err,
			v.ExpectedVerifyRequestRefusal, v.ExpectedMissingComponent)
	}
}

// TestGenerateWBAAppendixEVectors emits the Appendix E corpus: a verification
// no-op by default (asserts the committed file matches a fresh emit), rewritten
// under FORA_UPDATE_VECTORS=1. The Go SDK must reach every stated outcome first.
func TestGenerateWBAAppendixEVectors(t *testing.T) {
	requests := append(appendixERequests(), appendixF3Requests(t)...)
	rsaKey := appendixRSAKey(t)
	for _, v := range requests {
		checkAppendixERequest(t, v, rsaKey)
	}
	doc := map[string]any{
		"source": appendixESource{
			Draft: appendixEDraft, DraftURL: appendixEDraftURL,
			Sections: "Appendix E.1.1, E.1.2, E.2.1 and E.2.2, and the Appendix F.3 JSON file. " +
				"E.2.3, the signed directory response, is e2_3_signed_directory_response in directory-response-vectors.json.",
			F3URL: appendixF3URL, F3SHA256: appendixF3SHA256,
			Outcomes: "The draft states no verifier outcome. The expected_* fields are this corpus's: " +
				"the base rebuilt byte for byte, an Ed25519 signature verified under the injected key, " +
				"an RSASSA-PSS signature refused for its alg, and the FORA request verifier's refusal.",
			Unwrapped: "RFC 8792 line wrapping undone; the request vectors sign RFC 9421 Appendix B.2's " +
				"test-request, of which only @authority is covered.",
		},
		"request_vectors": requests,
	}
	path := filepath.Join("testdata", "wba-appendix-e-vectors.json")
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
