package helpers

// Directory-response golden-vector emitter (ADR-020 §8). A key directory's
// response is signed once per listed key; the Python and TypeScript faces replay
// this corpus against their own response verifiers, and must reach the verdict
// the REAL Go VerifyDirectoryResponse reaches: the set of listed keys that signed
// the response, or the error class for a response that cannot be checked at all.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

type directoryResponseVector struct {
	Name string `json:"name"`
	// Authority is the host[:port] the directory was fetched from, the value of
	// "@authority";req.
	Authority      string `json:"authority"`
	Body           string `json:"body"`
	ContentDigest  string `json:"content_digest,omitempty"`
	SignatureInput string `json:"signature_input,omitempty"`
	Signature      string `json:"signature,omitempty"`
	// Keys are the Ed25519 keys the body lists, base64url without padding.
	Keys []string `json:"keys"`
	// SignerSeedsHex are the seeds of the keys that signed, in label order, so a
	// sign-face port can reproduce the headers.
	SignerSeedsHex []string `json:"signer_seeds_hex,omitempty"`
	Created        int64    `json:"created,omitempty"`
	Expires        int64    `json:"expires,omitempty"`
	Now            int64    `json:"now"`
	// ExpectedVerified are the RFC 7638 thumbprints of the listed keys whose
	// response signature verifies, sorted. ExpectedError is "digest_mismatch" or
	// "unsigned" for a response that cannot be checked at all, "" otherwise.
	ExpectedVerified []string `json:"expected_verified"`
	ExpectedError    string   `json:"expected_error"`
}

func buildDirectoryResponseVectors(t *testing.T) []directoryResponseVector {
	t.Helper()
	const docBody = "{\n  \"keys\": [\n    {\n      \"kty\": \"OKP\",\n      \"crv\": \"Ed25519\",\n      \"use\": \"sig\",\n      \"alg\": \"EdDSA\",\n      \"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\n      \"not_before\": \"2026-07-01T00:00:00Z\",\n      \"not_after\": \"2027-01-01T00:00:00Z\"\n    }\n  ],\n  \"revocation_url\": \"https://research.acme.com/.well-known/fora-invalidations.json\"\n}"
	const (
		created = int64(1790812200)
		expires = int64(1790815800)
		now     = int64(1790812300)
	)
	agent := rfc8037Seed
	second := fixedSeed(0xA1)
	pubOf := func(seed []byte) string {
		return b64urlNoPad(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	twoKeyBody := `{"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"` + pubOf(agent) +
		`"},{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":"` + pubOf(second) + `"}]}`

	signed := func(name, authority, body string, seeds [][]byte, keys []string, c, e int64) directoryResponseVector {
		signers := make([]Signer, 0, len(seeds))
		hexSeeds := make([]string, 0, len(seeds))
		for _, seed := range seeds {
			s, err := NewEd25519SignerFromSeed(seedThumbprint(t, seed), seed)
			if err != nil {
				t.Fatal(err)
			}
			signers = append(signers, s)
			hexSeeds = append(hexSeeds, hexOf(seed))
		}
		d, err := SignDirectoryResponse(context.Background(), authority, []byte(body), signers, c, e)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return directoryResponseVector{
			Name: name, Authority: authority, Body: body,
			ContentDigest: d.ContentDigest, SignatureInput: d.SignatureInput, Signature: d.Signature,
			Keys: keys, SignerSeedsHex: hexSeeds, Created: c, Expires: e, Now: now,
		}
	}
	one := []string{pubOf(agent)}
	both := []string{pubOf(agent), pubOf(second)}
	out := []directoryResponseVector{
		// The authentication page's Key Directory example, byte for byte.
		signed("doc_directory_example", "research.acme.com", docBody, [][]byte{agent}, one, created, expires),
		signed("two_keys_both_signed", "agent.example:8443", twoKeyBody, [][]byte{agent, second}, both, created, expires),
		signed("two_keys_one_signed", "agent.example:8443", twoKeyBody, [][]byte{agent}, both, created, expires),
		signed("expired", "research.acme.com", docBody, [][]byte{agent}, one, created-20000, created-10000),
		signed("created_in_the_future", "research.acme.com", docBody, [][]byte{agent}, one, created+10000, expires+10000),
		signed("key_not_listed", "research.acme.com", docBody, [][]byte{second}, one, created, expires),
	}
	wrongHost := signed("signed_for_another_authority", "evil.example", docBody, [][]byte{agent}, one, created, expires)
	wrongHost.Authority = "research.acme.com"
	changed := signed("body_changed", "research.acme.com", docBody, [][]byte{agent}, one, created, expires)
	changed.Body = docBody + " "
	unsigned := directoryResponseVector{
		Name: "unsigned", Authority: "research.acme.com", Body: docBody,
		ContentDigest: ContentDigest([]byte(docBody)), Keys: one, Now: now,
	}
	// Tag and covered set are checked per signature: signed by hand with another
	// tag, and with a covered set lacking "@authority";req.
	wrongTag := signedDirectoryByHand(t, "wrong_tag", "research.acme.com", docBody, agent, directoryResponseCovered, "web-bot-auth", one, created, expires, now)
	noAuthority := signedDirectoryByHand(t, "no_authority_covered", "research.acme.com", docBody, agent,
		[]CoveredComponent{{Name: "content-digest"}}, DirectoryResponseTag, one, created, expires, now)
	out = append(out, wrongHost, changed, unsigned, wrongTag, noAuthority)

	for i := range out {
		out[i].ExpectedVerified, out[i].ExpectedError = directoryOracle(t, out[i])
	}
	return out
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0xf])
	}
	return string(out)
}

// signedDirectoryByHand signs a directory response with an arbitrary covered set
// and tag, as a nonconformant server would.
func signedDirectoryByHand(
	t *testing.T, name, authority, body string, seed []byte, covered []CoveredComponent, tag string,
	keys []string, created, expires, now int64,
) directoryResponseVector {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(seed)
	p := sigParams{
		Label: "sig1", Covered: covered, KeyID: seedThumbprint(t, seed), Alg: AlgEd25519,
		Created: created, Expires: expires, Tag: tag,
	}
	p.RawInner = signatureInputInner(p)
	digest := ContentDigest([]byte(body))
	raw := ed25519.Sign(priv, []byte(directoryResponseBaseFor(authority, digest, p)))
	return directoryResponseVector{
		Name: name, Authority: authority, Body: body, ContentDigest: digest,
		SignatureInput: "sig1=" + p.RawInner, Signature: "sig1=:" + base64.StdEncoding.EncodeToString(raw) + ":",
		Keys: keys, SignerSeedsHex: []string{hexOf(seed)}, Created: created, Expires: expires, Now: now,
	}
}

// directoryOracle runs the REAL VerifyDirectoryResponse over the vector.
func directoryOracle(t *testing.T, v directoryResponseVector) ([]string, string) {
	t.Helper()
	h := http.Header{}
	if v.ContentDigest != "" {
		h.Set("Content-Digest", v.ContentDigest)
	}
	if v.SignatureInput != "" {
		h.Set("Signature-Input", v.SignatureInput)
		h.Set("Signature", v.Signature)
	}
	keys := make([]ed25519.PublicKey, 0, len(v.Keys))
	for _, k := range v.Keys {
		raw, err := base64.RawURLEncoding.DecodeString(k)
		if err != nil {
			t.Fatalf("%s: key: %v", v.Name, err)
		}
		keys = append(keys, ed25519.PublicKey(raw))
	}
	verified, err := VerifyDirectoryResponse(v.Authority, h, []byte(v.Body), keys, time.Unix(v.Now, 0))
	switch {
	case errors.Is(err, ErrDigestMismatch):
		return []string{}, "digest_mismatch"
	case errors.Is(err, ErrDirectoryResponseUnsigned):
		return []string{}, "unsigned"
	case err != nil:
		t.Fatalf("%s: unexpected error class: %v", v.Name, err)
	}
	out := make([]string, 0, len(verified))
	for tp := range verified {
		out = append(out, tp)
	}
	slices.Sort(out)
	return out, ""
}

// TestGenerateDirectoryResponseVectors emits the directory-response corpus: a
// verification no-op by default (asserts the committed file matches a fresh
// emit), rewritten under FORA_UPDATE_VECTORS=1.
func TestGenerateDirectoryResponseVectors(t *testing.T) {
	vectors := buildDirectoryResponseVectors(t)
	for _, v := range vectors {
		got, gotErr := directoryOracle(t, v)
		if gotErr != v.ExpectedError || !slices.Equal(got, v.ExpectedVerified) {
			t.Fatalf("%s: oracle (%v, %q), recorded (%v, %q)", v.Name, got, gotErr, v.ExpectedVerified, v.ExpectedError)
		}
	}
	path := filepath.Join("testdata", "directory-response-vectors.json")
	doc := map[string]any{"vectors": vectors}
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}
