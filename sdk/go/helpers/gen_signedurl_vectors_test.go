package helpers

// The signed-URL corpus (testdata/signedurl-vectors.json): URLs signed with the real
// SignURLEd25519 and the outcome the real VerifyURLEd25519 reaches for each at its
// pinned clock. TestGenerateVectors (gen_vectors_test.go) renders and checks it with
// the other request-signing corpora.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

// signedURLVector mirrors the SignedUrlVector shape the TS/py parity tests read.
// The SIGN-parity fields (SignerSeedHex, SourceURL, AgentID, ExpUnix) let a
// TS/python port re-sign the exact SOURCE under the oracle's seed and reproduce
// the emitted SignedURL string byte-for-byte.
type signedURLVector struct {
	Name      string `json:"name"`
	PubB64URL string `json:"pub_b64url"`
	KID       string `json:"kid"`
	SignedURL string `json:"signed_url"`
	NowUnix   int64  `json:"now_unix"`
	// Outcome is what the REAL Go VerifyURLEd25519 answers at NowUnix, in the corpus
	// outcome format: "accepted", or "refused:" and the ReasonOf token.
	Outcome string `json:"outcome"`
	// --- SIGN-parity additions ---
	SignerSeedHex string `json:"signer_seed_hex"`
	SourceURL     string `json:"source_url"`
	AgentID       string `json:"agent_id"`
	ExpUnix       int64  `json:"exp_unix"`
}

// buildSignedURLVectors signs a set of URLs with the real signer and records
// the verdict the real verifier reaches for each (against the pinned clock).
func buildSignedURLVectors(t *testing.T) []signedURLVector {
	t.Helper()
	const (
		kid      = "ex.v1"
		expUnix  = int64(1_700_000_300)
		freshNow = int64(1_700_000_100) // before expiry
		staleNow = int64(1_700_000_400) // after expiry
	)
	exSeed := fixedSeed(0x11)
	exPriv := ed25519.NewKeyFromSeed(exSeed)
	exPub := exPriv.Public().(ed25519.PublicKey)

	// An agent key, so one vector is agent-bound (agent_id present).
	agentPub := ed25519.NewKeyFromSeed(fixedSeed(0x22)).Public().(ed25519.PublicKey)
	agentTP, err := Thumbprint(agentPub)
	if err != nil {
		t.Fatal(err)
	}

	expiry := time.Unix(expUnix, 0)
	exSeedHex := hex.EncodeToString(exSeed)
	pub := b64urlNoPad(exPub)

	signOrFail := func(rawURL, agentID string) SignedURL {
		su, err := SignURLEd25519(exPriv, kid, rawURL, agentID, expiry)
		if err != nil {
			t.Fatalf("sign %s: %v", rawURL, err)
		}
		return su
	}

	// emit signs `source` and records everything a sign-face port needs to
	// reproduce the exact `signed_url` string (source, agent_id, exp, signer seed).
	emit := func(name, source, agentID string, now int64, outcome string) signedURLVector {
		return signedURLVector{
			Name: name, PubB64URL: pub, KID: kid,
			SignedURL: signOrFail(source, agentID).URL,
			NowUnix:   now, Outcome: outcome,
			SignerSeedHex: exSeedHex, SourceURL: source, AgentID: agentID, ExpUnix: expUnix,
		}
	}

	// Tampered: flip a byte in the signed valid URL's path so verify fails. Its
	// stored signed_url no longer matches a fresh sign of any source, so it is
	// NOT exercised by the positive (re-sign) parity loop (it is refused).
	tamperedSource := "https://cdn.example/a?doc=1&z=9&a=2"
	tamperedAt := func(name string, now int64) signedURLVector {
		v := emit(name, tamperedSource, "", now, "refused:signature_mismatch")
		v.SignedURL = replaceFirst(v.SignedURL, "/a?", "/x?")
		return v
	}

	return []signedURLVector{
		emit("valid_bearer_sorted_query", "https://cdn.example/a?doc=1&z=9&a=2", "", freshNow, vectorio.Accepted),
		emit("valid_agent_bound", "https://cdn.example/b?doc=7", agentTP, freshNow, vectorio.Accepted),
		emit("expired", "https://cdn.example/c", "", staleNow, "refused:expired"),
		// A URL is valid strictly before its exp, so at exp itself it is refused.
		emit("expired_at_exp", "https://cdn.example/d", "", expUnix, "refused:expired"),
		tamperedAt("tampered_path", freshNow),
		// The signature is checked before expiry, so a URL that fails both is refused
		// for its signature.
		tamperedAt("expired_and_tampered", staleNow),
		// TRICKY vectors — the cases a `new URL()`/urlsplit-normalizing sign face
		// gets WRONG: mixed-case host, an explicit default :443, and a raw space or
		// percent in the PATH. Signed as OPAQUE BYTES, they MUST round-trip verbatim.
		emit("tricky_mixed_case_host", "https://CDN.Example/Doc?x=1", "", freshNow, vectorio.Accepted),
		emit("tricky_explicit_default_port", "https://cdn.example:443/doc?x=1", "", freshNow, vectorio.Accepted),
		emit("tricky_space_in_path", "https://cdn.example/a path/doc?x=1", "", freshNow, vectorio.Accepted),
		emit("tricky_percent_in_path", "https://cdn.example/Doc%2Fpart?z=9&a=2", "", freshNow, vectorio.Accepted),
	}
}

// verifySignedURLVector runs the vector through the real Go verifier so the
// recorded verdict is exactly what the oracle returns (self-consistency guard).
func verifySignedURLVector(t *testing.T, v signedURLVector) {
	t.Helper()
	pubBytes, err := base64.RawURLEncoding.DecodeString(v.PubB64URL)
	if err != nil {
		t.Fatalf("%s: decode pub: %v", v.Name, err)
	}
	_, err = VerifyURLEd25519(v.SignedURL, ed25519.PublicKey(pubBytes), time.Unix(v.NowUnix, 0))
	if got := vectorio.Outcome(err, ReasonOf(err)); got != v.Outcome {
		t.Fatalf("signed-url vector %s: oracle outcome %q, recorded %q (err=%v)", v.Name, got, v.Outcome, err)
	}
}
