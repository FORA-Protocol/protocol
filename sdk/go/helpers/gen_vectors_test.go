package helpers

// Golden-vector emitter for the cross-language parity corpus (ADR-020 §8).
//
// The sdk/ts and sdk/python L1 helpers assert byte-parity against the sdk/go
// oracle for the signed-URL and RFC 9421 GET-PoP schemes. Rather than
// hand-author vectors (which would silently defeat the "no re-sort on verify"
// guard — see signedurl.go), this emitter signs with the REAL Go signer and
// writes the vectors to committed JSON, exactly as testdata/thumbprint-vectors.json
// pins the thumbprint scheme.
//
// DETERMINISM: every key is derived from a FIXED hardcoded Ed25519 seed and
// every created/expires/now is a FIXED unix timestamp — never time.Now() or a
// random source — so re-running the emitter reproduces byte-identical files
// (drift-gated in CI alongside the generated artifacts).
//
// Default `go test` behaviour is a no-op unless FORA_UPDATE_VECTORS=1 is set;
// the vectors are committed, and CI regenerates + diffs them. Living in
// package helpers (internal test) lets the emitter reuse the unexported
// signature-base machinery (buildSignatureBase / sigParams / plainComponents /
// signatureInputInner) so the PoP vectors carry the exact bytes the edge
// verifier reconstructs.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// signedURLVector mirrors the SignedUrlVector shape the TS/py parity tests read.
// The SIGN-parity fields (SignerSeedHex, SourceURL, AgentID, ExpUnix) let a
// TS/python port re-sign the exact SOURCE under the oracle's seed and reproduce
// the emitted SignedURL string byte-for-byte.
type signedURLVector struct {
	Name          string `json:"name"`
	PubB64URL     string `json:"pub_b64url"`
	KID           string `json:"kid"`
	SignedURL     string `json:"signed_url"`
	NowUnix       int64  `json:"now_unix"`
	ExpectedValid bool   `json:"expected_valid"`
	// --- SIGN-parity additions ---
	SignerSeedHex string `json:"signer_seed_hex"`
	SourceURL     string `json:"source_url"`
	AgentID       string `json:"agent_id"`
	ExpUnix       int64  `json:"exp_unix"`
}

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
}

// fixedSeed returns a deterministic 32-byte Ed25519 seed: byte i = (b+i) mod 256.
func fixedSeed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = byte(int(b) + i)
	}
	return s
}

func b64urlNoPad(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

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
	emit := func(name, source, agentID string, now int64, valid bool) signedURLVector {
		return signedURLVector{
			Name: name, PubB64URL: pub, KID: kid,
			SignedURL: signOrFail(source, agentID).URL,
			NowUnix:   now, ExpectedValid: valid,
			SignerSeedHex: exSeedHex, SourceURL: source, AgentID: agentID, ExpUnix: expUnix,
		}
	}

	// Tampered: flip a byte in the signed valid URL's path so verify fails. Its
	// stored signed_url no longer matches a fresh sign of any source, so it is
	// NOT exercised by the positive (re-sign) parity loop (expected_valid=false).
	tampered := replaceFirst(signOrFail("https://cdn.example/a?doc=1&z=9&a=2", "").URL, "/a?", "/x?")

	return []signedURLVector{
		emit("valid_bearer_sorted_query", "https://cdn.example/a?doc=1&z=9&a=2", "", freshNow, true),
		emit("valid_agent_bound", "https://cdn.example/b?doc=7", agentTP, freshNow, true),
		emit("expired", "https://cdn.example/c", "", staleNow, false),
		{
			Name: "tampered_path", PubB64URL: pub, KID: kid, SignedURL: tampered,
			NowUnix: freshNow, ExpectedValid: false,
			SignerSeedHex: exSeedHex, SourceURL: "https://cdn.example/a?doc=1&z=9&a=2", AgentID: "", ExpUnix: expUnix,
		},
		// TRICKY vectors — the cases a `new URL()`/urlsplit-normalizing sign face
		// gets WRONG: mixed-case host, an explicit default :443, and a raw space or
		// percent in the PATH. Signed as OPAQUE BYTES, they MUST round-trip verbatim.
		emit("tricky_mixed_case_host", "https://CDN.Example/Doc?x=1", "", freshNow, true),
		emit("tricky_explicit_default_port", "https://cdn.example:443/doc?x=1", "", freshNow, true),
		emit("tricky_space_in_path", "https://cdn.example/a path/doc?x=1", "", freshNow, true),
		emit("tricky_percent_in_path", "https://cdn.example/Doc%2Fpart?z=9&a=2", "", freshNow, true),
	}
}

func replaceFirst(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
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
	presented      ed25519.PublicKey // nil means the signing key's public half
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
		Covered: sp.covered, KeyID: sp.keyID, Alg: AlgEd25519,
		Created: created, Expires: expires, Nonce: sp.nonce, Tag: sp.tag,
	}
	inner := signatureInputInner(p)
	lines := make([]string, 0, len(sp.covered)+1)
	for _, c := range sp.covered {
		switch {
		case c.Name == "@method":
			lines = append(lines, `"@method": GET`)
		case c.Name == "@target-uri":
			lines = append(lines, `"@target-uri": `+sp.url)
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
	with := func(name string, edit func(*popSpec)) popSpec {
		sp := base
		sp.name = name
		edit(&sp)
		return sp
	}
	specs := []popSpec{
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
	}
	out := make([]popVector, 0, len(specs))
	for _, sp := range specs {
		out = append(out, emitPopVector(t, sp, created, expires))
	}
	return out
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
	if sp.covered == nil {
		b := signEdgePoP(t, priv, sp, created, expires)
		sigInput, sig, agentHeader = b.SignatureInput, b.Signature, b.SignatureAgent
	} else {
		sigInput, sig = signEdgePoPByHand(priv, sp, created, expires)
		agentHeader = sp.signatureAgent
		if agentHeader == "" {
			agentHeader = signatureAgentMember(popLabel, sp.directory)
		}
		if agentHeader == "-" {
			agentHeader = ""
		}
	}
	return popVector{
		Name: sp.name, Method: http.MethodGet, URL: sp.url, AgentID: sp.keyID,
		PresentedKeyB64URL: b64urlNoPad(presented), SignerSeedHex: hex.EncodeToString(sp.seed),
		AgentDirectory: sp.directory, Nonce: sp.nonce, SignatureAgent: agentHeader,
		SignatureInput: sigInput, Signature: sig, NowUnix: sp.now, ExpectedValid: sp.valid,
	}
}

// signRequestVector mirrors the SignRequestVector shape the py parity test reads.
// It records the exact bytes the Go SignRequest emits (signature base,
// Signature-Input, Signature) plus everything the port needs to reproduce them
// (method, absolute URL, body, authorization, created/expires, seed) and to
// round-trip verify (pubkey, content-digest).
type signRequestVector struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	BodyHex       string `json:"body_hex"`
	Authorization string `json:"authorization"`
	// SignatureAgent is the signer's key-directory origin, the SignOptions input.
	// The Signature-Agent header it produces is in emitted_headers.
	SignatureAgent string `json:"signature_agent"`
	// AppendOnly marks a vector signed through AppendSignature (the relay path)
	// rather than SignRequest.
	AppendOnly bool   `json:"append_only,omitempty"`
	KeyID      string `json:"keyid"`
	Created    int64  `json:"created"`
	Expires    int64  `json:"expires"`
	// Nonce is the RFC 9421 nonce passed to the signer; absent when none was.
	Nonce          string `json:"nonce,omitempty"`
	SignerSeedHex  string `json:"signer_seed_hex"`
	PubkeyB64URL   string `json:"pubkey_b64url"`
	ContentDigest  string `json:"content_digest"`
	SignatureBase  string `json:"signature_base"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
	// EmittedHeaders is what the SIGNER puts on a bare request, lowercased —
	// not the full header set a live client sends, which also carries
	// content-type, the Connect protocol version and an accept-encoding.
	//
	// Every other field here records what was SIGNED. This one records what is
	// SENT, and the two are different claims: the covered set binds authorization
	// and signature-agent unconditionally, empty values included, so a verifier
	// needs them present on the wire to rebuild the base and refuses the request
	// when they are absent. A port can agree byte-for-byte on the signature and
	// still be unable to complete a single call.
	//
	// A LIST per name, read with Values, because that is what the verifier reads:
	// it joins repeated values with ", " before rebuilding the base, so a duplicated
	// covered header breaks a correct signature. A map of single strings cannot
	// express that, and a gate that cannot express the failure cannot catch it.
	EmittedHeaders map[string][]string `json:"emitted_headers"`
}

// Fixed 64-byte nonces (bytes 0..63, 64..127, 128..191, 192..255, base64url),
// the length the signing transports emit.
const (
	nonce64A = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw"
	nonce64B = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-fw"
	nonce64C = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp-goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2-vw"
	nonce64D = "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t_g4eLj5OXm5-jp6uvs7e7v8PHy8_T19vf4-fr7_P3-_w"
)

// The two published Ed25519 test keys the authentication page's examples are
// signed with: RFC 8037 Appendix A (the agent) and RFC 9421 Appendix B.1.4 (the
// Broker). Their vectors reproduce the page's example requests byte for byte.
var (
	rfc8037Seed = mustB64URL("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	rfc9421Seed = mustHex("9f8362f87a484a954e6e740c5b4c0e84229139a20aa8ab56ff66586f6a7d29c5")
)

func mustB64URL(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// seedThumbprint is the RFC 7638 thumbprint of the key seed derives: the keyid a
// Web Bot Auth signature names.
func seedThumbprint(t *testing.T, seed []byte) string {
	t.Helper()
	tp, err := Thumbprint(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// acceptanceVector mirrors the AcceptanceVector shape the py parity test reads.
// Seeded 0102..1f20 — the SAME seed the app fixture (testdata/acceptance-vectors.json)
// uses — so the emitted canonical bytes + signature cross-check byte-for-byte
// against the app.
type acceptanceVector struct {
	Name            string `json:"name"`
	OfferSig        string `json:"offer_sig"`
	RequesterID     string `json:"requester_id"`
	RequesterDomain string `json:"requester_domain"`
	IdempotencyKey  string `json:"idempotency_key"`
	// CanonicalJCS is the exact RFC 8785 JCS UTF-8 string the acceptance signature
	// covers (JCS(protojson(AgentAcceptancePayload))). Replaces the old
	// proto3-field-tag canonical_bytes_hex — the canonicalization itself changed.
	CanonicalJCS string `json:"canonical_jcs"`
	SignatureHex string `json:"signature_hex"`
	PubkeyB64    string `json:"pubkey_b64"`
	SeedHex      string `json:"seed_hex"`
}

// refusedAcceptanceVector is an acceptance whose canonical bytes would name an
// empty requester. Every SDK must refuse it three ways: the canonical-bytes
// function refuses to render it, the signer refuses to sign it, and the verifier
// refuses it. CanonicalJCS and SignatureHex are what a signer WITHOUT that check
// would produce — the omit-unpopulated render and a raw Ed25519 signature over
// it — so the verifier's refusal is proven against a signature that does verify
// over those bytes, not merely against a bad one. Empty names the field left
// empty.
type refusedAcceptanceVector struct {
	Name            string `json:"name"`
	Empty           string `json:"empty"`
	OfferSig        string `json:"offer_sig"`
	RequesterID     string `json:"requester_id"`
	RequesterDomain string `json:"requester_domain"`
	IdempotencyKey  string `json:"idempotency_key"`
	CanonicalJCS    string `json:"canonical_jcs"`
	SignatureHex    string `json:"signature_hex"`
	PubkeyB64       string `json:"pubkey_b64"`
	SeedHex         string `json:"seed_hex"`
}

// acceptanceSeedHex is the fixed seed shared with the app's committed
// testdata/acceptance-vectors.json; its raw bytes are the
// signer seed for every acceptance vector.
const acceptanceSeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

// offerVerifyVector mirrors the OfferVerifyVector shape the TS/py core
// offer-verify parity suites read. The signed payload is
// JCS(protojson(offer with sig cleared)); offer_json is the FULL canonical
// proto-JSON of the SIGNED offer (signature + signature_algorithm present) so the
// port re-derives the signed bytes by clearing those two keys and re-running JCS,
// exactly as the Go oracle does. A tamper vector carries a signature that does not
// verify (offer mutated after signing) so the port lands it in Rejected.
type offerVerifyVector struct {
	Name              string          `json:"name"`
	Exchange          string          `json:"exchange"`
	ExchangePubB64URL string          `json:"exchange_pub_b64url"`
	OfferJSON         json.RawMessage `json:"offer_json"`
	NowUnix           int64           `json:"now_unix"`
	ExpectedVerified  bool            `json:"expected_verified"`
	// ExchangeSeedHex is the exchange offer-signing seed (fixedSeed 0x66), so a
	// sign-face port re-signs CanonicalOfferBytes(offer_json) and byte-matches
	// the signature already embedded in offer_json.
	ExchangeSeedHex string `json:"exchange_seed_hex"`
}

// offerVerifyDoc is the {"vectors":[...]} wrapper the offer-verify suites read,
// carrying the canonicalization marker so a reader cannot confuse it with a
// deterministic-protobuf form.
type offerVerifyDoc struct {
	Canonicalization string              `json:"canonicalization"`
	Vectors          []offerVerifyVector `json:"vectors"`
}

// offerCanonicalProtoJSON renders offer to the SAME pinned proto-JSON the signer
// canonicalizes over (snake_case, enums-as-names, omit-unpopulated). Emitting the
// vector's offer_json through the identical option set is what lets the port
// reproduce JCS(protojson(offer)) byte-for-byte.
func offerCanonicalProtoJSON(t *testing.T, offer *forav1.Offer) json.RawMessage {
	t.Helper()
	pj, err := canonicalSignJSONOptions.Marshal(offer)
	if err != nil {
		t.Fatalf("offer proto-JSON marshal: %v", err)
	}
	// Re-key through JCS so the committed offer_json is itself canonical and stable
	// across protojson's non-deterministic whitespace/ordering (the port clears sig
	// + re-JCS-es regardless, but a canonical stored form keeps the vector file
	// deterministic under the drift gate).
	canon, err := jcs.Transform(pj)
	if err != nil {
		t.Fatalf("offer_json JCS: %v", err)
	}
	return json.RawMessage(canon)
}

// buildOfferVerifyVectors signs a MATRIX of offers with the REAL Go SignOffer and
// records, for each, the canonical proto-JSON, the exchange offer-signing pubkey,
// and the verdict the real VerifyOffer + expiry gate reaches. The matrix exercises
// the hard JCS encodings: minimal / Struct-ext-with->1-
// key (recursive key-sort) / two Timestamps / repeated terms+attestations+enum /
// a tamper negative.
func buildOfferVerifyVectors(t *testing.T) []offerVerifyVector {
	t.Helper()
	const (
		exchange = "exchange.example.com"
		nowUnix  = int64(1_700_000_100)
		expUnix  = int64(1_700_000_900) // after now → not expired
	)
	exSeed := fixedSeed(0x66)
	exPriv := ed25519.NewKeyFromSeed(exSeed)
	exPub := exPriv.Public().(ed25519.PublicKey)
	pubB64URL := b64urlNoPad(exPub)

	// signVerdict signs offer in place and records the verdict the real verifier
	// reaches (against the pinned clock). tamper mutates the offer AFTER signing so
	// the recorded verdict is a genuine reject.
	emit := func(name string, offer *forav1.Offer, tamper func(*forav1.Offer)) offerVerifyVector {
		offer.Exchange = exchange
		sig, err := SignOffer(exPriv, offer)
		if errors.Is(err, ErrOfferTermPriced) {
			// SignOffer refuses a priced term, so a vector that carries one is
			// signed over the same canonical bytes directly: the signature is
			// genuine, and the verdict must come from the term check alone.
			payload, cerr := CanonicalOfferBytes(offer)
			if cerr != nil {
				t.Fatalf("%s: canonical offer: %v", name, cerr)
			}
			sig, err = hex.EncodeToString(ed25519.Sign(exPriv, payload)), nil
		}
		if err != nil {
			t.Fatalf("%s: sign offer: %v", name, err)
		}
		offer.Signature = sig
		offer.SignatureAlgorithm = OfferSignatureAlgorithm
		if tamper != nil {
			tamper(offer)
		}
		verifyErr := VerifyOffer(offer, offer.GetSignature(), exPub)
		// Freshness is fail-closed and mirrors core.Verifier.expired: a missing
		// expires_at is expired (not eternal); a present bound is inclusive at now.
		expired := offer.GetExpiresAt() == nil || offer.GetExpiresAt().AsTime().Before(time.Unix(nowUnix, 0))
		// The offer's term carries no pricing, and an estimate a metered offer
		// states is positive (core.Verifier's last two checks).
		termErr := CheckOfferTermsUnpriced(offer)
		estimateErr := CheckMeteredEstimate(offer)
		return offerVerifyVector{
			Name:              name,
			Exchange:          exchange,
			ExchangePubB64URL: pubB64URL,
			OfferJSON:         offerCanonicalProtoJSON(t, offer),
			NowUnix:           nowUnix,
			ExpectedVerified:  verifyErr == nil && !expired && termErr == nil && estimateErr == nil,
			ExchangeSeedHex:   hex.EncodeToString(exSeed),
		}
	}

	// A conformant offer is always minted now+TTL, so every positive (verified)
	// fixture carries a future expires_at; the freshness dimension is exercised
	// by the dedicated vectors appended below.
	future := timestamppb.New(time.Unix(expUnix, 0).UTC())

	minimal := &forav1.Offer{OfferId: "offer-minimal", ExpiresAt: future}

	structExt, err := structpb.NewStruct(map[string]any{
		// >1 key, intentionally NOT in sorted order, to force JCS recursive key-sort.
		"zebra":  "last",
		"alpha":  "first",
		"nested": map[string]any{"y": 2.0, "x": 1.0},
	})
	if err != nil {
		t.Fatalf("struct ext: %v", err)
	}
	structExtOffer := &forav1.Offer{OfferId: "offer-struct", Ext: structExt, ExpiresAt: future}

	twoTimestamps := &forav1.Offer{
		OfferId:   "offer-two-ts",
		ExpiresAt: timestamppb.New(time.Unix(expUnix, 0).UTC()),
		DataAsOf:  timestamppb.New(time.Unix(1_699_990_000, 0).UTC()),
	}

	repeated := &forav1.Offer{
		OfferId:        "offer-repeated",
		ExpiresAt:      future,
		DeliveryMethod: forav1.DeliveryMethod_DELIVERY_METHOD_DIRECT,
		Pricing:        &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD", EstimatedQuantity: proto.Int32(1)},
		Terms: []*forav1.LicenseTerm{
			{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Scopes: []string{"ai-train", "ai-infer"}},
			{Semantics: forav1.TermSemantics_TERM_SEMANTICS_REFERENCE_ONLY, Scopes: []string{"resell"}},
		},
		Attestations: []*forav1.ResourceAttestation{
			{Verifier: "verifier.example", Keyid: "v1", Uri: "https://verifier.example/a"},
			{Verifier: "verifier2.example", Keyid: "v2", Uri: "https://verifier2.example/b"},
		},
		IabCategories: []string{"IAB1", "IAB2"},
	}

	return []offerVerifyVector{
		emit("minimal", minimal, nil),
		emit("struct_ext_multi_key", structExtOffer, nil),
		emit("two_timestamps", twoTimestamps, nil),
		emit("repeated_terms_enum", repeated, nil),
		// tamper_negative: sign a clean offer, then bump the price. The stored
		// signature no longer matches the (tampered) offer_json, so the port rejects.
		emit("tamper_negative", &forav1.Offer{
			OfferId:   "offer-tamper",
			ExpiresAt: future,
			Pricing:   &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
		}, func(o *forav1.Offer) {
			o.Pricing.Rate = "999.00" // mutate AFTER signing → signature invalid
		}),

		// --- Freshness dimension (M-7): every port must agree token-for-token on
		// the expires_at verdict against the injected clock. These lock the
		// fail-closed contract so a port cannot silently regress to fail-open. ---

		// fresh_at_now_inclusive: expires_at == now. Inclusive boundary → verified.
		emit("fresh_at_now_inclusive", &forav1.Offer{
			OfferId:   "offer-fresh-now",
			ExpiresAt: timestamppb.New(time.Unix(nowUnix, 0).UTC()),
		}, nil),

		// expired_past: valid signature, expires_at strictly before now → rejected
		// on freshness (not signature).
		emit("expired_past", &forav1.Offer{
			OfferId:   "offer-expired",
			ExpiresAt: timestamppb.New(time.Unix(nowUnix-100, 0).UTC()),
		}, nil),

		// --- Metered estimate dimension: a PER_UNIT offer may state an
		// estimated_quantity on its own pricing or none. One it states is
		// positive, or every port rejects the offer even though its signature
		// and expiry are good. ---

		// metered_with_estimate: the metered shape with an estimate.
		emit("metered_with_estimate", &forav1.Offer{
			OfferId:   "offer-metered",
			ExpiresAt: future,
			Pricing:   meteredVectorPricing(proto.Int32(2500)),
			Terms:     []*forav1.LicenseTerm{{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED}},
		}, nil),
		// metered_without_estimate: no estimate at all. The estimate is
		// optional, and the purchase charges one unit → verified.
		emit("metered_without_estimate", &forav1.Offer{
			OfferId:   "offer-metered-no-estimate",
			ExpiresAt: future,
			Pricing:   meteredVectorPricing(nil),
		}, nil),
		// metered_zero_estimate: a stated estimate of zero is not positive → rejected.
		emit("metered_zero_estimate", &forav1.Offer{
			OfferId:   "offer-metered-zero-estimate",
			ExpiresAt: future,
			Pricing:   meteredVectorPricing(proto.Int32(0)),
		}, nil),
		// metered_term_estimate_only: the term is PER_UNIT and carries an estimate,
		// the offer's own pricing does not. An offer's term carries no pricing, so
		// the priced term alone rejects it, whatever its estimate → rejected.
		emit("metered_term_estimate_only", &forav1.Offer{
			OfferId:   "offer-metered-term-only",
			ExpiresAt: future,
			Terms:     []*forav1.LicenseTerm{{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Pricing: meteredVectorPricing(proto.Int32(2500))}},
		}, nil),

		// --- One price dimension: an offer states its price once, in
		// Offer.pricing, and its term carries none. Every port rejects a priced
		// term even when its signature and expiry are good. ---

		// term_priced_same_as_offer: the term repeats the offer's own FLAT price
		// exactly → still rejected; agreement does not make a second copy valid.
		emit("term_priced_same_as_offer", &forav1.Offer{
			OfferId:   "offer-term-priced",
			ExpiresAt: future,
			Pricing:   &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
			Terms: []*forav1.LicenseTerm{{
				Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED,
				Pricing:   &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
			}},
		}, nil),
		// term_unpriced_flat: the conformant shape, a FLAT offer selling a term
		// with no pricing → verified.
		emit("term_unpriced_flat", &forav1.Offer{
			OfferId:   "offer-term-unpriced",
			ExpiresAt: future,
			Pricing:   &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
			Terms:     []*forav1.LicenseTerm{{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED}},
		}, nil),
		// flat_without_estimate: a non-metered offer needs no estimate → verified.
		emit("flat_without_estimate", &forav1.Offer{
			OfferId:   "offer-flat",
			ExpiresAt: future,
			Pricing:   &forav1.Pricing{Model: forav1.PricingModel_PRICING_MODEL_FLAT, Rate: "1.00", Currency: "USD"},
		}, nil),

		// missing_expires_at: valid signature, NO expires_at. Fail-closed → rejected.
		// This is the exact fail-open hole M-7 flagged: a port that returns "fresh"
		// on a missing bound admits an unbounded bearer offer and breaks here.
		emit("missing_expires_at", &forav1.Offer{
			OfferId: "offer-no-expiry",
		}, nil),
	}
}

// meteredVectorPricing is a PER_UNIT price per token with the given estimate
// (nil leaves it unset).
func meteredVectorPricing(estimate *int32) *forav1.Pricing {
	return &forav1.Pricing{
		Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.00002", Currency: "USD",
		Unit: proto.String("tokens"), EstimatedQuantity: estimate,
	}
}

// wireCanonicalVector pins the wire-to-canonical conversion: wire_json is the
// offer exactly as the Connect codec emits it (snake_case proto names, enums as
// names, EmitUnpopulated zero-inflation; JCS-stabilized so the committed file is
// deterministic), canonical_json is the byte sequence the offer signature covers
// (CanonicalOfferBytes: signature/signature_algorithm cleared, omit-unpopulated,
// JCS). Both sides share the snake_case naming, so what a from-wire canonicalizer
// must actually undo is the zero-inflation and the signature fields — it must map
// wire_json to canonical_json exactly.
type wireCanonicalVector struct {
	Name          string          `json:"name"`
	WireJSON      json.RawMessage `json:"wire_json"`
	CanonicalJSON json.RawMessage `json:"canonical_json"`
}

// wireEmitJSONOptions is the Connect wire emission the broker's codec produces:
// snake_case proto names (UseProtoNames=true, the FORA wire contract) plus
// EmitUnpopulated (see sdk/go/connectserver codec).
var wireEmitJSONOptions = protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}

// buildWireCanonicalVectors renders a matrix of offers through BOTH pinned
// option sets. The matrix deliberately covers the pruning rules a from-wire
// canonicalizer must implement: an UNSPECIFIED (zero) enum the wire inflates
// but the canonical form omits, a proto3-optional scalar SET to its zero value
// ("" — kept, presence-tracked), Struct ext key order, two Timestamps, and
// repeated message fields.
func buildWireCanonicalVectors(t *testing.T) []wireCanonicalVector {
	t.Helper()
	emit := func(name string, offer *forav1.Offer) wireCanonicalVector {
		wirePJ, err := wireEmitJSONOptions.Marshal(offer)
		if err != nil {
			t.Fatalf("%s: wire proto-JSON marshal: %v", name, err)
		}
		// JCS-stabilize the committed wire form (protojson whitespace/order is not
		// deterministic); JCS sorts and re-encodes but never RENAMES a key, so the
		// codec's snake_case wire shape survives intact.
		wireCanon, err := jcs.Transform(wirePJ)
		if err != nil {
			t.Fatalf("%s: wire JCS: %v", name, err)
		}
		canonical, err := CanonicalOfferBytes(offer)
		if err != nil {
			t.Fatalf("%s: canonical payload: %v", name, err)
		}
		return wireCanonicalVector{Name: name, WireJSON: wireCanon, CanonicalJSON: canonical}
	}

	structExt, err := structpb.NewStruct(map[string]any{
		"zebra": "last", "alpha": "first",
		"nested": map[string]any{"y": 2.0, "x": 1.0},
	})
	if err != nil {
		t.Fatalf("wire-canonical struct ext: %v", err)
	}

	return []wireCanonicalVector{
		// deliveryMethod is the zero enum: the wire renders
		// DELIVERY_METHOD_UNSPECIFIED, the canonical form omits the field.
		emit("unspecified_enum_pruned", &forav1.Offer{
			OfferId:  "offer-wire-unspec",
			Exchange: "exchange.example.com",
		}),
		// Pricing.unit is proto3 optional: set to "" it is presence-tracked and
		// KEPT by the canonical form, while the sibling non-optional zero scalars
		// the wire inflates are pruned.
		emit("set_empty_optional_unit", &forav1.Offer{
			OfferId:  "offer-wire-unit",
			Exchange: "exchange.example.com",
			Pricing: &forav1.Pricing{
				Model:    forav1.PricingModel_PRICING_MODEL_FREE,
				Currency: "EUR",
				Unit:     proto.String(""),
			},
		}),
		emit("struct_ext_multi_key", &forav1.Offer{
			OfferId:  "offer-wire-struct",
			Exchange: "exchange.example.com",
			Ext:      structExt,
		}),
		emit("two_timestamps", &forav1.Offer{
			OfferId:   "offer-wire-two-ts",
			Exchange:  "exchange.example.com",
			ExpiresAt: timestamppb.New(time.Unix(1_700_000_900, 0).UTC()),
			DataAsOf:  timestamppb.New(time.Unix(1_699_990_000, 0).UTC()),
		}),
		emit("repeated_terms_enum", &forav1.Offer{
			OfferId:        "offer-wire-repeated",
			Exchange:       "exchange.example.com",
			DeliveryMethod: forav1.DeliveryMethod_DELIVERY_METHOD_DIRECT,
			Pricing: &forav1.Pricing{
				Model: forav1.PricingModel_PRICING_MODEL_PER_UNIT, Rate: "0.05", Currency: "USD",
			},
			Terms: []*forav1.LicenseTerm{
				{Semantics: forav1.TermSemantics_TERM_SEMANTICS_ENUMERATED, Scopes: []string{"ai-train"}},
			},
		}),
	}
}

// buildSignRequestVectors signs a fixed set of requests with the REAL Go
// SignRequest and records the exact bytes it emits. Covered set is exactly
// @method @target-uri content-digest authorization signature-agent (no
// entitlement-token header present, so coveredFor never appends the conditional entitlement
// component). created/expires are the non-zero pinned window (reused from the
// pop emitter) so renderParamsTail never drops them. One vector carries an
// empty-authorization bound value; one carries an absent Signature-Agent so the
// empty-bind (static bootstrap) semantics are pinned cross-language.
func buildSignRequestVectors(t *testing.T) []signRequestVector {
	t.Helper()
	const (
		keyid   = "mcp.v1"
		created = int64(1_700_000_000)
		expires = int64(1_700_000_300)
	)
	seed := fixedSeed(0x55)

	type spec struct {
		name           string
		method         string
		url            string
		body           []byte
		authorization  string
		signatureAgent string
		// appendOnly signs through AppendSignature rather than SignRequest — the
		// RELAY path. It binds the same covered set and reaches the same
		// bindAuthorization, so the emitted set is pinned for the relay leg too.
		appendOnly bool
		// nonce is passed as SignOptions.Nonce; empty signs without one.
		nonce string
		// seed, keyid and the window default to the fixture values above; the
		// documentation examples override them.
		seed             []byte
		keyid            string
		created, expires int64
	}
	docBody := []byte(`{"ver":"1.0","exchange":"exchange.example","requester":{"id":"research-bot-42","domain":"research.acme.com","type":"REQUESTER_TYPE_AGENT"},"uris":["https://publisher.example/premium/ai-funding-roundup"]}`)
	docBrokerBody := []byte(`{"ver":"1.0","exchange":"exchange.example","requester":{"id":"research-bot-42","domain":"research.acme.com","type":"REQUESTER_TYPE_AGENT"},"uris":["https://publisher.example/premium/ai-funding-roundup"],"deadline":"0.4s"}`)
	specs := []spec{
		{
			name:           "post_with_authorization",
			method:         "POST",
			url:            "https://broker.example/fora.v1.BrokerService/Fetch",
			body:           []byte(`{"uri":"https://cdn.example/doc"}`),
			authorization:  "Bearer token-123",
			signatureAgent: "https://agent.example",
		},
		{
			// An empty Authorization is still bound and still sent.
			name:           "post_empty_authorization_bound",
			method:         "POST",
			url:            "https://broker.example/fora.v1.BrokerService/Fetch?trace=1",
			body:           []byte(`{"uri":"https://cdn.example/other"}`),
			authorization:  "",
			signatureAgent: "https://agent.example:8443",
		},
		{
			// The RELAY leg. Appending to an unsigned request produces the sig1 a
			// SignRequest would, so what this vector adds over the two above is the
			// emitted set of the relay path.
			name:           "append_relay_leg",
			method:         "POST",
			url:            "https://broker.example/fora.v1.BrokerService/Fetch",
			body:           []byte(`{"uri":"https://cdn.example/relayed"}`),
			authorization:  "",
			signatureAgent: "https://relay.example",
			appendOnly:     true,
		},
		{
			// A fixed 64-byte nonce, as the signing transports emit a random one.
			// Pins where the nonce sits in the parameter tail.
			name:           "post_with_nonce",
			method:         "POST",
			url:            "https://broker.example/fora.v1.BrokerService/Fetch",
			body:           []byte(`{"uri":"https://cdn.example/doc"}`),
			authorization:  "Bearer token-123",
			signatureAgent: "https://agent.example",
			nonce:          nonce64A,
		},
		{
			name:           "post_empty_authorization_bound_with_nonce",
			method:         "POST",
			url:            "https://broker.example/fora.v1.BrokerService/Fetch?trace=1",
			body:           []byte(`{"uri":"https://cdn.example/other"}`),
			authorization:  "",
			signatureAgent: "https://agent.example:8443",
			nonce:          nonce64B,
		},
		{
			name:           "append_relay_leg_with_nonce",
			method:         "POST",
			url:            "https://broker.example/fora.v1.BrokerService/Fetch",
			body:           []byte(`{"uri":"https://cdn.example/relayed"}`),
			authorization:  "",
			signatureAgent: "https://relay.example",
			appendOnly:     true,
			nonce:          nonce64C,
		},
		{
			// The authentication page's Single-Hop Example, signed with the RFC 8037
			// test key. Reproducing it proves the page and the SDKs describe one wire
			// format.
			name: "doc_single_hop_example", method: "POST",
			url:  "https://exchange.example/fora.v1.ExchangeService/DiscoverResources",
			body: docBody, authorization: "", signatureAgent: "https://research.acme.com",
			nonce: "TsrHAzO3DzKC9fj7sOvG6npFB86tAdaQ1XH4pBDIAPmZ93MbjGmCgXXhEyx-lC4CG6yY3ZwTqAVPC6LEeNMXIg",
			seed:  rfc8037Seed, keyid: seedThumbprint(t, rfc8037Seed), created: 1790812800, expires: 1790813100,
		},
		{
			// The page's Multi-Hop Example (Broker): a query the Broker originated and
			// signed alone, with the RFC 9421 Appendix B.1.4 test key.
			name: "doc_broker_example", method: "POST",
			url:  "https://exchange.example/fora.v1.ExchangeService/DiscoverResources",
			body: docBrokerBody, authorization: "", signatureAgent: "https://broker.example",
			nonce: "7jwqQ5Qo8ytp-rXrRXvOS6tktBBVNJ1Rds5Ypdvh2L3QwG_335-eo89DX7NoxoLuwpT-4uz2aEaIZEzqlKbNIg",
			seed:  rfc9421Seed, keyid: seedThumbprint(t, rfc9421Seed), created: 1790812801, expires: 1790813101,
		},
	}

	out := make([]signRequestVector, 0, len(specs))
	for _, s := range specs {
		sSeed, sKeyID, sCreated, sExpires := seed, keyid, created, expires
		if s.seed != nil {
			sSeed, sKeyID, sCreated, sExpires = s.seed, s.keyid, s.created, s.expires
		}
		req, err := http.NewRequest(s.method, s.url, nil)
		if err != nil {
			t.Fatalf("%s: new request: %v", s.name, err)
		}
		if s.authorization != "" {
			req.Header.Set("Authorization", s.authorization)
		}
		signer, err := NewEd25519SignerFromSeed(sKeyID, sSeed)
		if err != nil {
			t.Fatalf("%s: signer: %v", s.name, err)
		}
		sign := SignRequest
		if s.appendOnly {
			sign = AppendSignature
		}
		opts := SignOptions{Created: sCreated, Expires: sExpires, Nonce: s.nonce, SignatureAgent: s.signatureAgent}
		if err := sign(context.Background(), req, s.body, signer, opts); err != nil {
			t.Fatalf("%s: sign: %v", s.name, err)
		}
		params := sigParams{
			Label: "sig1", Covered: coveredFor(req, "sig1"), KeyID: sKeyID, Alg: AlgEd25519,
			Created: sCreated, Expires: sExpires, Nonce: s.nonce, Tag: WBATag,
		}
		base, err := buildSignatureBase(req, params)
		if err != nil {
			t.Fatalf("%s: build base: %v", s.name, err)
		}
		// The request was built bare, so what it carries after signing IS the
		// signer's contribution.
		emitted := make(map[string][]string, len(req.Header))
		for name := range req.Header {
			emitted[strings.ToLower(name)] = req.Header.Values(name)
		}
		pub := ed25519.NewKeyFromSeed(sSeed).Public().(ed25519.PublicKey)
		out = append(out, signRequestVector{
			Name: s.name, Method: s.method, URL: s.url, BodyHex: hex.EncodeToString(s.body),
			Authorization: s.authorization, SignatureAgent: s.signatureAgent, AppendOnly: s.appendOnly,
			KeyID: sKeyID, Created: sCreated, Expires: sExpires, Nonce: s.nonce,
			SignerSeedHex: hex.EncodeToString(sSeed), PubkeyB64URL: b64urlNoPad(pub),
			ContentDigest: req.Header.Get("Content-Digest"), SignatureBase: base,
			SignatureInput: req.Header.Get("Signature-Input"), Signature: req.Header.Get("Signature"),
			EmittedHeaders: emitted,
		})
	}
	return out
}

// verifyRequestNegVector mirrors the NegVerifyVector shape the TS/py server-verify
// parity suites read. It is a fully-formed SINGLE-SIG request whose verification
// MUST be rejected, tagged with the exact reason token the connectserver taxonomy
// (classify.go RejectReason.String()) assigns — proven by running the REAL Go
// verify path (VerifyRequest + the replay orchestration) against the vector and
// asserting it produces that reason. The port reconstructs the request from these
// fields, injects resolver_pubkey for keyid, pins the clock to `now`, and asserts
// the same rejection.
type verifyRequestNegVector struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	URL           string `json:"url"`
	BodyHex       string `json:"body_hex"`
	Authorization string `json:"authorization"`
	// SignatureAgent is the Signature-Agent header value the request carries.
	SignatureAgent string `json:"signature_agent"`
	ContentDigest  string `json:"content_digest"`
	SignatureInput string `json:"signature_input"`
	Signature      string `json:"signature"`
	// KeyID is the keyid the request's Signature-Input claims.
	KeyID string `json:"keyid"`
	// ResolverKeyID / ResolverPubkeyB64URL describe the key the injected resolver
	// serves: for most cases resolver_keyid==keyid and the pubkey is the true
	// signer key; for neg_wrong_key the resolver serves a DIFFERENT (wrong) key so
	// the crypto check fails.
	ResolverKeyID        string `json:"resolver_keyid"`
	ResolverPubkeyB64URL string `json:"resolver_pubkey_b64url"`
	// Now is the verifier clock the case is pinned to (inside the window except for
	// neg_expired, which is post-expiry).
	Now int64 `json:"now"`
	// ExpectedReason is RejectReason.String() for the Go rejection, "" for a
	// request the verifier accepts (the accept corpus).
	ExpectedReason string `json:"expected_reason"`
	// ExpectedAcceptSignature is the Accept-Signature value the verifier answers
	// the rejection with (helpers.AcceptSignatureFor), "" when it answers with
	// none: a refusal for a missing component or a refused form names what the
	// profile requires, a well-formed signature that fails does not.
	ExpectedAcceptSignature string `json:"expected_accept_signature,omitempty"`
	// ExpectedSignatureAgent is the key-directory origin an accepted request's
	// signature names (VerifiedRequest.SignatureAgent); accept corpus only.
	ExpectedSignatureAgent string `json:"expected_signature_agent,omitempty"`
	// Replay marks the neg_replay case: the same request is presented twice; the
	// SECOND presentation is the one that must be rejected as "replay".
	Replay bool `json:"replay,omitempty"`
	// Entitlement, when non-empty, is set as the X-Entitlement-Token request
	// header. The neg_entitlement_uncovered case carries it WITHOUT the signature
	// covering x-entitlement-token, so a conformant server-verify must reject an
	// unsigned entitlement claim (enforceEntitlementCoverage). Format-neutral —
	// the token value stands in for any JWT/opaque capability token.
	Entitlement string `json:"entitlement,omitempty"`
	// OmitHeaders names the header fields the request does NOT carry, deleted after
	// the base ones are set. ABSENT is not EMPTY: the base is rebuilt from the
	// request that ARRIVED, so a covered name with no field line under it cannot be
	// reconstructed at all, while an empty one reconstructs to the empty value the
	// signer bound. Reading these with Values rather than Get is what tells the two
	// apart — a port defaulting an absent header to "" invents a value and accepts
	// the request this case proves is refused.
	OmitHeaders []string `json:"omit_headers,omitempty"`
	// ExtraHeaders are field lines ADDED after the base ones, never replacing them.
	// Header names are case-insensitive on the wire, so a second line under a name
	// the signature covers belongs to that same covered name and joins with ", "
	// before the base is rebuilt — it changes the covered value rather than
	// overriding it, which is how an unsigned token slipped in beside a signed one
	// is refused instead of honoured. A replay's header map is keyed by string, so
	// the spelling here MUST differ in case from the lowercased base key or the two
	// lines collapse into one and the case proves nothing.
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// negRequest is one signed request the negative emitter mutates into a reject case.
type negRequest struct {
	method, url    string
	body           []byte
	authorization  string
	signatureAgent string // the Signature-Agent header value
	req            *http.Request
	sigInput       string
	sig            string
	contentDigest  string
}

// Fixed request material for the single-signature verify corpora.
const (
	negMethod   = "POST"
	negURL      = "https://broker.example/fora.v1.BrokerService/Fetch"
	negKeyID    = "mcp.v1"
	negCreated  = int64(1_700_000_000)
	negExpires  = int64(1_700_000_300)
	negFreshNow = int64(1_700_000_100) // inside window
	negStaleNow = int64(1_700_000_400) // past expires
	negAgent    = "https://agent.example"
)

var negBody = []byte(`{"uri":"https://cdn.example/neg"}`)

// signNegBase signs a fixed request with the neg-vector signer (seed 0x77) and
// returns the wire artifacts, so each negative is a real signature the Go verifier
// accepts before the case-specific mutation flips it to a rejection.
func signNegBase(t *testing.T, seed []byte) negRequest {
	t.Helper()
	return signNegBaseWith(t, seed, "Bearer neg-token")
}

// signNegBaseWith is signNegBase over an explicit Authorization value, so a base
// can be signed with the EMPTY value an agent holding no token binds.
func signNegBaseWith(t *testing.T, seed []byte, authorization string) negRequest {
	t.Helper()
	req, err := http.NewRequest(negMethod, negURL, nil)
	if err != nil {
		t.Fatalf("neg base: new request: %v", err)
	}
	req.Header.Set("Authorization", authorization)
	signer, err := NewEd25519SignerFromSeed(negKeyID, seed)
	if err != nil {
		t.Fatalf("neg base: signer: %v", err)
	}
	opts := SignOptions{Created: negCreated, Expires: negExpires, SignatureAgent: negAgent}
	if err := SignRequest(context.Background(), req, negBody, signer, opts); err != nil {
		t.Fatalf("neg base: sign: %v", err)
	}
	return negFrom(req, authorization)
}

func negFrom(req *http.Request, authorization string) negRequest {
	return negRequest{
		method: negMethod, url: negURL, body: negBody,
		authorization: authorization, signatureAgent: req.Header.Get(SignatureAgentHeader), req: req,
		sigInput:      req.Header.Get("Signature-Input"),
		sig:           req.Header.Get("Signature"),
		contentDigest: req.Header.Get("Content-Digest"),
	}
}

// signNegByHand signs the fixed request with exactly the parameters edit leaves:
// the production signer's sig1 parameters edited, under the Signature-Agent header
// agentHeader. It builds the signatures the shipped signer refuses to make — no
// tag, the legacy or bare Signature-Agent form, a missing component — as an
// outdated or hostile signer would.
func signNegByHand(t *testing.T, seed []byte, agentHeader string, edit func(*sigParams)) negRequest {
	t.Helper()
	req, err := http.NewRequest(negMethod, negURL, nil)
	if err != nil {
		t.Fatalf("neg by hand: new request: %v", err)
	}
	req.Header.Set("Authorization", "")
	req.Header.Set("Content-Digest", ContentDigest(negBody))
	req.Header.Set(SignatureAgentHeader, agentHeader)
	signer, err := NewEd25519SignerFromSeed(negKeyID, seed)
	if err != nil {
		t.Fatalf("neg by hand: signer: %v", err)
	}
	p := requestSigParams(req, "sig1", signer, SignOptions{Created: negCreated, Expires: negExpires})
	edit(&p)
	if err := signWithParams(context.Background(), req, p, signer, sigWriteSet); err != nil {
		t.Fatalf("neg by hand: sign: %v", err)
	}
	return negFrom(req, "")
}

// verifyNegOutcome drives the REAL Go verify path (VerifyMultisigRequestResolved,
// then the connectserver replay orchestration when replaySeen!=nil) over a
// reconstructed request and returns the classified reject reason token and the
// Accept-Signature value the refusal carries — the authoritative oracle the
// emitted expectations are taken from. For an accepted request it returns "" and
// the directory the signature names.
func verifyNegOutcome(
	t *testing.T, v verifyRequestNegVector, resolverPub ed25519.PublicKey,
	replaySeen map[string]bool,
) (reason, accept, directory string) {
	t.Helper()
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", v.Name, err)
	}
	req, err := http.NewRequest(v.Method, v.URL, nil)
	if err != nil {
		t.Fatalf("%s: new request: %v", v.Name, err)
	}
	setIfPresent := func(name, value string) {
		req.Header.Set(name, value)
	}
	setIfPresent("Content-Digest", v.ContentDigest)
	setIfPresent("Authorization", v.Authorization)
	setIfPresent(SignatureAgentHeader, v.SignatureAgent)
	setIfPresent("Signature-Input", v.SignatureInput)
	setIfPresent("Signature", v.Signature)
	if v.Entitlement != "" {
		req.Header.Set(entitlementHeader, v.Entitlement)
	}
	for _, name := range v.OmitHeaders {
		req.Header.Del(name)
	}
	// Add, not Set: the point of an extra line is that it lands BESIDE the base one
	// under the same covered name. Sorted so the emitted vector is deterministic —
	// Go map iteration is not.
	for _, name := range slices.Sorted(maps.Keys(v.ExtraHeaders)) {
		req.Header.Add(name, v.ExtraHeaders[name])
	}
	resolver := NewStaticKeyResolver(map[string]ed25519.PublicKey{})
	if resolverPub != nil {
		resolver.Put(v.ResolverKeyID, resolverPub)
	}
	opts := VerifyOptions{Now: time.Unix(v.Now, 0)}
	sigs, verr := VerifyMultisigRequestResolved(context.Background(), req, body, resolver, opts)
	if verr != nil {
		accept, _ := AcceptSignatureFor(verr)
		return classifyNegReason(verr), accept, ""
	}
	// Replay orchestration mirrors connectserver.serverConfig.verify: the nonce is
	// keyid+"\x00"+std-base64(sig); a seen nonce classifies as "replay".
	for i := range sigs {
		nonce := sigs[i].KeyID + "\x00" + sigs[i].Signature
		if replaySeen != nil {
			if replaySeen[nonce] {
				return "replay", "", ""
			}
			replaySeen[nonce] = true
		}
	}
	return "", "", sigs[0].SignatureAgent
}

// classifyNegReason mirrors connectserver.ClassifyReject over the helpers
// sentinels: the hop budget and an incomplete coverage of an earlier signature
// have their own tokens, and every other signature-authenticity, form, freshness
// or key failure is the default "signature" token.
func classifyNegReason(err error) string {
	switch {
	case errors.Is(err, ErrTooManyHops):
		return "hop_budget"
	case errors.Is(err, ErrBrokenSignatureChain):
		return "broken_chain"
	default:
		return "signature"
	}
}

// buildVerifyRequestNegVectors emits the SINGLE-SIG negative-verify corpus the
// TS/py server-verify suites consume. Each case is a real signature, made by the
// Go signer or by hand for a form the signer refuses, then mutated, and each
// recorded expected_reason and expected_accept_signature is taken from the REAL Go
// verify path, never hand-authored.
func buildVerifyRequestNegVectors(t *testing.T) []verifyRequestNegVector {
	t.Helper()
	seed := fixedSeed(0x77)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	pubB64 := b64urlNoPad(pub)
	base := signNegBase(t, seed)
	bodyHex := hex.EncodeToString(base.body)

	// mkFrom builds a vector template carrying r's (valid) artifacts; each case
	// then overrides the field it mutates.
	mkFrom := func(r negRequest, name string, now int64) verifyRequestNegVector {
		return verifyRequestNegVector{
			Name: name, Method: r.method, URL: r.url, BodyHex: bodyHex,
			Authorization: r.authorization, SignatureAgent: r.signatureAgent,
			ContentDigest: r.contentDigest, SignatureInput: r.sigInput, Signature: r.sig,
			KeyID: negKeyID, ResolverKeyID: negKeyID, ResolverPubkeyB64URL: pubB64, Now: now,
		}
	}
	mk := func(name string, now int64) verifyRequestNegVector { return mkFrom(base, name, now) }

	badSig := mk("neg_bad_sig", negFreshNow)
	badSig.Signature = corruptSignatureLastByte(base.sig)

	// The base request is valid; presented twice the second trips the replay store.
	replay := mk("neg_replay", negFreshNow)
	replay.Replay = true

	expired := mk("neg_expired", negStaleNow)

	// The resolver serves a DIFFERENT key (seed 0x78) for the keyid.
	wrongKey := mk("neg_wrong_key", negFreshNow)
	wrongKey.ResolverPubkeyB64URL = b64urlNoPad(ed25519.NewKeyFromSeed(fixedSeed(0x78)).Public().(ed25519.PublicKey))

	tampered := mk("neg_tampered_authorization", negFreshNow)
	tampered.Authorization = base.authorization + "-tampered"

	// The covered Signature-Agent member repointed at another directory after
	// signing: the signature no longer verifies.
	repointed := mk("neg_repointed_signature_agent", negFreshNow)
	repointed.SignatureAgent = `sig1="https://evil.example"`

	// A validly-signed request that ALSO carries X-Entitlement-Token WITHOUT the
	// signature covering it: the claim is unsigned, so it is refused, and the
	// refusal asks for the header to be covered.
	entitlement := mk("neg_entitlement_uncovered", negFreshNow)
	entitlement.Entitlement = "jwt:demo-unsigned-entitlement-token"

	// Signed over an EMPTY Authorization, which is load-bearing: omitting a header
	// bound non-empty is refused whichever way a port reads it, while omitting one
	// bound empty is refused only by a port that tells absent from empty.
	emptyBase := signNegBaseWith(t, seed, "")
	mkEmpty := func(name string, now int64) verifyRequestNegVector { return mkFrom(emptyBase, name, now) }
	absentAuthz := mkEmpty("neg_absent_authorization", negFreshNow)
	absentAuthz.OmitHeaders = []string{"Authorization"}
	absentAgent := mkEmpty("neg_absent_signature_agent", negFreshNow)
	absentAgent.OmitHeaders = []string{SignatureAgentHeader}

	// A SECOND Authorization field line beside the signed one, under a different
	// spelling: both lines join before the base is rebuilt, so the covered value
	// changes and the request is refused.
	dupAuthz := mkEmpty("neg_duplicate_authorization", negFreshNow)
	dupAuthz.ExtraHeaders = map[string]string{"Authorization": "Bearer unsigned-token"}

	// The entitlement header carried TWICE, an empty line ahead of a real token, on
	// a signature that does not cover it. Joining makes the value non-empty, so the
	// coverage rule fires. The EMPTY value sits under the capitalised spelling,
	// which sorts first, so it is the first line a port replays.
	shadowedEntitlement := mkEmpty("neg_shadowed_entitlement", negFreshNow)
	shadowedEntitlement.ExtraHeaders = map[string]string{
		"X-Entitlement-Token": "",
		"x-entitlement-token": "jwt:unsigned-capability-token",
	}

	// The forms the profile refuses, signed by hand because the signer will not.
	member := `sig1="` + negAgent + `"`
	noTag := mkFrom(signNegByHand(t, seed, member, func(p *sigParams) { p.Tag = "" }), "neg_missing_tag", negFreshNow)
	wrongTag := mkFrom(signNegByHand(t, seed, member, func(p *sigParams) { p.Tag = "other-tag" }), "neg_wrong_tag", negFreshNow)
	plainAgent := func(p *sigParams) {
		p.Covered = append(plainComponents(requiredCoveredComponents...), CoveredComponent{Name: signatureAgentLower})
	}
	// The v1.0.8 form: an unquoted URL covered as plain signature-agent.
	bare := mkFrom(signNegByHand(t, seed, negAgent, plainAgent), "neg_bare_signature_agent", negFreshNow)
	// The signature covers member sig1, which the dictionary does not carry.
	noMember := mkFrom(signNegByHand(t, seed, member, func(*sigParams) {}),
		"neg_signature_agent_member_absent", negFreshNow)
	noMember.SignatureAgent = `agent2="` + negAgent + `"`
	typeOther := mkFrom(signNegByHand(t, seed, member+`;type="jwks"`, func(*sigParams) {}),
		"neg_signature_agent_type_not_directory", negFreshNow)
	notOrigin := mkFrom(signNegByHand(t, seed, `sig1="http://agent.example"`, func(*sigParams) {}),
		"neg_signature_agent_not_https_origin", negFreshNow)
	withPath := mkFrom(signNegByHand(t, seed, `sig1="https://agent.example/keys"`, func(*sigParams) {}),
		"neg_signature_agent_not_an_origin", negFreshNow)
	// A signature that omits authorization, a FORA RPC component.
	noAuthz := mkFrom(signNegByHand(t, seed, member, func(p *sigParams) {
		p.Covered = append(plainComponents("@method", "@target-uri", "content-digest"), signatureAgentComponent("sig1"))
	}), "neg_missing_fora_component", negFreshNow)
	// No signature at all.
	unsigned := mk("neg_unsigned", negFreshNow)
	unsigned.OmitHeaders = []string{"Signature-Input", "Signature"}

	out := []verifyRequestNegVector{
		badSig, replay, expired, wrongKey, tampered, repointed, entitlement, shadowedEntitlement,
		absentAuthz, absentAgent, dupAuthz,
		noTag, wrongTag, bare, noMember, typeOther, notOrigin, withPath, noAuthz, unsigned,
	}
	// Derive the expectations from the REAL Go verify path — never hand-author them.
	for i := range out {
		assertExtraHeaderSpelling(t, out[i].Name, out[i].ExtraHeaders)
		out[i].ExpectedReason, out[i].ExpectedAcceptSignature, _ = oracleNegOutcome(t, out[i])
		if out[i].ExpectedReason == "" {
			t.Fatalf("neg vector %s: the oracle accepted it", out[i].Name)
		}
	}
	return out
}

// buildVerifyRequestAcceptVectors emits the forms a FORA verifier must ACCEPT
// although the shipped signer never makes them, because WG-00 permits them and
// other Web Bot Auth signers send them: the legacy String Signature-Agent on a
// single-signature request, a member key that differs from the label, a
// type=directory member parameter, no nonce, and a foreign parameter order. Same
// shape as the negative corpus, with expected_reason "".
func buildVerifyRequestAcceptVectors(t *testing.T) []verifyRequestNegVector {
	t.Helper()
	seed := fixedSeed(0x77)
	pubB64 := b64urlNoPad(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	mk := func(name string, r negRequest) verifyRequestNegVector {
		return verifyRequestNegVector{
			Name: name, Method: r.method, URL: r.url, BodyHex: hex.EncodeToString(r.body),
			Authorization: r.authorization, SignatureAgent: r.signatureAgent,
			ContentDigest: r.contentDigest, SignatureInput: r.sigInput, Signature: r.sig,
			KeyID: negKeyID, ResolverKeyID: negKeyID, ResolverPubkeyB64URL: pubB64, Now: negFreshNow,
		}
	}
	member := `sig1="` + negAgent + `"`
	out := []verifyRequestNegVector{
		mk("accept_signed_by_the_sdk", signNegBase(t, seed)),
		mk("accept_legacy_string_signature_agent", signNegByHand(t, seed, `"`+negAgent+`"`, func(p *sigParams) {
			p.Covered = append(plainComponents(requiredCoveredComponents...), CoveredComponent{Name: signatureAgentLower})
		})),
		mk("accept_member_key_differs_from_label", signNegByHand(t, seed, `agent="`+negAgent+`"`, func(p *sigParams) {
			p.Covered = append(plainComponents(requiredCoveredComponents...), signatureAgentComponent("agent"))
		})),
		mk("accept_member_type_directory", signNegByHand(t, seed, member+`;type="directory"`, func(*sigParams) {})),
		mk("accept_member_type_directory_token", signNegByHand(t, seed, member+`;type=directory`, func(*sigParams) {})),
		mk("accept_no_nonce", signNegByHand(t, seed, member, func(p *sigParams) { p.Nonce = "" })),
		mk("accept_other_members_beside", signNegByHand(t, seed, `other="https://other.example", `+member, func(*sigParams) {})),
		mk("accept_nonce_of_other_length", signNegByHand(t, seed, member, func(p *sigParams) { p.Nonce = "AAECAwQFBgcICQoLDA0ODw" })),
	}
	for i := range out {
		reason, accept, dir := oracleNegOutcome(t, out[i])
		if reason != "" || accept != "" {
			t.Fatalf("accept vector %s: the oracle refused it: %q", out[i].Name, reason)
		}
		out[i].ExpectedSignatureAgent = dir
	}
	return out
}

// baseVectorHeaderNames are the field names a replay writes into its header bag from
// the vector's own scalar columns, lowercased — the entries an extra line has to land
// BESIDE rather than replace.
var baseVectorHeaderNames = map[string]bool{
	"content-digest": true, "signature-input": true, "signature": true,
	"authorization": true, signatureAgentLower: true,
}

// assertExtraHeaderSpelling enforces the rule the ExtraHeaders doc states, which is
// otherwise only a comment: an extra line duplicating a name the replay already wrote
// from a scalar column MUST be spelled in a different case, or a replay's map would
// overwrite the base entry instead of adding a second field line.
func assertExtraHeaderSpelling(t *testing.T, name string, extra map[string]string) {
	t.Helper()
	for key := range extra {
		lower := strings.ToLower(key)
		if !baseVectorHeaderNames[lower] {
			continue
		}
		if key == lower {
			t.Fatalf("vector %s: extra header %q duplicates a base header name in the SAME "+
				"spelling — a replay's map would overwrite the base entry instead of adding "+
				"a second field line, and the case would assert nothing", name, key)
		}
	}
}

// oracleNegOutcome runs the emitted vector through the REAL Go verify path and
// returns the reason token, the Accept-Signature value and, for an accepted
// request, the directory — so the expectations are authoritative.
func oracleNegOutcome(t *testing.T, v verifyRequestNegVector) (reason, accept, directory string) {
	t.Helper()
	resolverPub := resolverPubOf(t, v)
	var seen map[string]bool
	if v.Replay {
		seen = map[string]bool{}
		_, _, _ = verifyNegOutcome(t, v, resolverPub, seen) // first presentation records the nonce
	}
	return verifyNegOutcome(t, v, resolverPub, seen)
}

func resolverPubOf(t *testing.T, v verifyRequestNegVector) ed25519.PublicKey {
	t.Helper()
	if v.ResolverPubkeyB64URL == "" {
		return nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(v.ResolverPubkeyB64URL)
	if err != nil {
		t.Fatalf("%s: decode resolver pub: %v", v.Name, err)
	}
	return ed25519.PublicKey(raw)
}

// corruptSignatureLastByte decodes the `sig1=:<b64>:` value, flips the final byte,
// and re-encodes — a minimal, deterministic mutation that fails the Ed25519 check
// while keeping the wire form well-formed (so the rejection is a signature failure,
// not a parse failure).
func corruptSignatureLastByte(sig string) string {
	i := strings.IndexByte(sig, ':')
	j := strings.LastIndexByte(sig, ':')
	if i < 0 || j <= i {
		return sig
	}
	label := sig[:i]
	raw, err := base64.StdEncoding.DecodeString(sig[i+1 : j])
	if err != nil || len(raw) == 0 {
		return sig
	}
	raw[len(raw)-1] ^= 0x01
	return label + ":" + base64.StdEncoding.EncodeToString(raw) + ":"
}

// verifyNegVectorOutcome asserts each emitted vector reaches the recorded outcome
// through the REAL Go verify path — the self-consistency guard that makes the
// expectations authoritative rather than hand-authored.
func verifyNegVectorOutcome(t *testing.T, v verifyRequestNegVector) {
	t.Helper()
	resolverPub := resolverPubOf(t, v)
	var seen map[string]bool
	if v.Replay {
		seen = map[string]bool{}
		// First presentation must be accepted (empty reason), recording the nonce.
		if got, _, _ := verifyNegOutcome(t, v, resolverPub, seen); got != "" {
			t.Fatalf("%s: first presentation unexpectedly rejected: %q", v.Name, got)
		}
	}
	reason, accept, dir := verifyNegOutcome(t, v, resolverPub, seen)
	if reason != v.ExpectedReason || accept != v.ExpectedAcceptSignature || dir != v.ExpectedSignatureAgent {
		t.Fatalf("vector %s: oracle (%q, %q, %q), recorded (%q, %q, %q)", v.Name,
			reason, accept, dir, v.ExpectedReason, v.ExpectedAcceptSignature, v.ExpectedSignatureAgent)
	}
}

// verifySignRequestVector round-trips a sign-request vector through the REAL Go
// VerifyRequest at a pinned `now` inside the window, so any divergence surfaces
// in the Go drift gate rather than in a port.
func verifySignRequestVector(t *testing.T, v signRequestVector) {
	t.Helper()
	pubBytes, err := base64.RawURLEncoding.DecodeString(v.PubkeyB64URL)
	if err != nil {
		t.Fatalf("%s: decode pub: %v", v.Name, err)
	}
	body, err := hex.DecodeString(v.BodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", v.Name, err)
	}
	req, err := http.NewRequest(v.Method, v.URL, nil)
	if err != nil {
		t.Fatalf("%s: new request: %v", v.Name, err)
	}
	for name, values := range v.EmittedHeaders {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	now := time.Unix((v.Created+v.Expires)/2, 0)
	vr, err := VerifyRequest(req, body, ed25519.PublicKey(pubBytes), VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("sign-request vector %s: oracle VerifyRequest rejected a self-signed vector: %v", v.Name, err)
	}
	if vr.SignatureAgent != v.SignatureAgent {
		t.Fatalf("sign-request vector %s: verified directory %q, signed as %q", v.Name, vr.SignatureAgent, v.SignatureAgent)
	}
}

// buildAcceptanceVectors signs a fixed set of offer acceptances with the REAL Go
// SignOfferAcceptance, seeded 0102..1f20 (shared with the app fixture). Records
// canonical bytes + signature hex + std-base64 pubkey.
//
// The specs cover each field the canonical form may omit, one per vector. Go omits
// them structurally (EmitUnpopulated=false); the Python and TS faces hand-build the
// object and have to drop empty members themselves, so an omission they miss shows
// up here as a byte mismatch and nowhere else.
func buildAcceptanceVectors(t *testing.T) []acceptanceVector {
	t.Helper()
	seed, err := hex.DecodeString(acceptanceSeedHex)
	if err != nil {
		t.Fatalf("decode acceptance seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	type spec struct {
		name            string
		offerSig        string
		requesterID     string
		requesterDomain string
		idempotencyKey  string
	}
	// An empty requester id or domain is no longer a signable acceptance: those
	// cases moved to buildRefusedAcceptanceVectors, which every SDK must refuse.
	specs := []spec{
		{"all_present", "ex-offer-sig-hex", "agent-1", "agent.example.com", "idem-1"},
		// The one field the canonical form can still omit.
		// TransactionRequest.idempotency_key carries min_len:1 so the wire rejects
		// an empty one, but these accessors are the layer below that check and must
		// still agree on the bytes. The hand-built Python/TS payloads enumerate the
		// keys instead of inheriting EmitUnpopulated=false, so without this vector
		// the omission guard can be dropped in either language with every gate
		// still green.
		{"empty_idempotency_key", "sig4deadbeef", "agent-4", "agent.example.com", ""},
	}

	out := make([]acceptanceVector, 0, len(specs))
	for _, s := range specs {
		offer := &forav1.Offer{Signature: s.offerSig}
		requester := &forav1.Requester{Id: s.requesterID, Domain: s.requesterDomain}
		canon, err := CanonicalAcceptanceBytes(offer, requester, s.idempotencyKey)
		if err != nil {
			t.Fatalf("%s: canonical: %v", s.name, err)
		}
		sigHex, err := SignOfferAcceptance(priv, offer, requester, s.idempotencyKey)
		if err != nil {
			t.Fatalf("%s: sign: %v", s.name, err)
		}
		// Self-check: the oracle verifies its own signature.
		if err := VerifyOfferAcceptance(offer, requester, s.idempotencyKey, sigHex, pub); err != nil {
			t.Fatalf("%s: oracle rejected its own acceptance signature: %v", s.name, err)
		}
		out = append(out, acceptanceVector{
			Name:            s.name,
			OfferSig:        s.offerSig,
			RequesterID:     s.requesterID,
			RequesterDomain: s.requesterDomain,
			IdempotencyKey:  s.idempotencyKey,
			CanonicalJCS:    string(canon),
			SignatureHex:    sigHex,
			PubkeyB64:       pubB64,
			SeedHex:         acceptanceSeedHex,
		})
	}
	return out
}

// buildRefusedAcceptanceVectors records one acceptance per requester field left
// empty, and checks the Go oracle refuses each with ErrAcceptanceRequesterEmpty at
// all three entry points. The recorded bytes are rendered and signed BELOW the
// refusal (canonicalSignPayload and a raw Ed25519 signature), so a port can prove
// its verifier refuses them although the signature over them verifies.
func buildRefusedAcceptanceVectors(t *testing.T) []refusedAcceptanceVector {
	t.Helper()
	seed, err := hex.DecodeString(acceptanceSeedHex)
	if err != nil {
		t.Fatalf("decode acceptance seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	specs := []refusedAcceptanceVector{
		{Name: "empty_requester_id", Empty: "requester_id", OfferSig: "sig3deadbeef",
			RequesterDomain: "agent.example.com", IdempotencyKey: "idem-3"},
		{Name: "empty_requester_domain", Empty: "requester_domain", OfferSig: "sig2deadbeef",
			RequesterID: "agent-2", IdempotencyKey: "idem-2"},
	}
	for i := range specs {
		v := &specs[i]
		offer := &forav1.Offer{Signature: v.OfferSig}
		requester := &forav1.Requester{Id: v.RequesterID, Domain: v.RequesterDomain}
		unchecked, err := canonicalSignPayload(&forav1.AgentAcceptancePayload{
			OfferSig: v.OfferSig, RequesterId: v.RequesterID,
			RequesterDomain: v.RequesterDomain, IdempotencyKey: v.IdempotencyKey,
		})
		if err != nil {
			t.Fatalf("%s: unchecked render: %v", v.Name, err)
		}
		sig := ed25519.Sign(priv, unchecked)
		if _, err := CanonicalAcceptanceBytes(offer, requester, v.IdempotencyKey); !errors.Is(err, ErrAcceptanceRequesterEmpty) {
			t.Fatalf("%s: CanonicalAcceptanceBytes = %v, want ErrAcceptanceRequesterEmpty", v.Name, err)
		}
		if _, err := SignOfferAcceptance(priv, offer, requester, v.IdempotencyKey); !errors.Is(err, ErrAcceptanceRequesterEmpty) {
			t.Fatalf("%s: SignOfferAcceptance = %v, want ErrAcceptanceRequesterEmpty", v.Name, err)
		}
		if err := VerifyOfferAcceptance(offer, requester, v.IdempotencyKey, hex.EncodeToString(sig), pub); !errors.Is(err, ErrAcceptanceRequesterEmpty) {
			t.Fatalf("%s: VerifyOfferAcceptance = %v, want ErrAcceptanceRequesterEmpty", v.Name, err)
		}
		v.CanonicalJCS = string(unchecked)
		v.SignatureHex = hex.EncodeToString(sig)
		v.PubkeyB64 = base64.StdEncoding.EncodeToString(pub)
		v.SeedHex = acceptanceSeedHex
	}
	return specs
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
	got := err == nil
	if got != v.ExpectedValid {
		t.Fatalf("signed-url vector %s: oracle verdict=%v, recorded=%v (err=%v)", v.Name, got, v.ExpectedValid, err)
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	if err := vectorio.Write(path, v); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestGenerateVectors emits the signed-URL and PoP golden vectors. It is a
// verification no-op by default (asserts the committed files match what the
// emitter would produce right now); with FORA_UPDATE_VECTORS=1 it (re)writes
// them. This makes the emitter both the generator and its own drift gate.
func TestGenerateVectors(t *testing.T) {
	signedURLVectors := buildSignedURLVectors(t)
	for _, v := range signedURLVectors {
		verifySignedURLVector(t, v)
	}
	popVectors := buildPopVectors(t)

	signRequestVectors := buildSignRequestVectors(t)
	for _, v := range signRequestVectors {
		verifySignRequestVector(t, v)
	}
	verifyRequestNegVectors := buildVerifyRequestNegVectors(t)
	for _, v := range verifyRequestNegVectors {
		verifyNegVectorOutcome(t, v)
	}
	verifyRequestAcceptVectors := buildVerifyRequestAcceptVectors(t)
	for _, v := range verifyRequestAcceptVectors {
		verifyNegVectorOutcome(t, v)
	}
	acceptanceVectors := buildAcceptanceVectors(t)
	refusedAcceptanceVectors := buildRefusedAcceptanceVectors(t)
	offerVerifyVectors := buildOfferVerifyVectors(t)
	wireCanonicalVectors := buildWireCanonicalVectors(t)

	signedURLPath := filepath.Join("testdata", "signedurl-vectors.json")
	popPath := filepath.Join("testdata", "pop-vectors.json")
	signRequestPath := filepath.Join("testdata", "sign-request-vectors.json")
	verifyNegPath := filepath.Join("testdata", "verify-request-neg-vectors.json")
	verifyAcceptPath := filepath.Join("testdata", "verify-request-accept-vectors.json")
	acceptancePath := filepath.Join("testdata", "acceptance-vectors.json")
	offerVerifyPath := filepath.Join("testdata", "offer-verify-vectors.json")
	wireCanonicalPath := filepath.Join("testdata", "wire-canonical-vectors.json")

	// The sign-request + acceptance parity suites read a {"vectors": [...]} object
	// (the thumbprint-vectors.json shape), not a bare array like signedurl/pop. The
	// acceptance + offer-verify docs additionally carry a canonicalization marker
	// ("jcs") so a reader cannot confuse them with the old proto-binary form.
	signRequestDoc := map[string]any{"vectors": signRequestVectors}
	verifyNegDoc := map[string]any{"vectors": verifyRequestNegVectors}
	verifyAcceptDoc := map[string]any{"vectors": verifyRequestAcceptVectors}
	acceptanceDoc := map[string]any{
		"canonicalization": "jcs",
		"vectors":          acceptanceVectors,
		"refused":          refusedAcceptanceVectors,
	}
	offerVerifyDocValue := offerVerifyDoc{Canonicalization: "jcs", Vectors: offerVerifyVectors}
	wireCanonicalDoc := map[string]any{"canonicalization": "jcs", "vectors": wireCanonicalVectors}

	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, signedURLPath, signedURLVectors)
		writeJSON(t, popPath, popVectors)
		writeJSON(t, signRequestPath, signRequestDoc)
		writeJSON(t, verifyNegPath, verifyNegDoc)
		writeJSON(t, verifyAcceptPath, verifyAcceptDoc)
		writeJSON(t, acceptancePath, acceptanceDoc)
		writeJSON(t, offerVerifyPath, offerVerifyDocValue)
		writeJSON(t, wireCanonicalPath, wireCanonicalDoc)
		return
	}

	// Default run: assert the committed files are byte-identical to a fresh emit.
	assertMatches(t, signedURLPath, signedURLVectors)
	assertMatches(t, popPath, popVectors)
	assertMatches(t, signRequestPath, signRequestDoc)
	assertMatches(t, verifyNegPath, verifyNegDoc)
	assertMatches(t, verifyAcceptPath, verifyAcceptDoc)
	assertMatches(t, acceptancePath, acceptanceDoc)
	assertMatches(t, offerVerifyPath, offerVerifyDocValue)
	assertMatches(t, wireCanonicalPath, wireCanonicalDoc)
}

func assertMatches(t *testing.T, path string, v any) {
	t.Helper()
	stale, err := vectorio.Stale(path, v)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", path)
	}
}
