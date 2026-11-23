package resolvers_test

// Golden-vector emitter for the cross-language active-Ed25519-key selector parity
// corpus. sdk/python `active_ed25519_key(_with_expiry)` and sdk/ts
// `activeEd25519Key(WithExpiry)` REPLAY this corpus and MUST reproduce the sdk/go
// `ActiveEd25519Key` oracle's selection for EVERY vector.
//
// Each vector is a WBA directory (keys[] with validity windows + JWK `x`), an
// optional max_scan, and the oracle's verdict: the selected key's DOCUMENT-ORDER
// index (-1 = none), its raw public key (base64url), and its not_after. The
// verdict is produced by RUNNING the real Go selector against the built directory
// — Go is the oracle, never a hand-authored table — and a per-vector sanity gate
// asserts the oracle picked the index the vector was constructed to exercise.
//
// COVERAGE (the edges the three languages must agree on): the base64 edges
// (standard-alphabet `x`, `=`-padded `x`, valid unpadded `x`), the mixed-case
// kty/crv lenient-accept, the timestamp edges (offset-less/naive bounds,
// date-only bounds, empty/missing bounds, the not_before==now and not_after==now
// half-open boundaries), and the document-order scan bound — now UNBOUNDED by
// default (an index-10 key the old cap-of-10 hid is selected), with an explicit
// bound that reaches the key, an exhausted explicit bound that returns none (and
// logs), and a negative bound that clamps to scan-none. Replaying it in all three
// languages is what LOCKS parity and would have caught these divergences.
//
// DETERMINISM: every key is derived from a FIXED seed and every instant is a
// FIXED offset from wbaAnchor, so re-running reproduces byte-identical output.
// Default `go test` asserts the committed file matches a fresh emit;
// FORA_UPDATE_VECTORS=1 rewrites it (same drift-gate shape as
// gen_revocation_membership_vectors_test.go).

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// discardActiveKeyLog silences the selector's bounded-exhaustion warning during
// emit: the corpus locks the RETURN verdict, and each language asserts the log
// separately, so the emitter itself must stay quiet.
func discardActiveKeyLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// activeKeyJWK is one served directory key (snake_case, protojson shape). Only
// the members the selector reads are emitted; use/alg are irrelevant to selection.
type activeKeyJWK struct {
	Kty       string `json:"kty"`
	Crv       string `json:"crv"`
	X         string `json:"x"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// activeKeyVector is one served directory + the oracle's selection verdict.
type activeKeyVector struct {
	Label   string         `json:"label"`
	Note    string         `json:"note"`
	MaxScan *int           `json:"max_scan"` // null → the selector's default cap
	Keys    []activeKeyJWK `json:"keys"`
	// Revoked is the RFC 7638 thumbprint set the SCREENED selector treats as revoked
	// (empty for the window/base64/timestamp/cap vectors). A replay builds a predicate
	// from it and runs the revocation-aware face; an empty set makes the screened
	// selection identical to the bare one, so those vectors also lock the bare path.
	Revoked          []string `json:"revoked"`
	ExpectedIndex    int      `json:"expected_index"`     // -1 = no key qualifies
	ExpectedPub      string   `json:"expected_pub"`       // base64url raw pub; "" when none
	ExpectedNotAfter string   `json:"expected_not_after"` // RFC3339; "" when none
}

// activeKeyCorpus is the whole served-doc + verdicts corpus.
type activeKeyCorpus struct {
	Note    string            `json:"note"`
	Now     string            `json:"now"`
	Vectors []activeKeyVector `json:"vectors"`
}

// kb pairs a built directory JWK with its raw public key. pub is nil when the key
// is deliberately unselectable (malformed `x`, wrong kty/crv, wrong length) so the
// index-of-selected lookup never spuriously matches it.
type kb struct {
	jwk activeKeyJWK
	pub []byte
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func toAKJWK(j *forav1.JsonWebKey) activeKeyJWK {
	return activeKeyJWK{
		Kty:       j.GetKty(),
		Crv:       j.GetCrv(),
		X:         j.GetX(),
		NotBefore: j.GetNotBefore(),
		NotAfter:  j.GetNotAfter(),
	}
}

// activeKB / expiredKB / futureKB build a valid OKP/Ed25519 key whose window
// straddles (or excludes) wbaAnchor. pub is the real 32-byte public key.
func activeKB(seed string) kb {
	priv, j := newSigningKey(seed, wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	return kb{jwk: toAKJWK(j), pub: priv.Public().(ed25519.PublicKey)}
}

func expiredKB(seed string) kb {
	priv, j := newSigningKey(seed, wbaAnchor.Add(-2*time.Hour), wbaAnchor.Add(-time.Hour))
	return kb{jwk: toAKJWK(j), pub: priv.Public().(ed25519.PublicKey)}
}

func futureKB(seed string) kb {
	priv, j := newSigningKey(seed, wbaAnchor.Add(time.Hour), wbaAnchor.Add(2*time.Hour))
	return kb{jwk: toAKJWK(j), pub: priv.Public().(ed25519.PublicKey)}
}

// withBounds overrides an active key's window bounds (for the naive/date-only/
// empty/boundary timestamp edges) and clears pub only when the key stays inactive.
func withBounds(base kb, notBefore, notAfter string, selectable bool) kb {
	base.jwk.NotBefore = notBefore
	base.jwk.NotAfter = notAfter
	if !selectable {
		base.pub = nil
	}
	return base
}

// stdAlphaKB builds a window-active key whose `x` is UNPADDED STANDARD base64
// (contains + or /), which py/ts previously lenient-decoded but Go's
// RawURLEncoding rejects → strict-unselectable (pub nil). Deterministic: the first
// seed whose std encoding actually differs from urlsafe.
func stdAlphaKB() kb {
	for i := 0; ; i++ {
		priv, j := newSigningKey(fmt.Sprintf("stdalpha-%d", i), wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
		pub := priv.Public().(ed25519.PublicKey)
		std := base64.RawStdEncoding.EncodeToString(pub)
		if strings.ContainsAny(std, "+/") {
			ak := toAKJWK(j)
			ak.X = std
			return kb{jwk: ak, pub: nil}
		}
	}
}

// paddedKB builds a window-active key whose `x` is urlsafe base64 WITH `=`
// padding — same alphabet as a valid key, only the padding differs — which py/ts
// previously accepted but Go's RawURLEncoding rejects → strict-unselectable.
func paddedKB() kb {
	priv, j := newSigningKey("padded", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	ak := toAKJWK(j)
	ak.X = base64.URLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) // urlsafe + '=' pad
	return kb{jwk: ak, pub: nil}
}

// mutateActive clones a window-active key and applies a field mutation that makes
// it unselectable (non-OKP, wrong crv, wrong length, undecodable x).
func mutateActive(seed string, mutate func(*activeKeyJWK)) kb {
	base := activeKB(seed)
	mutate(&base.jwk)
	base.pub = nil
	return base
}

// mutateActiveSelectable clones a window-active key and applies a mutation that
// leaves it SELECTABLE (pub kept) — for the case-insensitive kty/crv vector, where
// a mixed-case kty/crv is a deliberate lenient-accept, not a rejection.
func mutateActiveSelectable(seed string, mutate func(*activeKeyJWK)) kb {
	base := activeKB(seed)
	mutate(&base.jwk)
	return base
}

func intp(v int) *int { return &v }

// buildVector is buildScreenedVector with an EMPTY revoked set: it exercises the
// bare selection path (screened selection over an empty revoked set is identical to
// the bare face). Most vectors — window, base64, timestamp, cap — take this form.
func buildVector(t *testing.T, label, note string, maxScan *int, keys []kb, wantIndex int) activeKeyVector {
	t.Helper()
	return buildScreenedVector(t, label, note, maxScan, keys, nil, wantIndex)
}

// buildScreenedVector assembles the directory, runs the real Go REVOCATION-AWARE
// selector as the oracle (screening the given revoked thumbprint set), asserts it
// selected wantIndex (the sanity gate), and returns the vector with oracle-produced
// verdict fields. The plain and with-expiry screened faces are asserted to agree;
// when the revoked set is empty, the BARE face is asserted to agree too, so the
// non-screened path stays locked by the same vector.
func buildScreenedVector(
	t *testing.T,
	label, note string,
	maxScan *int,
	keys []kb,
	revoked []string,
	wantIndex int,
) activeKeyVector {
	t.Helper()
	jwks := make([]*forav1.JsonWebKey, len(keys))
	aks := make([]activeKeyJWK, len(keys))
	for i, k := range keys {
		jwks[i] = &forav1.JsonWebKey{
			Kty:       k.jwk.Kty,
			Crv:       k.jwk.Crv,
			X:         k.jwk.X,
			NotBefore: k.jwk.NotBefore,
			NotAfter:  k.jwk.NotAfter,
		}
		aks[i] = k.jwk
	}
	dir := &forav1.WBAFile{Keys: jwks}
	var opts []resolvers.ActiveKeyScanOptions
	if maxScan != nil {
		opts = []resolvers.ActiveKeyScanOptions{{MaxScan: maxScan, Logger: discardActiveKeyLog()}}
	}
	pred := revokedPredicate(revoked)

	pub, notAfter, err := resolvers.ActiveEd25519KeyWithExpiryScreened(dir, wbaAnchor, pred, opts...)
	plain, plainErr := resolvers.ActiveEd25519KeyScreened(dir, wbaAnchor, pred, opts...)
	assertFacesAgree(t, label, pub, err, plain, plainErr)
	if len(revoked) == 0 {
		// Empty screening degrades to the bare selector — lock that too.
		barePub, bareErr := resolvers.ActiveEd25519Key(dir, wbaAnchor, opts...)
		assertFacesAgree(t, label+"/bare", pub, err, barePub, bareErr)
	}

	gotIndex, expPub, expNotAfter := oracleVerdict(keys, pub, notAfter, err)
	if gotIndex != wantIndex {
		t.Fatalf("%s: oracle selected index %d, vector was built for %d", label, gotIndex, wantIndex)
	}
	return activeKeyVector{
		Label:            label,
		Note:             note,
		MaxScan:          maxScan,
		Keys:             aks,
		Revoked:          normalizeRevoked(revoked),
		ExpectedIndex:    gotIndex,
		ExpectedPub:      expPub,
		ExpectedNotAfter: expNotAfter,
	}
}

// revokedPredicate builds the thumbprint-revocation predicate the screened selector
// takes. An empty set yields a nil predicate, which disables screening entirely so
// the screened selection is byte-identical to the bare one.
func revokedPredicate(revoked []string) func(string) bool {
	if len(revoked) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(revoked))
	for _, tp := range revoked {
		set[tp] = struct{}{}
	}
	return func(tp string) bool {
		_, ok := set[tp]
		return ok
	}
}

// normalizeRevoked maps a nil revoked slice to a non-nil empty slice so the emitted
// JSON always carries "revoked": [] (never null) for the replays to build a set from.
func normalizeRevoked(revoked []string) []string {
	if revoked == nil {
		return []string{}
	}
	return revoked
}

// revokedThumbprints returns the RFC 7638 thumbprints of keys — the revoked set a
// revocation vector screens against.
func revokedThumbprints(t *testing.T, keys ...kb) []string {
	t.Helper()
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, mustThumbprint(t, ed25519.PublicKey(k.pub)))
	}
	return out
}

// oracleVerdict turns the selector's (pub, notAfter, err) into the recorded
// (index, base64url-pub, RFC3339-not_after). index is the document-order position
// of the selected key (matched by its known public key), or -1 when none.
func oracleVerdict(keys []kb, pub ed25519.PublicKey, notAfter time.Time, err error) (int, string, string) {
	if err != nil {
		return -1, "", ""
	}
	for i, k := range keys {
		if k.pub != nil && bytes.Equal(k.pub, pub) {
			return i, base64.RawURLEncoding.EncodeToString(pub), rfc(notAfter)
		}
	}
	return -1, base64.RawURLEncoding.EncodeToString(pub), rfc(notAfter)
}

func assertFacesAgree(
	t *testing.T,
	label string,
	pub ed25519.PublicKey,
	err error,
	plain ed25519.PublicKey,
	plainErr error,
) {
	t.Helper()
	if (err == nil) != (plainErr == nil) {
		t.Fatalf("%s: faces disagree on error: withExpiry=%v plain=%v", label, err, plainErr)
	}
	if err == nil && !bytes.Equal(pub, plain) {
		t.Fatalf("%s: faces disagree on selected key", label)
	}
}

func buildActiveKeyCorpus(t *testing.T) activeKeyCorpus {
	t.Helper()
	vectors := buildBasicVectors(t)
	vectors = append(vectors, buildBase64Vectors(t)...)
	vectors = append(vectors, buildTimestampVectors(t)...)
	vectors = append(vectors, buildScanVectors(t)...)
	vectors = append(vectors, buildRevocationVectors(t)...)
	return activeKeyCorpus{
		Note:    "active_ed25519_key document-order selection verdicts produced by the sdk/go oracle; py/ts replay and must match every vector",
		Now:     rfc(wbaAnchor),
		Vectors: vectors,
	}
}

// TestGenerateActiveKeyVector emits the active-key golden vector. Default run
// asserts the committed file is byte-identical to a fresh emit; FORA_UPDATE_VECTORS=1
// rewrites it.
func TestGenerateActiveKeyVector(t *testing.T) {
	t.Parallel()
	corpus := buildActiveKeyCorpus(t)
	path := filepath.Join("testdata", "active-ed25519-key-vectors.json")

	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeActiveKeyVector(t, path, corpus)
		return
	}
	want, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", path)
	}
}

func writeActiveKeyVector(t *testing.T, path string, corpus activeKeyCorpus) {
	t.Helper()
	b, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
