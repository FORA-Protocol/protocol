package resolvers

// Golden-vector emitter for the cross-language offer-key EXPIRY-CLAMP parity
// corpus. sdk/python `_clamp_expiry` and sdk/ts `clampOfferKeyExpiry` REPLAY this
// corpus and MUST reproduce the sdk/go `clampOfferKeyExpiry` oracle's result for
// EVERY vector.
//
// The clamped expiry is what keeps a cached offer-signing key from being served
// past its validity window: the entry expires at min(now+ttl, not_after). Each
// vector is {label, now, ttl_seconds, not_after, expected_expiry}; now/not_after/
// expected_expiry are RFC3339 STRINGS (unit-agnostic — each language parses them
// natively, exactly as active-ed25519-key-vectors.json does), ttl_seconds is
// numeric, and every instant lands on a WHOLE-SECOND boundary so no ms/ns
// precision drift can split the three languages.
//
// COVERAGE (the boundary the three languages must agree on): (a) the TTL expires
// first (exp = now+ttl); (b) not_after clamps first (exp = not_after); (c) exact
// equality now+ttl == not_after (the off-by-one seam — both arms yield the same
// instant). expected_expiry is emitted by RUNNING the real Go clamp — Go is the
// oracle, never a hand-authored table. This file is `package resolvers` (internal
// test) so it can call the unexported `clampOfferKeyExpiry` the resolver itself
// calls, proving the vector exercises the production arithmetic.
//
// DETERMINISM: every instant is a fixed offset from a fixed anchor, so re-running
// reproduces byte-identical output. `go test` asserts the committed file matches a fresh
// emit; a mismatch leaves a .got file beside the corpus (vectorio.Check) (same drift-gate
// shape as gen_active_key_vectors_test.go).

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

// offerKeyClampVector is one clamp input + the oracle's clamped expiry.
type offerKeyClampVector struct {
	Label          string `json:"label"`
	Now            string `json:"now"`             // RFC3339
	TTLSeconds     int    `json:"ttl_seconds"`     // numeric seconds
	NotAfter       string `json:"not_after"`       // RFC3339
	ExpectedExpiry string `json:"expected_expiry"` // RFC3339, emitted by the Go clamp
}

type offerKeyClampCorpus struct {
	Note    string                `json:"note"`
	Vectors []offerKeyClampVector `json:"vectors"`
}

func rfc3339Sec(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func buildOfferKeyClampCorpus() offerKeyClampCorpus {
	anchor := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	build := func(label string, now time.Time, ttl time.Duration, notAfter time.Time) offerKeyClampVector {
		exp := clampOfferKeyExpiry(now, ttl, notAfter)
		return offerKeyClampVector{
			Label:          label,
			Now:            rfc3339Sec(now),
			TTLSeconds:     int(ttl / time.Second),
			NotAfter:       rfc3339Sec(notAfter),
			ExpectedExpiry: rfc3339Sec(exp),
		}
	}
	return offerKeyClampCorpus{
		Note: "offer-key cache expiry = min(now+ttl, not_after), produced by the sdk/go clampOfferKeyExpiry oracle; py/ts replay and must match every vector",
		Vectors: []offerKeyClampVector{
			build("ttl-expires-first",
				anchor, 300*time.Second, anchor.Add(time.Hour)),
			build("not-after-clamps-first",
				anchor, time.Hour, anchor.Add(10*time.Minute)),
			build("exact-equality-now-plus-ttl-equals-not-after",
				anchor, 10*time.Minute, anchor.Add(10*time.Minute)),
		},
	}
}

// TestGenerateOfferKeyClampVector emits the clamp golden vector. It asserts the committed
// file is byte-identical to a fresh emit; a mismatch leaves a .got file beside the corpus
// (vectorio.Check).
func TestGenerateOfferKeyClampVector(t *testing.T) {
	t.Parallel()
	corpus := buildOfferKeyClampCorpus()
	path := filepath.Join("testdata", "offer-key-clamp-vectors.json")

	if err := vectorio.Check(path, corpus); err != nil {
		t.Fatal(err)
	}
}
