package resolvers_test

// The cases of the active-Ed25519-key corpus, by edge: document order, the base64
// forms of x, the timestamp forms of the bounds, the scan bound, and revocation.
// Each case names the index the oracle must select; buildScreenedVector refuses a
// case where the oracle disagrees.

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func buildBasicVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	return []activeKeyVector{
		buildVector(t, "selects-first-active", "two active keys: the first in document order wins", nil,
			[]kb{activeKB("a1"), activeKB("a2")}, 0),
		buildVector(t, "skips-retired-then-active", "a retired key ahead of the active one is skipped", nil,
			[]kb{expiredKB("dead"), activeKB("live")}, 1),
		buildVector(t, "skips-future-then-active", "a not-yet-valid key ahead of the active one is skipped", nil,
			[]kb{futureKB("early"), activeKB("live")}, 1),
		buildVector(t, "empty-directory-none", "an empty directory selects nothing", nil,
			[]kb{}, -1),
		buildVector(t, "all-inactive-none", "a directory of only retired/future keys selects nothing", nil,
			[]kb{expiredKB("x"), futureKB("y")}, -1),
	}
}

func buildBase64Vectors(t *testing.T) []activeKeyVector {
	t.Helper()
	return []activeKeyVector{
		buildVector(t, "valid-unpadded-x-selected", "a valid unpadded-urlsafe x decodes and is selected", nil,
			[]kb{activeKB("valid")}, 0),
		buildVector(
			t,
			"standard-alphabet-x-then-valid",
			"an active key with a STANDARD-alphabet x (+//) is skipped; the next valid key wins",
			nil,
			[]kb{stdAlphaKB(), activeKB("valid")},
			1,
		),
		buildVector(
			t,
			"standard-alphabet-x-only-none",
			"the only key has a STANDARD-alphabet x; Go rejects it → none (py/ts once selected it)",
			nil,
			[]kb{stdAlphaKB()},
			-1,
		),
		buildVector(
			t,
			"padded-x-then-valid",
			"an active key with a '='-PADDED urlsafe x is skipped; the next valid key wins",
			nil,
			[]kb{paddedKB(), activeKB("valid")},
			1,
		),
		buildVector(
			t,
			"padded-x-only-none",
			"the only key has a '='-PADDED x; Go rejects it → none (py/ts once selected it)",
			nil,
			[]kb{paddedKB()},
			-1,
		),
		buildVector(t, "non-okp-then-valid", "a window-active non-OKP key is skipped; the next valid key wins", nil,
			[]kb{mutateActive("rsa", func(j *activeKeyJWK) { j.Kty = "RSA" }), activeKB("valid")}, 1),
		buildVector(
			t,
			"wrong-crv-then-valid",
			"a window-active non-Ed25519 key is skipped; the next valid key wins",
			nil,
			[]kb{mutateActive("p256", func(j *activeKeyJWK) { j.Crv = "P-256" }), activeKB("valid")},
			1,
		),
		buildVector(
			t,
			"wrong-length-x-then-valid",
			"a window-active key whose x decodes to 31 bytes is skipped",
			nil,
			[]kb{
				mutateActive(
					"short",
					func(j *activeKeyJWK) { j.X = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) },
				),
				activeKB("valid"),
			},
			1,
		),
		buildVector(t, "undecodable-x-then-valid", "a window-active key whose x is not base64url is skipped", nil,
			[]kb{mutateActive("junk", func(j *activeKeyJWK) { j.X = "!!!!" }), activeKB("valid")}, 1),
		buildVector(
			t,
			"mixed-case-kty-crv-selected",
			"a window-active key with mixed-case kty/crv (oKp / ed25519) is ACCEPTED and selected — "+
				"case-insensitive kty/crv is a deliberate lenient SDK convention (RFC 7517/8037 specify "+
				"exact-case OKP / Ed25519); all three SDKs accept it identically",
			nil,
			[]kb{mutateActiveSelectable("mixedcase", func(j *activeKeyJWK) { j.Kty = "oKp"; j.Crv = "ed25519" })},
			0,
		),
	}
}

func buildTimestampVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	naive := func(seed string) kb {
		return withBounds(activeKB(seed), "2026-05-01T11:00:00", "2026-05-01T13:00:00", false)
	}
	dateOnly := func(seed string) kb {
		return withBounds(activeKB(seed), "2026-05-01", "2026-05-02", false)
	}
	empty := func(seed string) kb { return withBounds(activeKB(seed), "", "", false) }
	nbEqNow := withBounds(activeKB("nbnow"), rfc(wbaAnchor), rfc(wbaAnchor.Add(time.Hour)), true)
	naEqNow := withBounds(activeKB("nanow"), rfc(wbaAnchor.Add(-time.Hour)), rfc(wbaAnchor), false)
	return []activeKeyVector{
		buildVector(
			t,
			"offset-less-bound-then-valid",
			"an offset-less (naive) window is inactive; the next valid key wins",
			nil,
			[]kb{naive("naive"), activeKB("valid")},
			1,
		),
		buildVector(t, "offset-less-bound-only-none", "the only key has offset-less bounds → none", nil,
			[]kb{naive("naive")}, -1),
		buildVector(
			t,
			"date-only-bound-then-valid",
			"a date-only (no time) bound is unparseable → inactive; the next valid key wins",
			nil,
			[]kb{dateOnly("dateonly"), activeKB("valid")},
			1,
		),
		buildVector(t, "date-only-bound-only-none", "the only key has date-only bounds → none", nil,
			[]kb{dateOnly("dateonly")}, -1),
		buildVector(
			t,
			"empty-bounds-then-valid",
			"empty/missing window bounds are inactive; the next valid key wins",
			nil,
			[]kb{empty("empty"), activeKB("valid")},
			1,
		),
		buildVector(
			t,
			"boundary-not-before-equals-now",
			"not_before==now is INSIDE the half-open window → selected",
			nil,
			[]kb{nbEqNow},
			0,
		),
		buildVector(
			t,
			"boundary-not-after-equals-now-none",
			"not_after==now is OUTSIDE the half-open window → none",
			nil,
			[]kb{naEqNow},
			-1,
		),
		buildVector(
			t,
			"boundary-not-after-equals-now-then-valid",
			"a not_after==now key is inactive; the next valid key wins",
			nil,
			[]kb{naEqNow, activeKB("valid")},
			1,
		),
	}
}

// buildScanVectors exercises the document-order scan bound now that the default is
// UNBOUNDED: a key the old cap-of-10 hid is reachable by default; an explicit bound
// caps the scan; an exhausted explicit bound returns none (and logs); a negative
// bound clamps to scan-none.
func buildScanVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	fillers := func(n int) []kb {
		out := make([]kb, 0, n)
		for i := range n {
			out = append(out, expiredKB(fmt.Sprintf("filler-%d", i)))
		}
		return out
	}
	winnerAt10 := append(fillers(10), activeKB("target")) // 11 keys; the active key is at index 10
	return []activeKeyVector{
		buildVector(
			t,
			"winner-at-index-10-selected-unbounded",
			"with the cap dropped, a valid key at index 10 (the 11th) is reachable by DEFAULT → selected; "+
				"the old cap-of-10 would have hidden it",
			nil,
			winnerAt10,
			10,
		),
		buildVector(t, "winner-reached-with-explicit-bound",
			"an explicit max_scan of 11 examines index 10 → selected", intp(11),
			winnerAt10, 10),
		buildVector(
			t,
			"explicit-bound-exhausted-none",
			"an explicit max_scan of 10 is exhausted over the 10 expired fillers before the index-10 key → none; "+
				"the exhaustion is logged (a valid key beyond the cap is unreachable), asserted per-language",
			intp(10),
			winnerAt10,
			-1,
		),
		buildVector(
			t,
			"negative-bound-scans-none",
			"a negative max_scan clamps to zero (scan none) → none even though an active key is present "+
				"(parity: py max(0,n) / ts Math.max(0,n) / Go clamp-to-zero)",
			intp(-1),
			[]kb{activeKB("present-but-unscanned")},
			-1,
		),
	}
}

// buildRevocationVectors exercises the REVOCATION-AWARE selector: a window-active
// key whose thumbprint is revoked is skipped, and the next active non-revoked key
// (if any) wins. These are the vectors the bare selector CANNOT produce — they lock
// the screened faces the offer-key cache verification path depends on.
func buildRevocationVectors(t *testing.T) []activeKeyVector {
	t.Helper()
	r1 := activeKB("rev-1")
	r2 := activeKB("rev-2")
	solo := activeKB("rev-solo")
	return []activeKeyVector{
		buildScreenedVector(
			t,
			"revoked-active-key-skipped-then-next",
			"a window-active key whose thumbprint is in the revoked set is skipped; the next active non-revoked key wins",
			nil,
			[]kb{r1, r2},
			revokedThumbprints(t, r1),
			1,
		),
		buildScreenedVector(t, "revoked-only-active-key-none",
			"the only window-active key is revoked → none qualifies",
			nil, []kb{solo}, revokedThumbprints(t, solo), -1),
	}
}
