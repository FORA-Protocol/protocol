package helpers

import (
	"sort"
	"strings"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// Scopes / entitlements (ADR-020 §5, fora-sdk-api.md "Scopes / entitlements").
// The subscriptions/entitlements a requester holds are a SUPPLIED credential:
// the application hands the SDK what it holds and the SDK plumbs it into the
// request (Requester.scopes / Delegation.scopes). The caller never constructs an
// entitlement proof by hand. Today the Exchange trusts what is supplied; when
// JWT/biscuit issuance lands, only the verification under the surface changes —
// these helpers do not move (the change is additive).
//
// NOTE: the api-doc's WithSubscription has no request-side field in the current
// proto — subscription selection happens by choosing an Offer that carries a
// subscription_id, not by a requester-supplied request field. This is plumbed at
// offer-selection time, not here. Only scope plumbing is an L1 concern today.

// NormalizeScopes returns scopes with empty entries dropped, duplicates removed,
// and a stable (sorted) order — so two callers supplying the same set produce
// identical bytes on the wire.
func NormalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// ApplyScopes sets the requester's held scopes (normalized). It is how the caller
// supplies the entitlements it holds for a discover/resolve call.
func ApplyScopes(r *forav1.Requester, scopes ...string) {
	if r == nil {
		return
	}
	r.Scopes = NormalizeScopes(scopes)
}

// ScopeCovers reports whether one granted scope covers one required scope under
// the protocol's scope-matching rule (the rule stated on Requester.scopes, which
// LicenseTerm.scopes and delegation attenuation share):
//
//   - both scopes are split on ":" into segments;
//   - each granted segment must equal the required segment at the same position
//     or be "*";
//   - a "*" in the last position of the grant covers every remaining required
//     segment, and there must be at least one;
//   - there is no implicit prefix match: "dist" covers only "dist", not "dist:US";
//   - a grant with more segments than the requirement is narrower and never
//     covers it, even when its last segment is "*" ("dist:US:*" does not cover
//     "dist:US");
//   - a "*" inside the requirement is a literal segment, so a narrow grant never
//     covers a wildcard requirement ("credit:read" does not cover "*");
//   - an empty string covers nothing and is covered by nothing.
//
// Matching is case-sensitive and never trims.
func ScopeCovers(granted, required string) bool {
	if granted == "" || required == "" {
		return false
	}
	g := strings.Split(granted, ":")
	r := strings.Split(required, ":")
	for i, seg := range g {
		if seg == "*" && i == len(g)-1 {
			return i < len(r)
		}
		if i >= len(r) || (seg != "*" && seg != r[i]) {
			return false
		}
	}
	return len(g) == len(r)
}

// ScopesCover reports whether every scope in required is covered (ScopeCovers)
// by at least one scope in granted. An empty required list is always covered;
// an empty granted list covers nothing but an empty required list.
func ScopesCover(granted, required []string) bool {
	for _, req := range required {
		covered := false
		for _, g := range granted {
			if ScopeCovers(g, req) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// ScopesSubset reports whether every scope in sub is covered by some scope in
// super under ScopeCovers (grant containment, not exact set membership). It is
// the delegation-attenuation rule: a child's scopes must be contained in its
// parent's grant. A child may narrow a wildcard ("publisher:news:read" under
// "publisher:*:read") but may not widen one ("publisher:news:*" under
// "publisher:*:read" is refused). ScopesSubset(sub, super) is
// ScopesCover(super, sub) read from the child's side.
func ScopesSubset(sub, super []string) bool {
	return ScopesCover(super, sub)
}
