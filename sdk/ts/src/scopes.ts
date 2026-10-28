// Scopes / entitlements (ADR-020 §5) — TS port of the sdk/go oracle
// (helpers/scopes.go). The subscriptions/entitlements a requester holds are a
// SUPPLIED credential: the application hands the SDK what it holds and the SDK
// plumbs it into the request. NormalizeScopes/ScopesSubset are pure, byte-
// deterministic string ops pinned to the shared scopes-vectors.json;
// scopeCovers/scopesCover implement the protocol's segment-wise scope-matching
// rule and are pinned to scope-match-vectors.json.

/**
 * normalizeScopes returns scopes with empty entries dropped, duplicates removed
 * (first-seen), and a stable (lexicographic) order — so two callers supplying
 * the same set produce identical bytes on the wire. No casing change, no
 * trimming. The sdk/go oracle returns nil for empty/all-empty input (JSON
 * null); the TS face returns `[]` (the parity comparator treats null == []).
 */
export function normalizeScopes(scopes: string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const s of scopes) {
		if (s === "" || seen.has(s)) continue;
		seen.add(s);
		out.push(s);
	}
	out.sort();
	return out;
}

/**
 * scopeCovers reports whether one granted scope covers one required scope under
 * the protocol's scope-matching rule (stated on Requester.scopes): split both
 * on ":"; each granted segment equals the required segment or is "*"; a "*" in
 * the last position of the grant covers every remaining required segment and
 * there must be at least one; no implicit prefix match; a grant with more
 * segments than the requirement never covers it; a "*" inside the requirement
 * is a literal segment; an empty string covers nothing and is covered by
 * nothing. Case-sensitive, no trimming.
 */
export function scopeCovers(granted: string, required: string): boolean {
	if (granted === "" || required === "") return false;
	const g = granted.split(":");
	const r = required.split(":");
	for (let i = 0; i < g.length; i++) {
		const seg = g[i];
		if (seg === "*" && i === g.length - 1) return i < r.length;
		if (i >= r.length || (seg !== "*" && seg !== r[i])) return false;
	}
	return g.length === r.length;
}

/**
 * scopesCover reports whether every scope in `required` is covered
 * (scopeCovers) by at least one scope in `granted`. An empty `required` is
 * always covered.
 */
export function scopesCover(granted: string[], required: string[]): boolean {
	return required.every((req) => granted.some((g) => scopeCovers(g, req)));
}

/**
 * scopesSubset reports whether every scope in `sub` is covered by some scope in
 * `sup` under scopeCovers (grant containment, not exact set membership). It is
 * the delegation-attenuation rule: a child may narrow a parent wildcard but may
 * not widen one. Same check as scopesCover(sup, sub).
 */
export function scopesSubset(sub: string[], sup: string[]): boolean {
	return scopesCover(sup, sub);
}

/**
 * applyScopes is the functional analogue of the Go ApplyScopes (which mutates a
 * proto Requester). The TS port has no generated Requester mutation face, so it
 * returns the normalized scopes array the caller stamps onto its own request.
 */
export function applyScopes(scopes: string[]): string[] {
	return normalizeScopes(scopes);
}
