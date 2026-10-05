import { describe, expect, it } from "vitest";
import * as edgeEntry from "../resolvers/edge.ts";
import * as nodeEntry from "../resolvers/index.ts";

// Structural dedup guard for the WBA directory-path constant.
//
// TS carries TWO copies of the "/.well-known/http-message-signatures-directory"
// path string: the module-private WBA_DIRECTORY_PATH in resolvers/wba.ts and the
// duplicate WBA_OFFER_DIRECTORY_PATH exported from resolvers/offer-key-cache.ts and
// re-exported through the public barrel resolvers/index.ts. The consolidation
// collapses these onto ONE public WBA_DIRECTORY_PATH exported from both public entries
// (the Node barrel and the edge entry it re-exports) and DELETES the stale
// WBA_OFFER_DIRECTORY_PATH symbol + its barrel export.
//
// This is a non-behavioral (naming/dedup) disease with no runtime-observable
// change, so per the test-author structural-disease exception the red artifact is
// the export-level guard that sweep-verify later requires: it pins that the duplicate
// symbol is GONE and the single public constant is exported in its place. The
// meta-tests below exercise the name detector.

// The two public entries: the Node barrel re-exports the edge one, so each must carry
// the single constant and neither the duplicate. Read as module namespaces, so the
// assertion is about what a caller can import rather than how the barrel spells it.
const ENTRIES = { "resolvers/index.ts": nodeEntry, "resolvers/edge.ts": edgeEntry } as const;

// The duplicate symbol that MUST disappear from the public surface.
const FORBIDDEN_DUP = /\bWBA_OFFER_DIRECTORY_PATH\b/;
// The single public constant that MUST be exported in its place.
const REQUIRED_CONST = /\bWBA_DIRECTORY_PATH\b/;

describe("WBA directory-path constant is deduplicated onto one public export", () => {
	for (const [name, entry] of Object.entries(ENTRIES)) {
		it(`${name} no longer exports the duplicate WBA_OFFER_DIRECTORY_PATH`, () => {
			expect(Object.keys(entry).some((k) => FORBIDDEN_DUP.test(k))).toBe(false);
		});

		it(`${name} exports the single public WBA_DIRECTORY_PATH`, () => {
			expect(entry.WBA_DIRECTORY_PATH).toBe("/.well-known/http-message-signatures-directory");
		});
	}

	// --- meta-tests: exercise the detector against synthetic barrel source ----
	it("[meta positive] catches a lingering WBA_OFFER_DIRECTORY_PATH export", () => {
		const bad = "export { WBA_OFFER_DIRECTORY_PATH } from './offer-key-cache.ts';";
		expect(FORBIDDEN_DUP.test(bad)).toBe(true);
	});

	it("[meta negative] passes the deduped single-constant export", () => {
		const good = "export { WBA_DIRECTORY_PATH } from './wba.ts';";
		expect(FORBIDDEN_DUP.test(good)).toBe(false);
		expect(REQUIRED_CONST.test(good)).toBe(true);
	});
});
