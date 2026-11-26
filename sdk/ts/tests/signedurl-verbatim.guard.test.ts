// sdk/ts verbatim-canonicalization guard (parity guard).
//
// THE CONTRACT: the signed-URL signature covers
// `GET\n<url>` as OPAQUE URL BYTES. Signer and verifier MUST agree on `<url>`
// byte-for-byte. The ONLY permitted transform is deterministic query handling
// (add exp/kid/agent_id, remove sig, sort query) — NEVER host-lowercasing,
// default-port stripping, or path-escaping.
//
// This guard pins that invariant WITHOUT touching a Go vector: it asserts that
// the sign face and the verify face build the SAME canonical `GET\n<url>` bytes
// for a TRICKY URL. Because Ed25519 is deterministic, byte-identical canonical
// bytes are exactly what makes a self-signed URL verify — so the guard is:
//   sign(sourceUrl) -> signedUrl ; verify(signedUrl) === valid
// over a URL whose host case, explicit :443, and path space/percent would be
// mangled by any `new URL()` normalization on EITHER side.
//
// Both faces now exist and canonicalize the URL VERBATIM (no `new URL()`
// round-trip on either side), so a self-signed tricky URL — mixed-case host,
// explicit :443, spaced/percent path — verifies. This guard keeps them honest:
// if either side reintroduces WHATWG normalization, the self-signed URL stops
// verifying and this goes red.
import { describe, expect, it } from "vitest";
import { signEd25519SignedUrl } from "../src/signurl.ts";
import { verifyEd25519SignedUrl } from "../src/verify.ts";
import { importSigningKey, publicKeyForSeed } from "./wba-fixtures.ts";

// TRICKY URLs — mixed-case host, explicit :443, space and percent in the PATH.
// These are exactly the inputs a `new URL()`-normalizing canonicalizer mangles.
const TRICKY_SOURCE_URLS = [
	"https://CDN.Example:443/a path/doc",
	"https://CDN.Example/Doc%2Fpart?z=9&a=2",
	"https://Origin.EXAMPLE.com:443/deep/a b/c",
];

const SEED_HEX = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30";
const NOW_UNIX = 1_700_000_100;
const EXP_UNIX = 1_700_000_300;

describe("sdk/ts signed-URL canonicalization is VERBATIM (no host/port/path normalization)", () => {
	for (const source of TRICKY_SOURCE_URLS) {
		it(`self-signed tricky URL verifies (verbatim contract): ${source}`, async () => {
			const priv = await importSigningKey(SEED_HEX);
			const pub = await publicKeyForSeed(SEED_HEX);

			const signed = await signEd25519SignedUrl(source, { kid: "ex.v1", agentId: "", expUnix: EXP_UNIX }, priv);

			// If EITHER face normalizes the host/port/path, the sign-time bytes and the
			// verify-time bytes differ and this verification fails — proving the leak.
			const res = await verifyEd25519SignedUrl(signed, {
				now: () => NOW_UNIX * 1000,
				resolveKey: async (kid) => (kid === "ex.v1" ? pub : undefined),
			});
			expect(res.valid).toBe(true);
		});

		it(`signed URL preserves host case + explicit port + path bytes verbatim: ${source}`, async () => {
			const priv = await importSigningKey(SEED_HEX);
			const signed = await signEd25519SignedUrl(source, { kid: "ex.v1", agentId: "", expUnix: EXP_UNIX }, priv);
			// The emitted URL must still carry the ORIGINAL host casing and the explicit
			// :443 — a WHATWG round-trip would have dropped both. Split off the query we
			// deterministically appended; the scheme+host+path prefix must be verbatim.
			// split() always yields >=1 element, so [0] is defined (narrow for
			// noUncheckedIndexedAccess without changing what is asserted).
			const prefix = source.split("?")[0]!;
			expect(signed.startsWith(prefix)).toBe(true);
		});
	}
});
