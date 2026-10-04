// Signature Window (sdk/ts/core) — TS port of the sdk/go oracle
// (core/sigwindow.go). A Window returns the RFC 9421 (created, expires) cutoffs
// (unix seconds) to stamp on the next outbound signature; it is invoked once per
// signed request. Both values derive from a single now() reading so a
// deterministic-clock test stays inside the verifier's freshness window.
//
// The clock is in the SECONDS domain (matching Go's now().Unix()); both faces
// FLOOR to integer seconds via Math.floor so the produced @signature-params
// bytes stay byte-identical to the sign-site's historical inline mint.

/** A Window yields the [created, expires] unix-second cutoffs for one signature. */
export type Window = () => [created: number, expires: number];

/**
 * clockWindow returns the plain production Window: it stamps each signature with
 * clock-derived created = floor(now()) and expires = created + ttlSec. `now`
 * reads seconds (fractional allowed); the floor reproduces Go's .Unix().
 */
export function clockWindow(now: () => number, ttlSec: number): Window {
	return () => {
		const created = Math.floor(now());
		return [created, created + ttlSec];
	};
}

/**
 * monotonicWindow returns a Window whose expires cutoff strictly increases
 * across calls: it tracks floor(now()) + ttlSec but, when a burst of requests
 * lands in the same wall-clock second, bumps expires by one second per call so
 * no two back-to-back signatures share an (keyid, expires) pair. The signing
 * transport no longer needs this for uniqueness: every signature carries a fresh
 * nonce, so clockWindow is enough. created moves with expires, so the window is
 * always exactly ttlSec and never exceeds the Web Bot Auth limit when ttlSec is at
 * most MAX_SIGNATURE_LIFETIME; during a burst created leads the clock by the
 * burst's length in seconds, which a verifier's future-skew allowance absorbs.
 *
 * ONE INSTANCE PER CLIENT, never one per call. The running maximum is the whole
 * mechanism: a window created per request starts from zero, cannot see the
 * previous signature, and provides exactly none of the uniqueness it was chosen
 * for — while still looking correct at the call site.
 */
export function monotonicWindow(now: () => number, ttlSec: number): Window {
	let lastExpires = 0;
	return () => {
		const floor = Math.floor(now()) + ttlSec;
		const next = lastExpires >= floor ? lastExpires + 1 : floor;
		lastExpires = next;
		return [next - ttlSec, next];
	};
}
