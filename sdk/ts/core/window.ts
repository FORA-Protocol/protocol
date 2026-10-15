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
 * monotonicWindow returns a Window that stamps each signature at the clock's current
 * time: created = floor(now()) and expires = created + ttlSec, exactly as clockWindow
 * does.
 *
 * It once bumped expires (and later created with it) by one second per call inside a
 * wall-clock second, so that no two signatures shared a window. Above one request per
 * second that stamped signatures in the future, by as many seconds as there were
 * requests, and they passed only on the verifier's future-skew allowance. Uniqueness
 * never needed it: every signature carries a fresh 64-byte nonce, so two identical
 * requests in the same second already sign to different bytes. Go
 * core.MonotonicWindow and the Python SDK behave the same way.
 *
 * @deprecated Use clockWindow. monotonicWindow is kept so existing callers compile,
 * and behaves identically.
 */
export function monotonicWindow(now: () => number, ttlSec: number): Window {
	return clockWindow(now, ttlSec);
}
