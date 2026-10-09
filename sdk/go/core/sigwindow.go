package core

import "time"

// Window returns the RFC 9421 (created, expires) cutoffs (unix seconds) to
// stamp on the next outbound signature. It is invoked once per signed request.
// Both values matter: SignRequest/AppendSignature receive created and expires
// from the caller — the multisig verifier rejects any signature missing
// created. An implementation may return a wall-clock instant plus a fixed TTL
// (ClockWindow) or monotonically increasing values (MonotonicWindow); created
// and expires should derive from the same source so a deterministic-clock test
// stays inside the verifier's freshness window. The signing transport makes each
// signature unique with a fresh nonce, whatever the window returns.
type Window func() (created, expires int64)

// ClockWindow returns the plain production Window: it stamps each outbound
// signature with wall-clock-derived created=now() and expires=now()+ttl. Both
// axes come from the single now() reading so created ≤ expires and both land
// in the verifier's window. To adapt an application clock interface with a
// Now() method, pass the method value: ClockWindow(clk.Now, ttl).
func ClockWindow(now func() time.Time, ttl time.Duration) Window {
	return func() (int64, int64) {
		n := now()
		return n.Unix(), n.Add(ttl).Unix()
	}
}

// MonotonicWindow returns a Window that stamps each outbound signature at the
// clock's current time: created=now() and expires=now()+ttl, exactly as
// ClockWindow does.
//
// It once bumped expires (and later created with it) by one second per call
// inside a wall-clock second, so that no two signatures shared a window. That
// stamped signatures in the future at more than one request per second, by as many
// seconds as there were requests, which a verifier's future-skew allowance then
// absorbed. Uniqueness never needed it: every signature carries a fresh 64-byte
// nonce, so two identical requests in the same second already sign to different
// bytes.
//
// Deprecated: use ClockWindow. MonotonicWindow is kept so existing callers
// compile, and behaves identically.
func MonotonicWindow(now func() time.Time, ttl time.Duration) Window {
	return ClockWindow(now, ttl)
}
