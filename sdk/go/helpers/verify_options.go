package helpers

import (
	"crypto/ed25519"
	"time"
)

// defaultMaxFutureSkew bounds how far a created timestamp may lead the verifier's
// clock (replay defence). 300s matches the OAuth 2.0 reauth skew convention.
const defaultMaxFutureSkew = 300 * time.Second

// VerifyOptions tune VerifyRequest. The zero value is production-correct: Now
// defaults to the wall clock and MaxFutureSkew to defaultMaxFutureSkew. Tests
// inject Now for determinism.
type VerifyOptions struct {
	Now           time.Time
	MaxFutureSkew time.Duration
	// MaxSignatures bounds the number of signatures accepted on a request — the
	// hop budget. Every signature counts, whether or not it covers another. 0
	// means unbounded; an Exchange sets it to the max_intermediary_hops it
	// publishes. A request carrying more signatures is rejected with
	// ErrTooManyHops before any signature is cryptographically verified. Ignored by
	// single-sig VerifyRequest.
	MaxSignatures int
	// MaxSignatureAge clamps a signature's declared lifetime (expires − created).
	// MaxFutureSkew only bounds the future edge; without an upper bound on the
	// window a signer can set expires = now + 10y and, if the replay store is
	// absent or forgotten, keep replaying the same bytes for years. 0 (default)
	// means unbounded — back-compatible; a server-terminal consumer sets it (the
	// FORA target is minutes). A signature whose window exceeds it is rejected
	// with ErrSignatureLifetimeTooLong before the Ed25519 check.
	MaxSignatureAge time.Duration
}

// VerifiedRequest carries the proven signature metadata. PublicKey is the key
// the signature verified against, carried so downstream consumers bind to the
// proven key (e.g. its RFC 7638 thumbprint as agent_id) rather than re-resolving
// the claimed KeyID.
//
// KeyDirectory is the URL of the signer's key directory, the one the
// Signature-Agent member this signature covers names and its keyid was resolved
// in: always https://<origin>/.well-known/http-message-signatures-directory, with
// a member that carried the bare origin completed to it. SignatureAgent is that
// directory's https origin, whose host is the signer's identity (Requester.domain).
// The resolved verify entrypoints hand the origin to the KeyResolver. The member
// is covered, so both are signed.
//
// Algorithm is the algorithm the signature verified under: the alg it declares,
// or "ed25519" when it declares none and the key decided it.
type VerifiedRequest struct {
	KeyID          string
	Algorithm      string
	Label          string
	Signature      string
	Created        int64
	Expires        int64
	PublicKey      ed25519.PublicKey
	SignatureAgent string
	KeyDirectory   string
}
