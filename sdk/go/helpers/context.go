package helpers

import "context"

// Context plumbing for carrying verified signature(s) through a request's
// context. This is the PURE slot + accessors only — L1 has no Middleware (that
// is transport, ADR-020 keeps L1 IO-free); the platform relay/interceptor is the
// legitimate populator. Tests may populate the slots directly to drive
// handler-level authz without standing up the full signing chain.

// verifiedKey carries a single VerifiedRequest (the single-sig backward-compat
// slot).
type verifiedKey struct{}

// signatureAgentKey carries the key-directory origin of the signature being
// verified for the duration of its key resolution.
type signatureAgentKey struct{}

// WithSignatureAgent returns a copy of ctx carrying dir, the https origin of the
// key directory a signature's covered Signature-Agent member names. The resolved
// verify entrypoints thread it before resolving each signature's key, a fresh
// value per signature, so a KeyResolver fetches keys from the directory that
// signature commits to.
func WithSignatureAgent(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, signatureAgentKey{}, dir)
}

// SignatureAgentFromContext returns the key-directory origin threaded by the
// resolved verify entrypoints for the signature being resolved, or "" when none
// was set.
func SignatureAgentFromContext(ctx context.Context) string {
	v, _ := ctx.Value(signatureAgentKey{}).(string)
	return v
}

// multisigKey carries all verified signatures for a multisig request.
type multisigKey struct{}

// NewContext returns a copy of ctx carrying v under the single verified-request
// slot. Production code MUST NOT call this outside the verifying transport.
func NewContext(ctx context.Context, v *VerifiedRequest) context.Context {
	return context.WithValue(ctx, verifiedKey{}, v)
}

// NewMultisigContext returns a copy of ctx carrying all verified signatures, in
// header order. Production code MUST NOT call this outside the
// verifying transport.
func NewMultisigContext(ctx context.Context, sigs []VerifiedRequest) context.Context {
	return context.WithValue(ctx, multisigKey{}, sigs)
}

// FromContext returns the VerifiedRequest stashed in ctx, or nil. For a request
// carrying several signatures it returns the first in header order; it reads the
// multisig slot first then falls back to the single slot, so the N=1 read path is
// unchanged.
func FromContext(ctx context.Context) *VerifiedRequest {
	if sigs, ok := ctx.Value(multisigKey{}).([]VerifiedRequest); ok && len(sigs) > 0 {
		return &sigs[0]
	}
	v, _ := ctx.Value(verifiedKey{}).(*VerifiedRequest)
	return v
}

// AllSignaturesFromContext returns all verified signatures (the multisig case).
// It returns a single-element slice for a single-sig request, or nil if no
// signatures are in context.
func AllSignaturesFromContext(ctx context.Context) []VerifiedRequest {
	if sigs, ok := ctx.Value(multisigKey{}).([]VerifiedRequest); ok {
		return sigs
	}
	if v, ok := ctx.Value(verifiedKey{}).(*VerifiedRequest); ok && v != nil {
		return []VerifiedRequest{*v}
	}
	return nil
}
