package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// signWindow is the freshness TTL stamped on an outbound signature's
// created/expires pair by the DEFAULT window: helpers.MaxSignatureLifetime, the
// longest a Web Bot Auth request signature may live. The verifier enforces the
// window against its own clock. Callers with their own freshness policy inject a
// shorter window via WithWindow (see ClockWindow); a longer one
// is refused at signing with helpers.ErrSignatureLifetime.
const signWindow = helpers.MaxSignatureLifetime

// signingTransport is the client SIGN face realized as an http.RoundTripper —
// NOT a connect.Interceptor. RFC 9421 Content-Digest is computed over the EXACT
// marshaled body bytes, which a connect unary interceptor never sees (it holds
// the proto message, not the serialized payload). So signing MUST happen at the
// HTTP seam, after Connect has marshaled the request. This is the single correct
// place to sign; realizing sign as a connect.Interceptor would produce a wrong or
// absent Content-Digest and break interop with every verifier (ADR-020 §2, the
// sign-as-RoundTripper decision).
type signingTransport struct {
	base   http.RoundTripper
	signer helpers.Signer
	// window supplies the per-request (created, expires) freshness cutoffs.
	// One field, one clock: the default reads time.Now once and adds
	// signWindow; WithWindow replaces the whole pair source.
	window Window
	// directory is the signer's own key-directory origin, written as the
	// signature's Signature-Agent member (WithSignatureAgent). Every signature
	// names one: with neither a directory nor a source, signing fails.
	directory string
	// source resolves the signer and its directory per request
	// (WithSignerSource), overriding signer and directory.
	source SignerSource
	// appendOnly selects the always-append signing branch (WithAppendSigner).
	appendOnly bool
	// coverPrevious makes an appended signature cover the last earlier one
	// (WithCoverPrevious).
	coverPrevious bool
	// predicate gates which requests are signed (WithSignPredicate). The
	// default signs every bodied request — the pre-option compat contract.
	predicate func(*http.Request) bool
}

// nonceBytes is the entropy per signature nonce: 64 bytes, 86 base64url
// characters. 64 bytes is the length the Web Bot Auth test vectors use, and widely
// deployed WBA verifiers refuse a nonce of any other length.
const nonceBytes = 64

// newNonce returns a fresh random nonce, base64url without padding. Since Go
// 1.24 crypto/rand.Read never returns an error: on entropy failure it crashes
// the process. That is the intended fail-closed behavior: a missing or
// predictable nonce must never be sent.
func newNonce() string {
	b := make([]byte, nonceBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// SigningOption customizes the signing transport built by NewSigningTransport.
type SigningOption func(*signingTransport)

// SignerSource returns the signer and its Signature-Agent directory origin for one
// request, for a service that signs as many identities: an identity service
// signing as the calling agent, a console signing as the calling publisher.
type SignerSource func(ctx context.Context, req *http.Request) (helpers.Signer, string, error)

// WithSignerSource resolves the signer and its directory per request through src,
// in place of the transport's fixed signer and WithSignatureAgent directory. Every
// signature it makes follows the same profile, with a fresh nonce. A source error,
// a nil signer or an empty directory means nothing is sent: RoundTrip returns the
// error and never reaches the base transport.
func WithSignerSource(src SignerSource) SigningOption {
	return func(t *signingTransport) { t.source = src }
}

// WithCoverPrevious makes an appended signature cover the last signature already
// on the request, as WG-00 §5.2.2 permits a party that forwards a request unchanged
// in every component that signature covers (see helpers.SignOptions.CoverPrevious).
// It applies to the append branch only. A party that changed the request, such as
// a Broker re-packaging a purchase, must not use it.
func WithCoverPrevious() SigningOption {
	return func(t *signingTransport) { t.coverPrevious = true }
}

// WithWindow replaces the default freshness window (time.Now + 5 minutes) with
// a caller-supplied source of the RFC 9421 (created, expires) pair, for example
// ClockWindow with the deployment's own TTL. Signature uniqueness does not
// depend on the window: every signature carries a fresh nonce.
func WithWindow(w Window) SigningOption {
	return func(t *signingTransport) { t.window = w }
}

// WithAppendSigner routes EVERY signed request through helpers.AppendSignature
// instead of the default split (a fresh sig1 via helpers.SignRequest, an appended
// signature via helpers.AppendSignature when an incoming Signature is present).
// AppendSignature produces a plain sig1 when no incoming signature is present and
// adds a signature with its own label and Signature-Agent member when one is,
// leaving the earlier signatures untouched. The appended signature covers only its
// own request and member unless WithCoverPrevious is set. Each appended signature
// carries a fresh nonce, so identical back-to-back requests do not collide in the
// server's replay store.
func WithAppendSigner() SigningOption {
	return func(t *signingTransport) { t.appendOnly = true }
}

// WithSignatureAgent names dir, the signer's own key-directory origin
// ("https://agent.example"), as the Signature-Agent member every signature this
// transport makes covers. It is required unless WithSignerSource supplies the
// directory per request: a request signed with no directory is refused with
// helpers.ErrSignatureAgentRequired, and a value that is not an https origin with
// helpers.ErrSignatureAgentNotOrigin. On the append branch the member is added to
// the request's Signature-Agent dictionary beside the earlier signers' members,
// which stay untouched.
func WithSignatureAgent(dir string) SigningOption {
	return func(t *signingTransport) { t.directory = dir }
}

// WithSignPredicate gates signing on fn: only requests for which fn returns
// true are signed; everything else passes through unmodified. The default (no
// predicate) signs every bodied request — the behavior existing callers rely
// on. A FORA application that shares one *http.Client across FORA and non-FORA
// traffic typically passes a procedure-namespace predicate such as
//
//	core.WithSignPredicate(func(r *http.Request) bool {
//		return strings.HasPrefix(r.URL.Path, "/fora.")
//	})
//
// mirroring the /fora. procedure boundary the server-side verify seam already
// enforces.
func WithSignPredicate(fn func(*http.Request) bool) SigningOption {
	return func(t *signingTransport) { t.predicate = fn }
}

// NewSigningTransport returns the client sign-face RoundTripper: it buffers each
// outbound request body, stamps Content-Digest, binds Authorization, and writes
// the Web Bot Auth Signature-Agent member and the RFC 9421 Signature-Input /
// Signature headers via the injected Signer, then forwards to base. A request
// already carrying a Signature header gets an additional signature
// (helpers.AppendSignature) rather than having its signature replaced. base
// defaults to http.DefaultTransport when nil. It is exported so an application
// can compose the SDK sign face onto its own *http.Client (e.g. to wrap it in a
// tracing or metrics RoundTripper). Options tune transport behavior — the
// directory (WithSignatureAgent, required unless a source supplies it), a
// per-request signer source, the freshness window, append mode and coverage of
// an earlier signature, and the sign predicate.
func NewSigningTransport(signer helpers.Signer, base http.RoundTripper, opts ...SigningOption) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	t := &signingTransport{
		base:   base,
		signer: signer,
		window: ClockWindow(time.Now, signWindow),
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// RoundTrip signs req (or chains a co-signature onto an already-signed req) and
// forwards it to the base transport. A request with no body passes through
// unsigned — there is nothing to bind a Content-Digest to — as does any request
// the sign predicate excludes.
func (t *signingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if (t.signer == nil && t.source == nil) || req.Body == nil || (t.predicate != nil && !t.predicate(req)) {
		return t.base.RoundTrip(req)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.ContentLength = int64(len(body))
	if req.Host == "" && req.URL != nil {
		req.Host = req.URL.Host
	}
	if err := t.sign(req.Context(), req, body); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// identityFor returns the signer and directory for req: the source's when one is
// configured, the transport's own otherwise.
func (t *signingTransport) identityFor(ctx context.Context, req *http.Request) (helpers.Signer, string, error) {
	if t.source == nil {
		return t.signer, t.directory, nil
	}
	signer, dir, err := t.source(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("core: signer source: %w", err)
	}
	if signer == nil {
		return nil, "", errors.New("core: signer source returned no signer")
	}
	return signer, dir, nil
}

// sign selects the single-signature or append branch and stamps the directory,
// the freshness window and a fresh nonce. The nonce makes every signature unique,
// so two identical requests in the same second are not refused as replays of each
// other. The appendOnly branch (WithAppendSigner) always appends: AppendSignature
// produces a fresh sig1 when no incoming signature is present.
func (t *signingTransport) sign(ctx context.Context, req *http.Request, body []byte) error {
	signer, dir, err := t.identityFor(ctx, req)
	if err != nil {
		return err
	}
	created, expires := t.window()
	opts := helpers.SignOptions{
		Created: created, Expires: expires, Nonce: newNonce(),
		SignatureAgent: dir, CoverPrevious: t.coverPrevious,
	}
	if t.appendOnly || req.Header.Get("Signature") != "" {
		return helpers.AppendSignature(ctx, req, body, signer, opts)
	}
	opts.CoverPrevious = false
	return helpers.SignRequest(ctx, req, body, signer, opts)
}
