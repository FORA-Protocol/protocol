package resolvers

// The ONE SSRF-guarded HTTP client factory.
//
// NewGuardedClient is the single public construction path every FORA
// consumer uses for ANY third-party-influenceable fetch (WBA directory, content,
// usage-report POST, well-known probe). Its policy has no switch: the client
// refuses to dial a reserved or non-public address (SSRFGuard), and it dials
// https only. Nothing it reads, the environment included, relaxes either check.
//
// A deployment or a test that must reach a private or plaintext peer injects its
// own client or transport through the option of the fetch it configures, and
// owns that client's policy from then on.

import (
	"fmt"
	"net/http"
	"strings"
)

// NewGuardedClient builds the guarded HTTP client: the dial-time address pin, the
// https-only scheme check on the initial request and on every redirect, and the
// shared redirect-depth cap. It dials through a no-proxy transport, so a set
// HTTP(S)_PROXY cannot tunnel a private target past the address pin.
func NewGuardedClient() *http.Client {
	return &http.Client{
		Timeout:       defaultWBAHTTPTimeout,
		Transport:     NewGuardedTransport(nil),
		CheckRedirect: schemeCheckRedirect,
	}
}

// NewGuardedClientFromEnv returns NewGuardedClient(). It reads nothing from the
// environment.
//
// Deprecated: use NewGuardedClient. NewGuardedClientFromEnv is removed in 2.0.
func NewGuardedClientFromEnv() *http.Client {
	return NewGuardedClient()
}

// refuseSchemeOption is the refusal for a deprecated scheme option that names a
// scheme other than https: the same "SSRF guard" error the scheme check returns, so
// a value that once reached a plaintext peer is refused before anything is dialed,
// whatever client was injected. An empty option means https and is not refused.
func refuseSchemeOption(scheme string) error {
	if scheme == "" || schemeGuardAllows(scheme) {
		return nil
	}
	return fmt.Errorf("resolvers: refusing to dial disallowed scheme %q (SSRF guard)", scheme)
}

// NewGuardedTransport returns the guarded round-tripper, the https-only scheme
// check over the dial-time address pin, with base underneath it. A nil base gets
// a fresh transport.
//
// base exists so a caller can carry its OWN transport settings (a tuned
// connection pool, client certificates) UNDER the guard rather than instead of
// it. Handing over a base is the way to customise the dial and keep the guard; a
// caller that must reach a private or plaintext peer passes its own client or
// transport to the fetch instead, and owns that policy.
//
// SSRFGuard clones what it is given, so the caller's value is never mutated, and
// drops the two settings that would route a dial around the address pin: a proxy,
// which would tunnel a private target past it, and a custom TLS dialer, which
// net/http prefers over the pinned dialer on https. TLSClientConfig is kept, so
// client certificates and a pinned root set are carried the way the pin allows.
func NewGuardedTransport(base *http.Transport) http.RoundTripper {
	return RequireHTTPS(SSRFGuard(base))
}

// RequireHTTPS wraps base with the scheme check alone: a request whose scheme is
// not https is refused before base sees it, with the same "SSRF guard" error
// NewGuardedTransport returns. The legs that dial a peer another party named
// apply it ABOVE a transport the caller injected, so an injected transport
// replaces the address guard but can never carry a signature or a proof of
// possession over plaintext.
func RequireHTTPS(base http.RoundTripper) http.RoundTripper {
	return &schemeGuardRoundTripper{base: base}
}

// schemeGuardRoundTripper enforces the scheme policy on the INITIAL request
// before any dial: https is allowed, every other scheme denied, plaintext http
// included. A denied scheme is refused up front with an "SSRF guard" error, so an
// http target never reaches the transport.
type schemeGuardRoundTripper struct {
	base http.RoundTripper
}

func (g *schemeGuardRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if !schemeGuardAllows(req.URL.Scheme) {
		return nil, fmt.Errorf(
			"resolvers: refusing to dial disallowed scheme %q (SSRF guard)", req.URL.Scheme)
	}
	return g.base.RoundTrip(req)
}

// schemeGuardAllows is the scheme decision: https, and nothing else (a scheme
// denylist is unwinnable: http, ftp, ftps, telnet, gopher, file, data, dict, ...).
// Case-insensitive per RFC 3986.
func schemeGuardAllows(scheme string) bool {
	return strings.EqualFold(scheme, "https")
}

// schemeCheckRedirect bounds redirect depth and re-vets every redirect target's
// scheme under the SAME https-only policy; the redirect target's ADDRESS is
// re-pinned automatically by the guarded dialer.
func schemeCheckRedirect(req *http.Request, via []*http.Request) error {
	if redirectChainRefused(len(via)) {
		return fmt.Errorf("resolvers: too many redirects (SSRF guard)")
	}
	if !schemeGuardAllows(req.URL.Scheme) {
		return fmt.Errorf(
			"resolvers: refusing redirect to disallowed scheme %q (SSRF guard)", req.URL.Scheme)
	}
	return nil
}
