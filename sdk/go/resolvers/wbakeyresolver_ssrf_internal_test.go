package resolvers

// Internal test: the SSRF guard on the built-in WBA HTTP client lives on an
// unexported constructor, so it is exercised from inside the package.

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// TestSSRFBlocked_ReservedRanges pins the reserved/non-public classification,
// including the ranges the old IsPrivate() heuristic missed: CGNAT,
// 0.0.0.0/8, and the v4-mapped / NAT64 forms that embed a private v4.
func TestSSRFBlocked_ReservedRanges(t *testing.T) {
	blocked := []string{
		"0.1.2.3",            // 0.0.0.0/8 non-zero host
		"10.0.0.1",           // RFC 1918
		"100.64.0.1",         // CGNAT — missed by IsPrivate()
		"127.0.0.1",          // loopback
		"169.254.169.254",    // link-local / cloud metadata
		"172.16.5.5",         // RFC 1918
		"192.168.1.1",        // RFC 1918
		"198.18.0.1",         // benchmarking
		"192.0.2.7",          // TEST-NET-1
		"::1",                // v6 loopback
		"fc00::1",            // ULA
		"fe80::1",            // v6 link-local
		"::ffff:169.254.1.1", // v4-mapped link-local — must unwrap
		"::ffff:10.0.0.1",    // v4-mapped RFC 1918
		"64:ff9b::a9fe:a9fe", // NAT64-embedded 169.254.169.254 — must unwrap
		"64:ff9b::0a00:0001", // NAT64-embedded 10.0.0.1
		"2001:db8::1",        // documentation
	}
	for _, s := range blocked {
		if !ssrfBlocked(netip.MustParseAddr(s)) {
			t.Errorf("ssrfBlocked(%s) = false, want blocked", s)
		}
	}
	allowed := []string{
		"8.8.8.8",              // public v4
		"1.1.1.1",              // public v4
		"93.184.216.34",        // public v4 (example.com)
		"2606:4700:4700::1111", // public v6 (cloudflare)
	}
	for _, s := range allowed {
		if ssrfBlocked(netip.MustParseAddr(s)) {
			t.Errorf("ssrfBlocked(%s) = true, want allowed", s)
		}
	}
}

// TestGuardedWBAClientBlocksLoopback: the default (caller-injected-none) client
// must refuse to dial a loopback/private target. The WBA directory host is a
// caller-supplied Signature-Agent fetched BEFORE the ed25519 check, so an
// unguarded default is a pre-auth SSRF lever. httptest servers listen on
// 127.0.0.1, so a successful GET here would prove the guard is absent.
func TestGuardedWBAClientBlocksLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, err := statusOf(NewWBAKeyResolver(WBAKeyResolverOptions{}).http, srv.URL) // https://127.0.0.1:<port>
	if err == nil {
		t.Fatal("guarded client dialed a loopback target — the SSRF guard did not fire")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("dial failed for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestNewWBAKeyResolverDefaultsToGuardedClient: constructing without opts.HTTP
// installs the guarded client (not http.DefaultClient), so the SSRF default is
// on unless the caller opts out by injecting their own client.
func TestNewWBAKeyResolverDefaultsToGuardedClient(t *testing.T) {
	r := NewWBAKeyResolver(WBAKeyResolverOptions{})
	if r.http == http.DefaultClient {
		t.Fatal("WBAKeyResolver fell back to http.DefaultClient — the SSRF guard is bypassed by default")
	}
	if r.http == nil {
		t.Fatal("WBAKeyResolver has no HTTP client")
	}
}

// TestNewWellKnownEndpointResolverDefaultsToGuardedClient: the endpoint resolver's
// host is request-derived (a per-request Offer.exchange), so constructing without
// opts.HTTP must install the SSRF-guarded client — a guarded client refuses a
// loopback target, so a loopback GET through the default must fail with an SSRF
// error (never reach the httptest origin).
func TestNewWellKnownEndpointResolverDefaultsToGuardedClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := NewWellKnownEndpointResolver(WellKnownOptions{})
	if _, err := r.ResolveEndpoint(t.Context(), u.Host); err == nil {
		t.Fatal("endpoint resolver default reached a loopback target — it did not install the SSRF-guarded client")
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("endpoint resolver refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestSSRFGuardNilsProxy: a base transport carrying a Proxy would tunnel the dial
// to the PROXY, so the dial-time address check would vet the proxy's IP instead of
// the true target — a full bypass. SSRFGuard must force Proxy=nil, so a guarded
// client built over a proxied base still refuses a loopback (internal) target at
// the dial seam rather than tunneling to the proxy.
func TestSSRFGuardNilsProxy(t *testing.T) {
	proxyURL, _ := url.Parse("http://127.0.0.1:9") // a proxy that must never be used
	base := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	guarded := SSRFGuard(base)
	if guarded.Proxy != nil {
		t.Fatal("SSRFGuard did not nil the base transport's Proxy — a proxied CONNECT could tunnel past the dial guard")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := &http.Client{Transport: guarded}
	if _, err := client.Get(srv.URL); err == nil { // srv.URL is loopback
		t.Fatal(
			"guarded client over a proxied base reached a loopback target — Proxy was honored, bypassing the dial guard",
		)
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("dial refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestSSRFGuardNilsCustomTLSDialers: net/http prefers a transport's own TLS
// dialer over DialContext for https, so a base carrying DialTLSContext (or the
// legacy DialTLS) would take the dial through the caller's dialer and the
// address pin would never run — on https, which is every FORA leg. SSRFGuard
// must clear both, so a guarded client built over such a base still refuses a
// loopback target at the dial seam.
//
// The base also carries the server's own TLS config, which is what a caller
// customising TLS legitimately supplies: that must keep working, and only the
// dialer is dropped.
func TestSSRFGuardNilsCustomTLSDialers(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig

	base := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, tlsCfg)
		},
		DialTLS: func(network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, tlsCfg)
		},
	}
	guarded := SSRFGuard(base)
	if guarded.DialTLSContext != nil || guarded.DialTLS != nil {
		t.Fatal(
			"SSRFGuard left a custom TLS dialer installed — net/http prefers it over DialContext on https, so the address pin never runs",
		)
	}
	if guarded.TLSClientConfig == nil {
		t.Error("SSRFGuard dropped the caller's TLS config; only the dialer is mutually exclusive with the pin")
	}
	client := &http.Client{Transport: guarded}
	if _, err := client.Get(srv.URL); err == nil { // srv.URL is loopback
		t.Fatal(
			"guarded client over a base with a custom TLS dialer reached a loopback target — the dial guard was bypassed",
		)
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("dial refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// wiringClient is the guarded client's redirect and status policy over a transport
// that reaches srv, the way a caller reaches a private peer: the address pin is the
// part an injected transport replaces, so the policy the client keeps is what these
// tests exercise. The https-only check stays above the injected transport, as on
// every leg that takes one.
func wiringClient(srv *httptest.Server) *http.Client {
	client := NewGuardedClientFromEnv()
	client.Transport = RequireHTTPS(srv.Client().Transport)
	return client
}

// statusOf GETs url through client and returns the answer's status, closing its body.
func statusOf(client *http.Client, url string) (int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// TestGuardedClientRedirectDepthCap: the guarded client follows at most
// maxWBARedirects redirect hops and refuses the next — the real-dial confirmation
// that the client honors the shared redirect corpus (a chain exactly at the cap is
// followed to its 200 terminal; one hop over is refused with an SSRF error). This
// pins the cap so no future change silently inherits net/http's larger default.
func TestGuardedClientRedirectDepthCap(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /n redirects to /(n-1); /0 is the terminal 200.
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if n <= 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, srv.URL+"/"+strconv.Itoa(n-1), http.StatusFound)
	}))
	defer srv.Close()

	// Exactly at the cap: all maxWBARedirects hops followed to the 200 terminal.
	status, err := statusOf(wiringClient(srv), srv.URL+"/"+strconv.Itoa(maxWBARedirects))
	if err != nil {
		t.Fatalf("a chain of %d redirects (at the cap) was refused, want followed: %v", maxWBARedirects, err)
	}
	if status != http.StatusOK {
		t.Fatalf("at-cap chain StatusCode = %d, want 200", status)
	}

	// One hop over the cap: refused.
	if _, err := statusOf(wiringClient(srv), srv.URL+"/"+strconv.Itoa(maxWBARedirects+1)); err == nil {
		t.Fatalf("a chain of %d redirects (one over the cap) was followed, want refused", maxWBARedirects+1)
	} else if !strings.Contains(err.Error(), "SSRF guard") {
		t.Fatalf("over-cap chain refused for the wrong reason (want SSRF guard): %v", err)
	}
}

// TestGuardedClientSurfacesNon2xx: a non-2xx directory response must surface
// as an ordinary (StatusCode, nil-error) response, never a transport error — the
// read classifies the status itself (a 404 is ErrDocumentNotFound and a 5xx is
// not, both wrapped with ErrDirectoryUnavailable, and neither is an unknown key).
// Parity with the Python (fetch_soft→None / fetch_strict→outage) and TS
// (fetchStrict→DirectoryUnavailable) non-2xx behavioral tests; Go's path is stock
// net/http, so this locks the contract rather than guarding custom wiring (the
// non-2xx crash that motivated this suite was Python's hand-built opener).
func TestGuardedClientSurfacesNon2xx(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	status, err := statusOf(wiringClient(srv), srv.URL)
	if err != nil {
		t.Fatalf("non-2xx surfaced as a transport error, want a 404 response: %v", err)
	}
	if status != http.StatusNotFound {
		t.Fatalf("StatusCode = %d, want 404", status)
	}
}

// TestGuardedClientRefusesRedirectScheme: a 302 into a scheme other than https
// (ftp, or plaintext http) must be refused by CheckRedirect BEFORE any dial to it
// — the guard is a deny-by-default scheme allowlist, not an ftp-specific block.
// Parity with the Python test_guarded_fetch_refuses_redirect_to_ftp behavioral
// test. The redirect target is never contacted.
func TestGuardedClientRefusesRedirectScheme(t *testing.T) {
	for _, target := range []string{"ftp://ftp.internal.example/secret", "http://plain.internal.example/secret"} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}))
		_, err := statusOf(wiringClient(srv), srv.URL)
		srv.Close()
		if err == nil {
			t.Fatalf("guarded client followed a redirect to %s — CheckRedirect did not fire", target)
		}
		if !strings.Contains(err.Error(), "refusing redirect") {
			t.Fatalf("redirect to %s refused for the wrong reason (want the redirect scheme check): %v", target, err)
		}
	}
}
