package helpers_test

// Structural IO-leaf guard for the pure L1 helpers tree — the Go analogue of the
// Python (test_guards_resolvers_io_leaf) and TS (resolvers-io-leaf.guard) guards,
// which fail the build on an httpx / undici import in the transport-neutral core.
//
// sdk/go/helpers is the SDK's pure, IO-FREE protocol-mechanics tier: RFC 7638
// thumbprint, signed-URL verify, RFC 9421 sign/verify + PoP, offer-acceptance,
// cross-field validation. It legitimately uses net/http REQUEST TYPES
// (http.Header, *http.Request) to canonicalize/verify signatures, but it MUST NOT
// DIAL — no HTTP client, no socket. All dialing lives one tier up, in
// sdk/go/resolvers (the fetching faces), behind the SSRF guard. A helpers file that
// pulled in http.Client / http.Get / net.Dial / an http.Transport would drag the
// pre-auth-reachable network surface into the trust core — exactly the regression
// this guard bans, matching the other two SDKs' io-leaf guards.
//
// The scan covers every package of this module that helpers is built from, not only
// this directory: code helpers calls in an internal package (the canonical renderer in
// internal/canonicalsign, for one) is as much the trust core as helpers' own files, and
// moving code there must not move it out of the guard's reach. The generated wire
// packages under gen/ are left out of this substring scan: they are regenerated rather
// than written, and the connect-free guard (connectrpc_free_test.go) checks their
// imports.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/importclosure"
)

// forbiddenDialingTokens are the DIAL/socket surfaces a pure-tier file must not
// use. Each is matched precisely so the legitimate request-TYPE surface
// (http.Header, http.Request) is NOT flagged — e.g. "http.Head(" carries the
// paren so it never matches "http.Header".
var forbiddenDialingTokens = []string{
	"http.Client",
	"http.DefaultClient",
	"http.DefaultTransport",
	"http.Transport",
	"http.RoundTripper",
	"http.Get(",
	"http.Post(",
	"http.PostForm(",
	"http.Head(",
	"http.NewRequest", // constructs a request to SEND (dialing intent)
	"net.Dial",
	"net.Listen",
	".RoundTrip(",
}

// importsDialingSurface is the pure predicate (extracted so meta-tests can
// exercise it): a pure-tier file leaks IO if it names any dialing/socket surface.
func importsDialingSurface(source string) bool {
	for _, tok := range forbiddenDialingTokens {
		if strings.Contains(source, tok) {
			return true
		}
	}
	return false
}

// helpersClosure returns the module root, the module path, and the directory of every
// package of this module that sdk/go/helpers is built from, helpers included, keyed by
// import path. Both purity guards of this package scan it.
func helpersClosure(t *testing.T) (root, module string, closure map[string]string) {
	t.Helper()
	root = filepath.Join("..", "..", "..")
	module, err := importclosure.ModulePath(root)
	if err != nil {
		t.Fatal(err)
	}
	closure, err = importclosure.Walk(root, module, module+"/sdk/go/helpers")
	if err != nil {
		t.Fatal(err)
	}
	// Pinned, so a closure that stopped reaching them fails here instead of scanning
	// less: helpers itself, the canonical renderer it calls, and the wire types it reads.
	for _, pkg := range []string{"sdk/go/helpers", "sdk/go/internal/canonicalsign", "gen/go/fora/v1"} {
		if _, ok := closure[module+"/"+pkg]; !ok {
			t.Fatalf("the closure of sdk/go/helpers no longer reaches %s, so the purity guards would not scan it", pkg)
		}
	}
	return root, module, closure
}

// pureHelperSources returns the module root and every non-test Go file of a package
// helpers is built from, except the generated ones.
func pureHelperSources(t *testing.T) (string, []string) {
	t.Helper()
	root, module, closure := helpersClosure(t)
	var out []string
	for path, dir := range closure {
		if strings.HasPrefix(path, module+"/gen/") {
			continue
		}
		files, err := importclosure.SourceFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, files...)
	}
	sort.Strings(out)
	return root, out
}

func TestHelpersIoLeafGuard_NoDialingSurface(t *testing.T) {
	root, sources := pureHelperSources(t)
	if len(sources) == 0 {
		t.Fatal("no helpers sources found — the io-leaf guard would vacuously pass")
	}
	for _, file := range sources {
		b, err := os.ReadFile(file) //nolint:gosec // a source file of this module
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		if importsDialingSurface(string(b)) {
			name, _ := filepath.Rel(root, file)
			t.Errorf("pure L1 file %s names a DIALING/socket surface — the trust core must open no sockets; move any fetch into sdk/go/resolvers behind the SSRF guard", name)
		}
	}
}

// --- meta-tests: exercise the detector against synthetic source ---------------

func TestHelpersIoLeafGuard_MetaPositive(t *testing.T) {
	for _, src := range []string{
		"c := http.Client{}",
		"resp, _ := http.Get(url)",
		"conn, _ := net.Dial(\"tcp\", addr)",
		"t := &http.Transport{}",
		"http.DefaultClient.Do(req)",
	} {
		if !importsDialingSurface(src) {
			t.Errorf("detector missed a dialing surface: %q", src)
		}
	}
}

func TestHelpersIoLeafGuard_MetaNegative(t *testing.T) {
	// The legitimate request-TYPE surface must NOT be flagged.
	for _, src := range []string{
		"func f(h http.Header) {}",
		"func g(r *http.Request) {}",
		"h.Get(\"Signature\")", // http.Header.Get, not http.Get
	} {
		if importsDialingSurface(src) {
			t.Errorf("detector false-positived on a pure request-type use: %q", src)
		}
	}
}
