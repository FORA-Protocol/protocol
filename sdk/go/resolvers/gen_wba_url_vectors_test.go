package resolvers

// Golden-vector emitter for the cross-language WBA-directory URL-builder parity
// corpus. sdk/python `wba_directory_url` and sdk/ts `wbaDirectoryURL` REPLAY this
// corpus and MUST reproduce the sdk/go `WBADirectoryURL` oracle's built URL for
// EVERY vector.
//
// The built URL is what a WBA identity directory is fetched from:
// scheme://host + WBADirectoryPath. Each vector is {label, scheme, host,
// expected_url}; scheme/host are the two explicit builder args (scheme empty →
// https, host arrives ALREADY-JOINED) and expected_url is emitted by RUNNING the
// real Go WBADirectoryURL — Go is the oracle, never a hand-authored table.
//
// COVERAGE (the seam the three languages must agree on): (a) https-default — an
// empty scheme defaults to https; (b) explicit-http — a non-default scheme is
// honored verbatim; (c) host-with-port — a host carrying :port is passed through
// unchanged; (d) ipv6-passthrough — an ALREADY-bracketed IPv6 host is not mangled
// (this proves the PURE builder passes a pre-joined host through verbatim; it does
// NOT lock the fetcher-level Go-net.JoinHostPort-vs-TS-${domain}:${port} port-join,
// which lives in the fetchers and is tracked separately).
//
// DETERMINISM: the inputs are fixed literals, so re-running reproduces byte-identical
// output. `go test` asserts the committed file matches a fresh emit; a mismatch leaves a
// .got file beside the corpus (vectorio.Check) (same drift-gate shape as
// gen_offer_key_clamp_vectors_test.go).

import (
	"path/filepath"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

// wbaURLVector is one builder input pair + the oracle's built URL.
type wbaURLVector struct {
	Label       string `json:"label"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	ExpectedURL string `json:"expected_url"` // emitted by the Go WBADirectoryURL
}

type wbaURLCorpus struct {
	Note    string         `json:"note"`
	Vectors []wbaURLVector `json:"vectors"`
}

func buildWBAURLCorpus() wbaURLCorpus {
	build := func(label, scheme, host string) wbaURLVector {
		return wbaURLVector{
			Label:       label,
			Scheme:      scheme,
			Host:        host,
			ExpectedURL: WBADirectoryURL(scheme, host),
		}
	}
	return wbaURLCorpus{
		Note: "WBA directory URL = scheme://host + /.well-known/http-message-signatures-directory, produced by the sdk/go WBADirectoryURL oracle; py/ts replay and must match every vector",
		Vectors: []wbaURLVector{
			build("https-default", "", "exchange.example"),
			build("explicit-http", "http", "exchange.example"),
			build("host-with-port", "https", "exchange.example:8443"),
			build("ipv6-passthrough", "https", "[2001:db8::1]:8443"),
		},
	}
}

// TestGenerateWBAURLVector emits the WBA-URL golden vector. It asserts the committed file
// is byte-identical to a fresh emit; a mismatch leaves a .got file beside the corpus
// (vectorio.Check).
func TestGenerateWBAURLVector(t *testing.T) {
	t.Parallel()
	corpus := buildWBAURLCorpus()
	path := filepath.Join("testdata", "wba-url-vectors.json")

	if err := vectorio.Check(path, corpus); err != nil {
		t.Fatal(err)
	}
}
