package resolvers

// Golden-vector emitter for the cross-language fetcher-level HOST+PORT JOIN parity
// corpus. sdk/python `_join_host_port` and sdk/ts `joinDirectoryHost` REPLAY this
// corpus and MUST reproduce the sdk/go `joinDirectoryHost` oracle's answer for
// EVERY vector.
//
// This is the seam wba-url-vectors.json deliberately does not cover. That corpus
// pins the PURE builder, which takes an ALREADY-JOINED host; the join that produces
// that host lives in each language's directory fetcher and was hand-written three
// times, with the three copies disagreeing on a bracketed IPv6 host. Go is the
// oracle here as everywhere else, so this corpus is what holds the other two to it.
//
// COVERAGE (the seam the three languages must agree on): (a) empty-port — the
// domain passes through untouched so the scheme default applies; (b) plain-domain —
// an ordinary domain gains :port; (c) bare-ipv6 — an unbracketed IPv6 literal gains
// brackets before the port; (d) bracketed-ipv6 — an ALREADY-bracketed literal is
// bracketed AGAIN, because that is what net.JoinHostPort does; (e) domain-with-port
// — a domain that already carries a port is treated as a colon-bearing host and
// bracketed; (f) empty-port-bare-ipv6 — an empty port wins over the colon rule, so
// the literal is left unbracketed.
//
// Only (d) is out of reach of a validated offer: Offer.exchange
// (proto/fora/v1/fora.proto) is constrained to a bare domain with an OPTIONAL
// NUMERIC PORT, and that optional port is exactly what admits (e)'s
// "exchange.example:8443" — the field's own doc comment uses that spelling as its
// example. So (e) is reachable in production: an Exchange whose offers name a port,
// read by a fetcher configured with a port of its own, joins to
// "[exchange.example:8443]:9000". No transport accepts that authority, the
// directory is never fetched, and every offer from that Exchange fails to verify
// down the fail-closed path. The vectors pin it, and Dialable below is what makes
// the outcome asserted rather than assumed.
//
// DETERMINISM: the inputs are fixed literals, so re-running reproduces
// byte-identical output. Default `go test` asserts the committed file matches a
// fresh emit; FORA_UPDATE_VECTORS=1 rewrites it (same drift-gate shape as
// gen_wba_url_vectors_test.go).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// wbaJoinVector is one join input pair + the oracle's joined authority.
type wbaJoinVector struct {
	Label        string `json:"label"`
	Domain       string `json:"domain"`
	Port         string `json:"port"`
	ExpectedHost string `json:"expected_host"` // emitted by the Go joinDirectoryHost
	// Dialable says whether the joined authority forms a URL a transport will
	// accept. Three of the vectors join to a string that is not a valid authority,
	// and the contract there is that the fetcher dials NOTHING and contains the
	// failure. The oracle emits the answer so all three replays branch on ONE
	// value; when each suite asked its own URL parser instead, Python asserted the
	// fetch dials nothing and TypeScript asserted the malformed string is dialled.
	Dialable bool `json:"dialable"`
}

type wbaJoinCorpus struct {
	Note    string          `json:"note"`
	Vectors []wbaJoinVector `json:"vectors"`
}

func buildWBAJoinCorpus() wbaJoinCorpus {
	build := func(label, domain, port string) wbaJoinVector {
		host := joinDirectoryHost(domain, port)
		// Dialability is decided the way the fetcher decides it: NewWBADirectoryFetcher
		// hands the built URL to http.NewRequestWithContext, and an authority net/url
		// refuses never reaches a transport.
		_, err := http.NewRequest(http.MethodGet, WBADirectoryURL("https", host), nil) //nolint:noctx // parse check only, never sent
		return wbaJoinVector{
			Label:        label,
			Domain:       domain,
			Port:         port,
			ExpectedHost: host,
			Dialable:     err == nil,
		}
	}
	return wbaJoinCorpus{
		Note: "fetcher-level host+port join, produced by the sdk/go joinDirectoryHost oracle (net.JoinHostPort, empty port passes through); go/py/ts all replay it and must match every vector, dialable included",
		Vectors: []wbaJoinVector{
			build("empty-port", "exchange.example", ""),
			build("plain-domain", "exchange.example", "8443"),
			build("bare-ipv6", "::1", "8443"),
			build("bracketed-ipv6", "[::1]", "8443"),
			build("domain-with-port", "exchange.example:8443", "9000"),
			build("empty-port-bare-ipv6", "::1", ""),
		},
	}
}

// TestGenerateWBAJoinVector emits the host+port join golden vector. Default run
// asserts the committed file is byte-identical to a fresh emit;
// FORA_UPDATE_VECTORS=1 rewrites it.
func TestGenerateWBAJoinVector(t *testing.T) {
	t.Parallel()
	corpus := buildWBAJoinCorpus()
	path := filepath.Join("testdata", "wba-join-vectors.json")

	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeWBAJoinVector(t, path, corpus)
		return
	}
	want, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", path)
	}
}

func writeWBAJoinVector(t *testing.T, path string, corpus wbaJoinCorpus) {
	t.Helper()
	b, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // committed test vector
		t.Fatalf("write %s: %v", path, err)
	}
}
