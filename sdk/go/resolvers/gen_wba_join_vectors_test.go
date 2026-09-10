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
// bracketed. Cases (d) and (e) cannot arrive through a validated offer, since
// Offer.exchange is constrained to a bare domain with an optional numeric port.
// They are pinned so the three SDKs agree rather than diverge silently.
//
// DETERMINISM: the inputs are fixed literals, so re-running reproduces
// byte-identical output. Default `go test` asserts the committed file matches a
// fresh emit; FORA_UPDATE_VECTORS=1 rewrites it (same drift-gate shape as
// gen_wba_url_vectors_test.go).

import (
	"encoding/json"
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
}

type wbaJoinCorpus struct {
	Note    string          `json:"note"`
	Vectors []wbaJoinVector `json:"vectors"`
}

func buildWBAJoinCorpus() wbaJoinCorpus {
	build := func(label, domain, port string) wbaJoinVector {
		return wbaJoinVector{
			Label:        label,
			Domain:       domain,
			Port:         port,
			ExpectedHost: joinDirectoryHost(domain, port),
		}
	}
	return wbaJoinCorpus{
		Note: "fetcher-level host+port join, produced by the sdk/go joinDirectoryHost oracle (net.JoinHostPort, empty port passes through); py/ts replay and must match every vector",
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
