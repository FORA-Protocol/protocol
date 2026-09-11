package resolvers_test

// Go replay of the fetcher-level host+port join corpus (wba-join-vectors.json).
//
// The corpus is emitted by running the Go joinDirectoryHost oracle, so Go replays it
// too rather than only emitting it — a corpus its own oracle does not consume proves
// nothing about the oracle. Without this suite you could delete the join from
// NewWBADirectoryFetcher, leave wba-join-vectors.json byte-identical, watch all three
// suites pass, and have Go dial a different URL than the table says.
//
// The emitter and this replay are deliberately not the same code path. The emitter
// calls the private joinDirectoryHost; this asserts through the PUBLIC
// NewWBADirectoryFetcher with a recording transport, which is the same surface the
// Python and TypeScript replays use. Two things are proved that way instead of one:
// the fetcher's join is the one the corpus records, AND the fetcher builds its URL
// from the shared WBADirectoryURL builder rather than from a string of its own.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

type wbaJoinReplayVector struct {
	Label        string `json:"label"`
	Domain       string `json:"domain"`
	Port         string `json:"port"`
	ExpectedHost string `json:"expected_host"`
	Dialable     bool   `json:"dialable"`
}

// requiredJoinLabels is the behavior the corpus MUST cover, stated here as the
// contract so a thinner corpus fails this suite and not only the drift gate. The
// Python and TypeScript replays carry the same list.
var requiredJoinLabels = []string{
	"empty-port",           // the domain passes through so the scheme default applies
	"plain-domain",         // an ordinary domain gains :port
	"bare-ipv6",            // an unbracketed IPv6 literal gains brackets before the port
	"bracketed-ipv6",       // an already-bracketed literal is bracketed AGAIN
	"domain-with-port",     // a domain already carrying a port is bracketed as a colon-bearing host
	"empty-port-bare-ipv6", // an empty port wins over the colon rule
}

// recordingTransport captures the URL of every request that reaches a transport and
// answers each one with an empty directory.
type recordingTransport struct {
	urls []string
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.urls = append(t.urls, req.URL.String())
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"keys":[]}`)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestWBADirectoryFetcherReplaysJoinCorpus(t *testing.T) {
	t.Parallel()
	path := filepath.Join("testdata", "wba-join-vectors.json")
	raw, err := os.ReadFile(path) //nolint:gosec // a committed test vector this package owns
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Note    string                `json:"note"`
		Vectors []wbaJoinReplayVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", path)
	}

	labels := make(map[string]bool, len(doc.Vectors))
	for _, v := range doc.Vectors {
		labels[v.Label] = true
	}
	for _, want := range requiredJoinLabels {
		if !labels[want] {
			t.Errorf("corpus is missing required vector %q", want)
		}
	}

	for _, v := range doc.Vectors {
		t.Run(v.Label, func(t *testing.T) {
			t.Parallel()
			rec := &recordingTransport{}
			fetch := resolvers.NewWBADirectoryFetcher(&http.Client{Transport: rec}, "https", v.Port)

			got, err := fetch(context.Background(), v.Domain)

			if !v.Dialable {
				// The joined authority does not form a URL. http.NewRequestWithContext
				// refuses it, so no request reaches the transport and the failure is
				// contained as ErrDirectoryUnavailable — the same outcome the Python
				// and TypeScript replays assert for this vector.
				if len(rec.urls) != 0 {
					t.Fatalf("%s: the oracle joins domain=%q port=%q to %q, which is not a valid authority — the fetcher must dial nothing, but it dialled %v",
						v.Label, v.Domain, v.Port, v.ExpectedHost, rec.urls)
				}
				if !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
					t.Fatalf("%s: an unformable URL must be contained as ErrDirectoryUnavailable, got %v", v.Label, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("%s: fetch: %v", v.Label, err)
			}
			if got == nil {
				t.Fatalf("%s: fetch returned no directory", v.Label)
			}
			wantURL := resolvers.WBADirectoryURL("https", v.ExpectedHost)
			if len(rec.urls) != 1 || rec.urls[0] != wantURL {
				t.Fatalf("%s: the fetcher dialled %v for domain=%q port=%q, but the oracle joins that to %q (URL %q)",
					v.Label, rec.urls, v.Domain, v.Port, v.ExpectedHost, wantURL)
			}
		})
	}
}
