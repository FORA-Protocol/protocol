package resolvers

// Go replay of the document-fetch corpus (document-fetch-vectors.json).
//
// The corpus is the cross-language contract for the status a document read is
// answered with, so Go replays it too rather than only emitting it — a corpus its own
// oracle does not consume proves nothing about the oracle.
//
// The emitter and the replay are deliberately not the same code path: the emitter
// records which verdict the read reported, and this asserts each recorded verdict
// against the sentinels themselves. It also holds what every vector shares: a failure
// is always ErrDirectoryUnavailable and never ErrUnknownKey, and it never carries the
// Location the server chose.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocumentFetchCorpusReplay(t *testing.T) {
	path := filepath.Join("testdata", "document-fetch-vectors.json")
	raw, err := os.ReadFile(path) //nolint:gosec // a committed test vector this package owns
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc struct {
		Vectors []documentFetchVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", path)
	}
	controls := map[string]bool{}
	for _, v := range doc.Vectors {
		if v.Verdict == "ok" {
			controls[v.Read] = true
		}
		t.Run(v.Name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if v.Location != "" {
					w.Header().Set("Location", v.Location)
				}
				w.WriteHeader(v.Status)
			}))
			defer srv.Close()
			var err error
			switch v.Read {
			case "key_directory":
				_, err = fetchDocumentNoRedirect(context.Background(), srv.Client(), srv.URL+"/document")
			case "document":
				_, err = fetchDocument(context.Background(), srv.Client(), srv.URL+"/document")
			default:
				t.Fatalf("read %q is neither key_directory nor document", v.Read)
			}
			if v.Verdict == "ok" {
				if err != nil {
					t.Fatalf("the read failed for a vector recorded as ok: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrDirectoryUnavailable) || errors.Is(err, ErrUnknownKey) {
				t.Fatalf("err = %v, want ErrDirectoryUnavailable and never ErrUnknownKey", err)
			}
			notFound, refused := errors.Is(err, ErrDocumentNotFound), errors.Is(err, ErrRedirectRefused)
			switch v.Verdict {
			case "not_found":
				if !notFound || refused {
					t.Errorf("err = %v, want ErrDocumentNotFound alone", err)
				}
			case "redirect_refused":
				if !refused || notFound {
					t.Errorf("err = %v, want ErrRedirectRefused alone", err)
				}
			case "unavailable":
				if notFound || refused {
					t.Errorf("err = %v, want ErrDirectoryUnavailable with neither sentinel", err)
				}
			default:
				t.Fatalf("verdict %q is not one the corpus defines", v.Verdict)
			}
			if v.Location != "" && strings.Contains(err.Error(), v.Location) {
				t.Errorf("err = %q carries the Location the server chose", err)
			}
		})
	}
	for _, read := range []string{"key_directory", "document"} {
		if !controls[read] {
			t.Errorf("no %s vector is read: the corpus has no control for that read", read)
		}
	}
}
