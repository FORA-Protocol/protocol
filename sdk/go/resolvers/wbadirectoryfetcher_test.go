package resolvers_test

// NewWBADirectoryFetcher, the offer-key cache's default directory read, as a caller
// that classifies its failures sees them. Every failure is ErrDirectoryUnavailable,
// so a fail-closed caller halts on all of them; a 404, a redirect, the wrong media
// type and a response whose signatures cannot be checked also carry a sentinel of
// their own, so a caller can tell what the directory answered from an outage
// without reading the message.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

func TestWBADirectoryFetcherNamesWhatTheDirectoryAnswered(t *testing.T) {
	_, jwk := newSigningKey("fetcher-answers", wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
	body := marshalWBA(jwk)
	var answer atomic.Value // http.HandlerFunc
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		answer.Load().(http.HandlerFunc)(w, r)
	}))
	t.Cleanup(srv.Close)
	fetch := resolvers.NewWBADirectoryFetcher(srv.Client(), "http", "")
	domain := hostOf(t, srv)
	ctx := context.Background()

	answer.Store(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeSignedDirectory(w, r, body) }))
	if f, err := fetch(ctx, domain); err != nil || len(f.GetKeys()) != 1 {
		t.Fatalf("the signed directory: keys %v, err %v; want its one key", f.GetKeys(), err)
	}

	status := func(code int) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
	}
	all := []error{
		resolvers.ErrDocumentNotFound, resolvers.ErrRedirectRefused, resolvers.ErrMediaTypeRefused,
		helpers.ErrDirectoryResponseUnsigned, helpers.ErrDigestMismatch,
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		also    []error
	}{
		{"404", status(http.StatusNotFound), []error{resolvers.ErrDocumentNotFound}},
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, []error{resolvers.ErrRedirectRefused}},
		{"503", status(http.StatusServiceUnavailable), nil},
		{"the JWK Set media type", func(w http.ResponseWriter, r *http.Request) {
			rec := httptest.NewRecorder()
			writeSignedDirectory(rec, r, body)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.Header().Set("Content-Type", "application/jwk-set+json")
			_, _ = w.Write(rec.Body.Bytes())
		}, []error{resolvers.ErrMediaTypeRefused}},
		{"a Content-Digest that does not match", func(w http.ResponseWriter, r *http.Request) {
			writeDirectoryWithWrongDigest(w, r, body)
		}, []error{helpers.ErrDirectoryResponseUnsigned, helpers.ErrDigestMismatch}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answer.Store(tc.handler)
			before := hits.Load()
			_, err := fetch(ctx, domain)
			if hits.Load() == before {
				t.Fatal("the directory was never asked")
			}
			if !errors.Is(err, resolvers.ErrDirectoryUnavailable) || errors.Is(err, resolvers.ErrUnknownKey) {
				t.Fatalf("err = %v, want ErrDirectoryUnavailable and never ErrUnknownKey", err)
			}
			for _, sentinel := range all {
				want := false
				for _, a := range tc.also {
					want = want || a == sentinel
				}
				if errors.Is(err, sentinel) != want {
					t.Errorf("err = %v: errors.Is(%v) = %v, want %v", err, sentinel, !want, want)
				}
			}
		})
	}

	t.Run("a host that does not answer", func(t *testing.T) {
		srv.Close()
		_, err := fetch(ctx, domain)
		if !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			t.Fatalf("err = %v, want ErrDirectoryUnavailable", err)
		}
		for _, sentinel := range all {
			if errors.Is(err, sentinel) {
				t.Errorf("err = %v also matches %v", err, sentinel)
			}
		}
	})
}

// A directory's response signatures are judged at a clock. A fetcher built with
// WBADirectoryFetcherOptions.Now reads that clock on every fetch, so the cache that
// selects keys and the fetch that checks the directory can run on one clock.
func TestWBADirectoryFetcherJudgesResponseSignaturesAtItsClock(t *testing.T) {
	created := int64(1_000_000_000)
	expires := created + 60
	inWindow := time.Unix(created+30, 0)
	priv, jwk := newSigningKey("fetcher-clock", inWindow.Add(-time.Hour), inWindow.Add(time.Hour))
	body := marshalWBA(jwk)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeSignedDirectoryWindow(w, r, body, created, expires)
	}))
	t.Cleanup(srv.Close)
	domain := hostOf(t, srv)
	ctx := context.Background()

	// The wall clock is long past the window, so the response signature has expired
	// and the key it signed is not handed out.
	wall := resolvers.NewWBADirectoryFetcher(srv.Client(), "http", "")
	if f, err := wall(ctx, domain); err != nil || len(f.GetKeys()) != 0 {
		t.Fatalf("at the wall clock: keys %v, err %v; want none", f.GetKeys(), err)
	}

	now := inWindow
	clock := func() time.Time { return now }
	fetch := resolvers.NewWBADirectoryFetcher(srv.Client(), "http", "", resolvers.WBADirectoryFetcherOptions{Now: clock})
	if f, err := fetch(ctx, domain); err != nil || len(f.GetKeys()) != 1 {
		t.Fatalf("inside the window: keys %v, err %v; want the one key", f.GetKeys(), err)
	}
	// Read on every fetch, never captured when the fetcher was built.
	now = time.Unix(expires+1, 0)
	if f, err := fetch(ctx, domain); err != nil || len(f.GetKeys()) != 0 {
		t.Fatalf("after the window: keys %v, err %v; want none", f.GetKeys(), err)
	}

	// One clock for the cache and the fetch it calls resolves the key; the same cache
	// over a fetcher on the wall clock finds none to select.
	now = inWindow
	shared := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{Fetch: fetch, Now: clock})
	if key, err := shared.Resolve(ctx, domain); err != nil || !key.Equal(priv.Public()) {
		t.Fatalf("one clock: key %x, err %v; want the key the directory signed for", key, err)
	}
	split := resolvers.NewCachedOfferKeyResolver(resolvers.CachedOfferKeyResolverConfig{Fetch: wall, Now: clock})
	if _, err := split.Resolve(ctx, domain); !errors.Is(err, resolvers.ErrUnknownKey) {
		t.Fatalf("two clocks: err = %v, want ErrUnknownKey", err)
	}
}
