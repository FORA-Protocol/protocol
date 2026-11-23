package resolvers_test

// The content leg's injection point, ContentFetchOptions.Transport: an injected
// round-tripper is dialed exactly as given, and the https-only check stays above it.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// answeringTransport answers every request with a 200 carrying body, and records
// the URL of each request it was handed.
type answeringTransport struct {
	body string
	seen []string
}

func (r *answeringTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.seen = append(r.seen, req.URL.String())
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

func TestContentFetcher_DialsAnInjectedTransportAsGiven(t *testing.T) {
	rt := &answeringTransport{body: "licensed"}
	fetcher := resolvers.NewContentFetcher(resolvers.ContentFetchOptions{Transport: rt})
	const target = "https://edge.example/doc?agent_id=tp"

	got, err := fetcher.Fetch(context.Background(), target, newPopSigner(t))
	if err != nil {
		t.Fatalf("fetch through the injected transport: %v", err)
	}
	if len(rt.seen) != 1 || rt.seen[0] != target {
		t.Fatalf("injected transport saw %q, want exactly one request for %q", rt.seen, target)
	}
	if string(got.Body) != "licensed" {
		t.Errorf("body = %q, want the injected transport's answer", got.Body)
	}
}

// A plaintext delivery URL is refused before the injected transport sees it: the
// transport decides where a request is dialed, never whether a proof of possession
// may travel over plaintext.
func TestContentFetcher_RefusesPlaintextAboveAnInjectedTransport(t *testing.T) {
	rt := &answeringTransport{body: "licensed"}
	fetcher := resolvers.NewContentFetcher(resolvers.ContentFetchOptions{Transport: rt})

	_, err := fetcher.Fetch(context.Background(), "http://edge.example/doc", newPopSigner(t))
	var ferr *resolvers.FetchError
	if !errors.As(err, &ferr) {
		t.Fatalf("want a typed FetchError, got %v", err)
	}
	if ferr.Failure != resolvers.FetchUnreachable || !strings.Contains(err.Error(), "SSRF guard") {
		t.Errorf("error = %v, want an unreachable FetchError from the scheme guard", err)
	}
	if len(rt.seen) != 0 {
		t.Errorf("injected transport saw %q; a plaintext URL must never reach it", rt.seen)
	}
}
