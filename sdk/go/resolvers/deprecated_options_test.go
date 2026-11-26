package resolvers_test

// The deprecated scheme and port options accept only https and its default port.
// Anything else is refused with the reader's own error before a request reaches the
// client, injected or not, so no value of them reaches a plaintext peer.

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// refusedBeforeDialing asserts that err is the scheme or port refusal and that rec
// saw no request.
func refusedBeforeDialing(t *testing.T, what string, err error, rec *recordingTransport) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: accepted, want a refusal", what)
	}
	if !strings.Contains(err.Error(), "disallowed scheme") && !strings.Contains(err.Error(), "port argument") {
		t.Fatalf("%s: refused for the wrong reason: %v", what, err)
	}
	if len(rec.urls) != 0 {
		t.Fatalf("%s: dialled %v; a refused option must reach no client", what, rec.urls)
	}
}

func TestDeprecatedSchemeOptionsRefuseAnythingButHTTPS(t *testing.T) {
	ctx := context.Background()
	for _, scheme := range []string{"http", "ftp", "HTTP"} {
		rec := &recordingTransport{}
		client := &http.Client{Transport: rec}

		_, err := resolvers.ReadManifest(ctx, "exchange.example", resolvers.ReadOptions{Client: client, Scheme: scheme})
		if !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			t.Errorf("ReadManifest with Scheme %q: %v, want ErrDirectoryUnavailable", scheme, err)
		}
		refusedBeforeDialing(t, "ReadManifest "+scheme, err, rec)

		_, err = resolvers.ReadWBADirectory(ctx, "exchange.example", resolvers.ReadOptions{Client: client, Scheme: scheme})
		refusedBeforeDialing(t, "ReadWBADirectory "+scheme, err, rec)

		opts := resolvers.WellKnownOptions{HTTP: client, Scheme: scheme}
		_, err = resolvers.NewWellKnownEndpointResolver(opts).ResolveEndpoint(ctx, "exchange.example")
		refusedBeforeDialing(t, "ResolveEndpoint "+scheme, err, rec)

		_, err = resolvers.NewWellKnownRequirementsReader(opts).ResolveRegistrationRequirements(ctx, "exchange.example")
		refusedBeforeDialing(t, "ResolveRegistrationRequirements "+scheme, err, rec)
	}
}

func TestDeprecatedDirectoryFetcherArgumentsRefuseAnythingButTheHTTPSDefaults(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ scheme, port string }{
		{"http", ""}, {"ftp", ""}, {"HTTP", ""}, {"", "8443"}, {"https", "80"},
	} {
		rec := &recordingTransport{}
		_, err := resolvers.NewWBADirectoryFetcher(&http.Client{Transport: rec}, tc.scheme, tc.port)(ctx, "exchange.example")
		if !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			t.Errorf("scheme %q port %q: %v, want ErrDirectoryUnavailable", tc.scheme, tc.port, err)
		}
		refusedBeforeDialing(t, "scheme "+tc.scheme+" port "+tc.port, err, rec)
	}
}

// The values the options still accept are the https defaults, and they are dialed
// as https.
func TestDeprecatedOptionsAcceptTheHTTPSDefaults(t *testing.T) {
	ctx := context.Background()
	rec := &recordingTransport{}
	client := &http.Client{Transport: rec}
	https := resolvers.WellKnownOptions{HTTP: client, Scheme: "https"}
	_, _ = resolvers.ReadManifest(ctx, "exchange.example", resolvers.ReadOptions{Client: client, Scheme: "https"})
	_, _ = resolvers.NewWellKnownEndpointResolver(https).ResolveEndpoint(ctx, "exchange.example")
	_, _ = resolvers.NewWellKnownRequirementsReader(https).ResolveRegistrationRequirements(ctx, "exchange.example")
	manifest := "https://exchange.example/.well-known/fora.json"
	if len(rec.urls) != 3 || rec.urls[0] != manifest || rec.urls[1] != manifest || rec.urls[2] != manifest {
		t.Fatalf("Scheme \"https\" dialled %v, want the manifest three times", rec.urls)
	}
}

func TestDeprecatedDirectoryFetcherAcceptsTheHTTPSDefaults(t *testing.T) {
	rec := &recordingTransport{}
	fetch := resolvers.NewWBADirectoryFetcher(&http.Client{Transport: rec}, "https", "443")
	if _, err := fetch(context.Background(), "exchange.example"); err != nil {
		t.Fatalf("https and port 443: %v", err)
	}
	want := "https://exchange.example:443" + resolvers.WBADirectoryPath
	if len(rec.urls) != 1 || rec.urls[0] != want {
		t.Errorf("dialled %v, want %q", rec.urls, want)
	}
}

// ReadWBADirectory reads the Scheme option only to build a bare host's URL. A full URL
// carries its own scheme, so a Scheme other than https is not read for it, and a value
// that is neither a URL nor a bare host is ErrInvalidHost whatever the Scheme. The Python
// and TypeScript SDKs hold the same two cases.
func TestDeprecatedSchemeOptionAndTheWBADirectoryURLForms(t *testing.T) {
	ctx := context.Background()
	url := "https://exchange.example" + resolvers.WBADirectoryPath
	rec := &recordingTransport{}
	opts := resolvers.ReadOptions{Client: &http.Client{Transport: rec}, Scheme: "http"}

	_, err := resolvers.ReadWBADirectory(ctx, url, opts)
	if err != nil && strings.Contains(err.Error(), "disallowed scheme") {
		t.Fatalf("a full URL with Scheme \"http\" was refused for the scheme: %v", err)
	}
	if len(rec.urls) != 1 || rec.urls[0] != url {
		t.Fatalf("a full URL with Scheme \"http\" dialled %v, want %q", rec.urls, url)
	}

	rec.urls = nil
	_, err = resolvers.ReadWBADirectory(ctx, "not a host", opts)
	if !errors.Is(err, helpers.ErrInvalidHost) {
		t.Fatalf("an invalid host with Scheme \"http\": %v, want ErrInvalidHost", err)
	}
	if len(rec.urls) != 0 {
		t.Fatalf("an invalid host dialled %v", rec.urls)
	}
}
