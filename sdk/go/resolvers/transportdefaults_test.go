package resolvers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// Which transport a resolver takes when the caller injects none, for the one face the
// shared corpus cannot carry.
//
// The rule is that a resolver's default follows its URL's PROVENANCE: a fixed,
// operator-chosen address takes the plain client, a host another party named takes
// the guarded one (the WellKnownOptions.HTTP comment). Every face whose outcome reads
// the same through all three public surfaces is pinned by the shared corpus
// testdata/resolver-default-vectors.json, emitted by gen_resolver_default_vectors_test.go
// and replayed by both ports.
//
// The offer-directory fetch is the exception. Its default is guarded in all three
// languages, but the ports' seam contains every failure as "no directory" where Go
// returns the error, so the refusal a corpus row records is not observable through
// two of the three surfaces. What every language can observe is the socket: the
// guarded default never connects to a loopback listener. Each language pins that here,
// in its own copy of this test.
//
// CHANGING THIS OBLIGES A CHECK OF THE License.uri SSRF GUARDS in
// proto/fora/v1/fora.proto and Licensing Terms
// (website/src/content/docs/protocol/licensing-terms.mdx), which say what a consumer
// must apply before it fetches a URL another party named.
func TestOfferDirectoryFetchDefaultsToGuarded(t *testing.T) {
	// The flags are cleared rather than inherited from the shell, and ALLOW_INSECURE
	// is set so the scheme guard is not what refuses the plaintext listener: the
	// address guard must. t.Setenv restores them after the test.
	t.Setenv("SKIP_SSRF", "")
	t.Setenv("ALLOW_INSECURE", "1")
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	// The error is deliberately ignored: which outcome occurred is what `reached` says.
	_, _ = resolvers.NewWBADirectoryFetcher(nil, "http", "")(context.Background(), hostOf(t, srv))
	if reached {
		t.Fatal("the offer-directory fetch's default transport reached a loopback origin; " +
			"its exchange domain comes off an offer, so the default must be the guarded client")
	}
}
