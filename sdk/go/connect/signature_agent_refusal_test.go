package connect_test

// A Signature-Agent value the signer refuses is a malformed call. The client
// refuses it locally with the signer's own sentinel and sends nothing; without the
// signingRefused entry for that sentinel, connect-go would report the call as a
// peer that never answered.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// requireMalformed requires err to be a call the client refused as malformed
// before sending, and returns it.
func requireMalformed(t *testing.T, err error) *foraconnect.CallError {
	t.Helper()
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallMalformed {
		t.Fatalf("error = %v, want CallMalformed", err)
	}
	return cerr
}

func TestWithSignatureAgent_ARefusedValueIsMalformedAndNothingIsSent(t *testing.T) {
	const wellKnown = "https://agent.test/.well-known/http-message-signatures-directory"
	for _, tc := range []struct {
		name, value string
		want        error
	}{
		{"no value", "", helpers.ErrSignatureAgentRequired},
		{"an http origin", "http://agent.test", helpers.ErrSignatureAgentNotOrigin},
		{
			"the well-known URL over http", "http://agent.test/.well-known/http-message-signatures-directory",
			helpers.ErrSignatureAgentNotOrigin,
		},
		{"a key set at another path", "https://agent.test/jwks.json", helpers.ErrSignatureAgentNotKeyDirectory},
		{"the well-known URL with a query", wellKnown + "?v=1", helpers.ErrSignatureAgentNotKeyDirectory},
		{"the well-known URL with a fragment", wellKnown + "#k", helpers.ErrSignatureAgentNotKeyDirectory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(srv.Close)
			sig := newSigningFixture(t)
			client := foraconnect.NewCatalogClient(srv.URL,
				foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent(tc.value))

			_, err := client.PushResources(context.Background(), validPush())
			_ = requireMalformed(t, err)
			if !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want it to wrap %v", err, tc.want)
			}
			if n := hits.Load(); n != 0 {
				t.Errorf("the server received %d request(s)", n)
			}
		})
	}
}
