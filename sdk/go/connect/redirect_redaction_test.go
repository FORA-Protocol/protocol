package connect_test

// A refused redirect never names its target in an RPC error. Every RPC leg refuses
// to follow a 3xx, and the refusal's own message redacts the target to its scheme,
// host and path. net/http wraps that refusal in a *url.Error carrying the raw
// Location the peer sent, credentials included; connect-go discards that wrapper
// before the error reaches this client, which is what keeps the Location out today.
// This pins the result on every face, so a dependency that stopped discarding it
// fails here rather than in a log. The content leg rebuilds the wrapper itself and
// is pinned in the resolvers suite.

import (
	"context"
	"net/http"
	"strings"
	"testing"

	foraadminv1 "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
)

// redirectTarget carries a credential in every part a URL can carry one: userinfo,
// the query and the fragment.
const redirectTarget = "https://user:pw-6c1f0e@elsewhere.test/next?token=s3cret-6c1f0e#frag-6c1f0e"

var redirectSecrets = []string{"pw-6c1f0e", "s3cret-6c1f0e", "frag-6c1f0e"}

// assertRedirectRedacted fails unless err is the refusal of a redirect whose message
// names no secret of the target, while still naming where it pointed.
func assertRedirectRedacted(t *testing.T, err error) {
	t.Helper()
	cerr := callErrorFrom(t, err)
	if cerr.Kind != foraconnect.CallUnreachable {
		t.Errorf("Kind = %v, want CallUnreachable: %v", cerr.Kind, cerr)
	}
	msg := cerr.Error()
	for _, secret := range redirectSecrets {
		if strings.Contains(msg, secret) {
			t.Errorf("the message names %q from the redirect target: %s", secret, msg)
		}
	}
	if !strings.Contains(msg, "elsewhere.test/next") {
		t.Errorf("the message no longer says where the redirect pointed: %s", msg)
	}
}

func TestARefusedRedirectNeverNamesItsTarget(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	faces := []struct {
		name string
		call func(baseURL string) error
	}{
		{"discover", func(baseURL string) error {
			_, err := foraconnect.NewClient(baseURL).Discover(ctx, &forav1.ResourceQuery{Exchange: "exchange.test"})
			return err
		}},
		{"a raw body", func(baseURL string) error {
			_, err := foraconnect.NewClient(baseURL).Discover(ctx, nil, foraconnect.WithRawBody([]byte{}))
			return err
		}},
		{"the Broker", func(baseURL string) error {
			_, err := foraconnect.NewBrokerClient(baseURL, foraconnect.WithRequester(testRequester())).
				Resolve(ctx, &forav1.DiscoveryRequest{})
			return err
		}},
		{"the catalog", func(baseURL string) error {
			_, err := foraconnect.NewCatalogClient(baseURL).
				PushResources(ctx, &forav1.PushResourcesRequest{Exchange: "exchange.test"})
			return err
		}},
		{"the operator plane", func(baseURL string) error {
			_, err := foraconnect.NewAdminClient(baseURL).SetTenantFeeRate(ctx, &foraadminv1.SetTenantFeeRateRequest{})
			return err
		}},
	}
	for _, face := range faces {
		t.Run(face.name, func(t *testing.T) {
			t.Parallel()
			srv := refusalAnswer(t, http.StatusFound, "text/plain", "", fieldLine{"Location", redirectTarget})
			assertRedirectRedacted(t, face.call(srv.URL))
		})
	}
}

// TestTheOfferDerivedLegNeverNamesARedirectsTarget covers the leg whose host
// another party chose. Not parallel: the loopback posture is set in the environment.
func TestTheOfferDerivedLegNeverNamesARedirectsTarget(t *testing.T) {
	sig := newSigningFixture(t)
	domain, _ := loopbackManifestServer(t,
		refusalHandler(http.StatusFound, "text/plain", "", fieldLine{"Location", redirectTarget}))
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))...)
	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
		Usage:         &forav1.Usage{Function: []string{"ai-input"}},
	})
	assertRedirectRedacted(t, err)
}
