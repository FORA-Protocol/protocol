package connect_test

// Delivery URLs are checked by the delivery edge, not by the agent's client. The
// edge verifies the URL signature and, where it can, the agent binding against the
// proof of possession the agent presents; an edge that cannot check the binding
// (CloudFront with its pre-arranged RSA key pair) treats the URL as a bearer token.
// So a purchase returns every URL exactly as the Exchange issued it, even one this
// client could not read, and Fetch dials it as given with the proof attached. By
// the time the answer arrives the Exchange has charged, and refusing it locally
// would lose the purchase answer.

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// cloudFrontURL is a CloudFront RSA signed URL: no kid, no agent_id, and a
// signature no Ed25519 check reads.
const cloudFrontURL = "https://d111111abcdef8.cloudfront.net/content/asset-2" +
	"?Expires=4102444800&Signature=c2lnbmF0dXJl&Key-Pair-Id=K2JCJMDEHXQW5F"

// unverifiableURL is signed by a key no directory publishes, bound to another
// agent, and already expired: an edge would refuse it.
func unverifiableURL(t *testing.T) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := helpers.SignURLEd25519(key, "unknown-key", "https://edge.example/content/asset-1",
		"someone-else", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return signed.URL
}

func deliveredItems(urls ...string) []*forav1.TransactionResultItem {
	items := make([]*forav1.TransactionResultItem, len(urls))
	for i, u := range urls {
		endpoint := u
		items[i] = &forav1.TransactionResultItem{
			OfferId: []string{"offer-1", "offer-2"}[i], TransactionId: "tx", RetrievalEndpoint: &endpoint,
		}
	}
	return items
}

// issuingExchange answers a purchase with the given retrieval URLs.
type issuingExchange struct {
	forav1connect.UnimplementedExchangeServiceHandler
	urls []string
}

func (e *issuingExchange) ExecuteTransaction(
	context.Context, *connectrpc.Request[forav1.TransactionRequest],
) (*connectrpc.Response[forav1.TransactionResponse], error) {
	return connectrpc.NewResponse(&forav1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: "agent-thumbprint",
		Items:             deliveredItems(e.urls...),
	}), nil
}

func endpoints(items []*forav1.TransactionResultItem) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.GetRetrievalEndpoint()
	}
	return out
}

func TestExecute_ReturnsEveryDeliveryURLAsIssued(t *testing.T) {
	sig := newSigningFixture(t)
	want := []string{unverifiableURL(t), cloudFrontURL}
	srv := serveExchange(t, sig, &issuingExchange{urls: want})
	client := foraconnect.NewClient(srv.URL,
		foraconnect.WithSigner(sig.signer), foraconnect.WithRequester(testRequester()))
	offers := []core.VerifiedOffer{
		signedOfferAt(t, "offer-1", "exchange.test", "USD"),
		signedOfferAt(t, "offer-2", "exchange.test", "USD"),
	}

	resp, err := client.ExecuteBatch(context.Background(), offers)
	if err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if got := endpoints(resp.GetItems()); got[0] != want[0] || got[1] != want[1] {
		t.Errorf("retrieval endpoints = %v, want %v", got, want)
	}
}

func TestBrokerExecute_ReturnsEveryDeliveryURLAsIssued(t *testing.T) {
	sig := newSigningFixture(t)
	want := []string{unverifiableURL(t), cloudFrontURL}
	srv := serveBroker(t, sig, &relayBroker{answer: &forav1.BrokerTransactionResponse{
		Ver:   helpers.ProtocolVersion,
		Items: deliveredItems(want...),
		Exchanges: []*forav1.ExchangeOutcome{
			{Exchange: "exchange-a.test", OfferIds: []string{"offer-1"}},
			{Exchange: "exchange-b.test", OfferIds: []string{"offer-2"}},
		},
	}})
	offers := []core.VerifiedOffer{
		signedOfferAt(t, "offer-1", "exchange-a.test", "USD"),
		signedOfferAt(t, "offer-2", "exchange-b.test", "USD"),
	}

	resp, err := brokerClient(srv.URL, sig).Execute(context.Background(), offers)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := endpoints(resp.GetItems()); got[0] != want[0] || got[1] != want[1] {
		t.Errorf("retrieval endpoints = %v, want %v", got, want)
	}
}

// Fetch dials whatever URL it is given, with the agent's proof of possession: the
// edge decides.
func TestFetch_DialsTheURLAsGivenWithTheAgentProof(t *testing.T) {
	sig := newSigningFixture(t)
	var seen *http.Request
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("licensed bytes"))
	}))
	t.Cleanup(edge.Close)
	client := foraconnect.NewClient("http://exchange.test", append(allowLoopback(t),
		foraconnect.WithSigner(sig.signer), foraconnect.WithAgentKey(sig.pub))...)
	target := edge.URL + "/content/asset-2?Expires=4102444800&Signature=c2lnbmF0dXJl&Key-Pair-Id=K2JCJMDEHXQW5F"

	content, err := client.Fetch(context.Background(), target)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(content.Body) != "licensed bytes" {
		t.Errorf("body = %q", content.Body)
	}
	if seen == nil || seen.URL.RequestURI() != "/content/asset-2?Expires=4102444800&Signature=c2lnbmF0dXJl&Key-Pair-Id=K2JCJMDEHXQW5F" {
		t.Fatalf("the edge saw %v, want the URL as given", seen)
	}
	if seen.Header.Get(helpers.AgentKeyHeader) == "" || seen.Header.Get("Signature") == "" {
		t.Error("the fetch carries no proof of possession")
	}
}
