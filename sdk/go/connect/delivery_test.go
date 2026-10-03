package connect_test

// Delivery verification, through the real client against one in-process Exchange:
// a real Connect ExchangeService handler behind the SDK's server verify face, and
// the Exchange's own WBA key directory publishing the key it signs delivery URLs
// with. The client resolves that key through the SDK's WBA resolver, so every case
// exercises the path a deployment runs.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// deliveringExchange answers a purchase with one item whose retrieval URL is
// produced by url — the knob each case turns.
type deliveringExchange struct {
	forav1connect.UnimplementedExchangeServiceHandler
	url    func() string
	stated string
}

func (d *deliveringExchange) ExecuteTransaction(
	context.Context, *connectrpc.Request[forav1.TransactionRequest],
) (*connectrpc.Response[forav1.TransactionResponse], error) {
	endpoint := d.url()
	return connectrpc.NewResponse(&forav1.TransactionResponse{
		Ver:               helpers.ProtocolVersion,
		AgentIdentityHash: d.stated,
		Items: []*forav1.TransactionResultItem{
			{OfferId: "offer-1", TransactionId: "tx-1", RetrievalEndpoint: &endpoint},
			// A denied item carries no URL and gets the zero Delivery.
			{OfferId: "offer-2", DenialReason: forav1.DenialReason_DENIAL_REASON_RATE_LIMITED.Enum()},
		},
	}), nil
}

// deliveryFixture is the Exchange, its URL-signing key and the agent buying from it.
type deliveryFixture struct {
	sig      signingFixture
	exchange string // the bare domain, which is the Exchange's identity
	origin   *deliveringExchange
	key      ed25519.PrivateKey
	keyID    string
	content  *httptest.Server
	fetches  *atomic.Int64
}

func newDeliveryFixture(t *testing.T) *deliveryFixture {
	t.Helper()
	sig := newSigningFixture(t)
	key, keyID, err := helpers.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	f := &deliveryFixture{sig: sig, key: key, keyID: keyID, origin: &deliveringExchange{stated: sig.keyID}, fetches: &atomic.Int64{}}
	doc, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(
		helpers.DirectoryDocument([]ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, 0, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	path, h := foraserver.NewExchangeServiceHandler(f.origin, foraserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	mux.HandleFunc("/.well-known/http-message-signatures-directory", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(doc)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f.exchange = strings.TrimPrefix(srv.URL, "http://")
	f.content = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.fetches.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("licensed bytes"))
	}))
	t.Cleanup(f.content.Close)
	f.origin.url = func() string { return f.sign(t, f.key, f.keyID, sig.keyID, time.Hour) }
	return f
}

// sign issues a delivery URL for the content server.
func (f *deliveryFixture) sign(t *testing.T, key ed25519.PrivateKey, keyID, agent string, ttl time.Duration) string {
	t.Helper()
	signed, err := helpers.SignURLEd25519(key, keyID, f.content.URL+"/doc", agent, time.Now().Add(ttl))
	if err != nil {
		t.Fatal(err)
	}
	return signed.URL
}

func (f *deliveryFixture) client(t *testing.T, extra ...foraconnect.ClientOption) *foraconnect.Client {
	t.Helper()
	opts := append(allowLoopback(t),
		foraconnect.WithSigner(f.sig.signer),
		foraconnect.WithAgentKey(f.sig.pub),
		foraconnect.WithRequester(testRequester()),
		foraconnect.WithDeliveryKeyResolver(resolvers.NewWBAKeyResolver(
			resolvers.WBAKeyResolverOptions{Scheme: "http", HTTP: http.DefaultClient})),
	)
	return foraconnect.NewClient("http://"+f.exchange, append(opts, extra...)...)
}

func (f *deliveryFixture) offers(t *testing.T) []core.VerifiedOffer {
	t.Helper()
	return []core.VerifiedOffer{
		signedOfferAt(t, "offer-1", f.exchange, "USD"),
		signedOfferAt(t, "offer-2", f.exchange, "USD"),
	}
}

// A URL that verifies is handed back with its verified binding, and a fetch that
// names the Exchange carries the same binding on its Content.
func TestExecute_VerifiesTheDeliveryURL(t *testing.T) {
	f := newDeliveryFixture(t)
	client := f.client(t)
	var deliveries []foraconnect.Delivery
	resp, err := client.ExecuteBatch(context.Background(), f.offers(t), foraconnect.WithDeliveries(&deliveries))
	if err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("deliveries = %v, want one per item", deliveries)
	}
	got := deliveries[0]
	if got.URL != resp.GetItems()[0].GetRetrievalEndpoint() || got.Exchange != f.exchange ||
		got.AgentID != f.sig.keyID || got.KeyID != f.keyID || !got.Expiry.After(time.Now()) {
		t.Errorf("delivery = %+v", got)
	}
	if deliveries[1] != (foraconnect.Delivery{}) {
		t.Errorf("the denied item's delivery = %+v, want the zero value", deliveries[1])
	}

	content, err := client.Fetch(context.Background(), got.URL, foraconnect.WithDeliveryExchange(got.Exchange))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if content.Binding == nil || content.Binding.AgentID != f.sig.keyID {
		t.Errorf("binding = %+v, want the verified one", content.Binding)
	}
	plain, err := client.Fetch(context.Background(), got.URL)
	if err != nil || plain.Binding != nil {
		t.Errorf("a fetch naming no Exchange = %+v, %v; want the URL fetched as given", plain.Binding, err)
	}
}

// Every way a delivery URL can fail to verify refuses the purchase answer with the
// retrieval-auth reason an edge would give the same URL.
func TestExecute_RefusesADeliveryURLThatDoesNotVerify(t *testing.T) {
	_, foreign, _ := ed25519.GenerateKey(nil)
	cases := []struct {
		name string
		url  func(f *deliveryFixture, t *testing.T) string
		want forav1.RetrievalAuthFailureReason
	}{
		{"signature by another key", func(f *deliveryFixture, t *testing.T) string {
			return f.sign(t, foreign, f.keyID, f.sig.keyID, time.Hour)
		}, forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH},
		{"bound to another agent", func(f *deliveryFixture, t *testing.T) string {
			return f.sign(t, f.key, f.keyID, "someone-else", time.Hour)
		}, forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH},
		{"bearer URL where the answer states a binding", func(f *deliveryFixture, t *testing.T) string {
			return f.sign(t, f.key, f.keyID, "", time.Hour)
		}, forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH},
		{"expired", func(f *deliveryFixture, t *testing.T) string {
			return f.sign(t, f.key, f.keyID, f.sig.keyID, -time.Minute)
		}, forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED},
		{"unsigned", func(f *deliveryFixture, _ *testing.T) string {
			return f.content.URL + "/doc?exp=9999999999&kid=" + f.keyID
		}, forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDeliveryFixture(t)
			f.origin.url = func() string { return c.url(f, t) }
			_, err := f.client(t).ExecuteBatch(context.Background(), f.offers(t))
			assertDeliveryRefusal(t, err, c.want)

			// The same URL is refused by a fetch that names the Exchange, before
			// anything is sent. A bearer URL is the exception: a fetch has no answer
			// stating a binding, and the protocol lets an Exchange issue one.
			if c.name == "bearer URL where the answer states a binding" {
				return
			}
			_, err = f.client(t).Fetch(context.Background(), c.url(f, t), foraconnect.WithDeliveryExchange(f.exchange))
			assertDeliveryRefusal(t, err, c.want)
			if n := f.fetches.Load(); n != 0 {
				t.Errorf("the edge was reached %d time(s) for a URL that does not verify", n)
			}
		})
	}
}

func assertDeliveryRefusal(t *testing.T, err error, want forav1.RetrievalAuthFailureReason) {
	t.Helper()
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallMalformed {
		t.Fatalf("error = %v, want CallMalformed", err)
	}
	detail, ok := foraconnect.ErrorDetailFrom(err)
	if !ok || detail.GetRetrievalAuthFailure().GetReason() != want {
		t.Fatalf("detail = %v, want %v", detail, want)
	}
	if detail.GetDomain() != "fora.v1.Client" {
		t.Errorf("domain = %q, want the client's own tier", detail.GetDomain())
	}
}

// WithDeliveryVerification(core.Off) is the named opt-out for a URL in another
// signing scheme.
func TestExecute_DeliveryVerificationOff(t *testing.T) {
	f := newDeliveryFixture(t)
	f.origin.url = func() string { return f.content.URL + "/doc?Signature=rsa&Key-Pair-Id=K" }
	_, err := f.client(t, foraconnect.WithDeliveryVerification(core.Off)).ExecuteBatch(context.Background(), f.offers(t))
	if err != nil {
		t.Fatalf("ExecuteBatch with verification off: %v", err)
	}
}

// A relayed purchase verifies each URL against the Exchange that issued its offer
// and the binding that Exchange's outcome states.
func TestBrokerExecute_VerifiesEachExchangesDeliveryURL(t *testing.T) {
	f := newDeliveryFixture(t)
	good := f.sign(t, f.key, f.keyID, f.sig.keyID, time.Hour)
	bad := f.sign(t, f.key, f.keyID, "someone-else", time.Hour)
	answer := func(endpoint string) *forav1.BrokerTransactionResponse {
		return &forav1.BrokerTransactionResponse{
			Ver:       helpers.ProtocolVersion,
			Items:     []*forav1.TransactionResultItem{{OfferId: "offer-1", TransactionId: "tx-1", RetrievalEndpoint: &endpoint}},
			Exchanges: []*forav1.ExchangeOutcome{{Exchange: f.exchange, OfferIds: []string{"offer-1"}, AgentIdentityHash: f.sig.keyID}},
		}
	}
	keys := foraconnect.WithDeliveryKeyResolver(resolvers.NewWBAKeyResolver(
		resolvers.WBAKeyResolverOptions{Scheme: "http", HTTP: http.DefaultClient}))
	offers := []core.VerifiedOffer{signedOfferAt(t, "offer-1", f.exchange, "USD")}

	srv := serveBroker(t, f.sig, &relayBroker{answer: answer(good)})
	var deliveries []foraconnect.Delivery
	if _, err := brokerClient(srv.URL, f.sig, keys).Execute(context.Background(), offers,
		foraconnect.WithDeliveries(&deliveries)); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(deliveries) != 1 || deliveries[0].Exchange != f.exchange || deliveries[0].AgentID != f.sig.keyID {
		t.Errorf("deliveries = %+v", deliveries)
	}

	srv = serveBroker(t, f.sig, &relayBroker{answer: answer(bad)})
	_, err := brokerClient(srv.URL, f.sig, keys).Execute(context.Background(), offers)
	assertDeliveryRefusal(t, err, forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH)
}
