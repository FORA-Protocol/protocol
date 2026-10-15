package connect_test

// BrokerClient.Execute and Client.ExecuteBatch, driven through the outermost
// public surface: an SDK-built client over real HTTP to a real Connect
// BrokerService / ExchangeService handler running the SDK's own server verify
// face. The Broker origin is the application service the SDK wraps: it records
// the request it received and answers with a combined response, which is what a
// relaying Broker hands back. What the client owns — building and signing the
// request, the local refusals, decoding the answer — is what these tests assert.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// agentDirectory is the WBA directory the test agent signs as; testRequester's
// domain is its host, which is what a Broker requires.
const agentDirectory = "https://agent.test"

// relayBroker records the purchase it received and answers with a canned
// combined response, or with a refusal of its own.
type relayBroker struct {
	forav1connect.UnimplementedBrokerServiceHandler
	answer  *forav1.BrokerTransactionResponse
	refusal error

	mu   sync.Mutex
	got  *forav1.TransactionRequest
	hits atomic.Int64
}

func (b *relayBroker) ExecuteTransaction(
	ctx context.Context, req *connectrpc.Request[forav1.TransactionRequest],
) (*connectrpc.Response[forav1.BrokerTransactionResponse], error) {
	b.hits.Add(1)
	if err := requireVerified(ctx); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.got = req.Msg
	b.mu.Unlock()
	if b.refusal != nil {
		return nil, b.refusal
	}
	return connectrpc.NewResponse(b.answer), nil
}

func (b *relayBroker) received() *forav1.TransactionRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.got
}

func serveBroker(t *testing.T, sig signingFixture, svc forav1connect.BrokerServiceHandler) *httptest.Server {
	t.Helper()
	path, h := foraserver.NewBrokerServiceHandler(svc, foraserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// signedOfferAt mints an offer issued by exchange, priced in currency, signed by
// that Exchange's key, and hands it over as a VerifiedOffer the way a verifier
// that resolved that key would.
func signedOfferAt(t *testing.T, id, exchange, currency string) core.VerifiedOffer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	offer := sampleOffer(id)
	offer.Exchange = exchange
	offer.Pricing = &forav1.Pricing{Rate: "1.25", Currency: currency}
	sigHex, err := helpers.SignOffer(priv, offer)
	if err != nil {
		t.Fatal(err)
	}
	offer.Signature = sigHex
	offer.SignatureAlgorithm = helpers.OfferSignatureAlgorithm
	return core.RejectedOffer{Offer: offer}.Unsafe()
}

func brokerClient(srvURL string, sig signingFixture, extra ...foraconnect.ClientOption) *foraconnect.BrokerClient {
	opts := append([]foraconnect.ClientOption{
		foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"),
		foraconnect.WithSignatureAgent(agentDirectory),
		foraconnect.WithRequester(testRequester()),
	}, extra...)
	return foraconnect.NewBrokerClient(srvURL, opts...)
}

// A purchase across two Exchanges is one request whose every item carries a
// verifying acceptance, and whose request acceptance verifies as the complete
// in-order projection for EACH Exchange the Broker will relay to. The answer —
// one Exchange refused its whole sub-request, the other sold in two currencies —
// decodes with the refusal on the affected item and the totals kept apart.
func TestBrokerExecute_RelaysAMixedBatchAndDecodesTheCombinedAnswer(t *testing.T) {
	sig := newSigningFixture(t)
	offers := []core.VerifiedOffer{
		signedOfferAt(t, "offer-a1", "exchange-a.test", "USD"),
		signedOfferAt(t, "offer-b1", "exchange-b.test", "USD"),
		signedOfferAt(t, "offer-a2", "exchange-a.test", "EUR"),
	}
	refusal := &forav1.UpstreamRefusal{
		Party: "exchange-b.test",
		Code:  "permission_denied",
		Detail: helpers.TransactionDenialDetail("fora.v1.ExchangeService", "no account",
			forav1.DenialReason_DENIAL_REASON_ACCOUNT_NOT_REGISTERED),
	}
	origin := &relayBroker{answer: &forav1.BrokerTransactionResponse{
		Ver: helpers.ProtocolVersion,
		Items: []*forav1.TransactionResultItem{
			{OfferId: "offer-a1", TransactionId: "tx-a1", Cost: &forav1.Cost{Amount: "1.25", Currency: "USD"}},
			{OfferId: "offer-b1", Refusal: refusal},
			{OfferId: "offer-a2", TransactionId: "tx-a2", Cost: &forav1.Cost{Amount: "1.25", Currency: "EUR"}},
		},
		Exchanges: []*forav1.ExchangeOutcome{
			{Exchange: "exchange-a.test", OfferIds: []string{"offer-a1", "offer-a2"}, AgentIdentityHash: sig.keyID},
			{Exchange: "exchange-b.test", OfferIds: []string{"offer-b1"}},
		},
		Totals: []*forav1.Cost{{Amount: "1.25", Currency: "USD"}, {Amount: "1.25", Currency: "EUR"}},
	}}
	srv := serveBroker(t, sig, origin)

	resp, err := brokerClient(srv.URL, sig).Execute(context.Background(), offers,
		foraconnect.WithIdempotencyKey("relay-key"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	got := origin.received()
	if got.GetVer() != helpers.ProtocolVersion || got.GetIdempotencyKey() != "relay-key" {
		t.Errorf("envelope ver=%q key=%q", got.GetVer(), got.GetIdempotencyKey())
	}
	if !proto.Equal(got.GetRequester(), testRequester()) {
		t.Errorf("requester = %+v, want the configured identity", got.GetRequester())
	}
	if len(got.GetItems()) != len(offers) {
		t.Fatalf("items = %d, want %d", len(got.GetItems()), len(offers))
	}
	for i, item := range got.GetItems() {
		if item.GetOffer().GetOfferId() != offers[i].Offer().GetOfferId() {
			t.Errorf("item %d = %q, want request order", i, item.GetOffer().GetOfferId())
		}
		if err = helpers.VerifyOfferAcceptance(item.GetOffer(), got.GetRequester(),
			got.GetIdempotencyKey(), item.GetAgentAcceptance().GetSignature(), sig.pub); err != nil {
			t.Errorf("item %d acceptance does not verify: %v", i, err)
		}
	}
	for _, exchange := range []string{"exchange-a.test", "exchange-b.test"} {
		projected := projectionFor(got, exchange)
		if _, err = helpers.VerifyRequestAcceptanceProjection(
			projected, got.GetAgentRequestAcceptance(), exchange, sig.pub); err != nil {
			t.Errorf("the sub-request for %s would be refused: %v", exchange, err)
		}
	}

	if r := resp.GetItems()[1].GetRefusal(); r.GetCode() != "permission_denied" ||
		r.GetDetail().GetTransactionDenial().GetReason() != forav1.DenialReason_DENIAL_REASON_ACCOUNT_NOT_REGISTERED {
		t.Errorf("refusal = %+v, want the Exchange's code and typed reason unchanged", r)
	}
	if resp.GetItems()[0].GetTransactionId() != "tx-a1" || resp.GetItems()[2].GetRefusal() != nil {
		t.Errorf("the other Exchange's results must come back unchanged, got %+v", resp.GetItems())
	}
	if len(resp.GetTotals()) != 2 || resp.GetTotals()[0].GetCurrency() != "USD" ||
		resp.GetTotals()[1].GetCurrency() != "EUR" {
		t.Errorf("totals = %+v, want one per currency", resp.GetTotals())
	}
	if len(resp.GetExchanges()) != 2 || resp.GetExchanges()[0].GetAgentIdentityHash() != sig.keyID {
		t.Errorf("exchanges = %+v", resp.GetExchanges())
	}
}

// projectionFor is the sub-request a Broker sends one Exchange: that Exchange's
// items in request order, with the agent's envelope unchanged.
func projectionFor(req *forav1.TransactionRequest, exchange string) *forav1.TransactionRequest {
	sub, _ := proto.Clone(req).(*forav1.TransactionRequest)
	sub.Items = nil
	for _, item := range req.GetItems() {
		if item.GetOffer().GetExchange() == exchange {
			sub.Items = append(sub.Items, item)
		}
	}
	return sub
}

// One offer is the degenerate one-item purchase, built by the same code.
func TestBrokerExecute_SingleOffer(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &relayBroker{answer: &forav1.BrokerTransactionResponse{Ver: helpers.ProtocolVersion}}
	srv := serveBroker(t, sig, origin)

	offer := signedOfferAt(t, "offer-one", "exchange-a.test", "USD")
	if _, err := brokerClient(srv.URL, sig).Execute(context.Background(),
		[]core.VerifiedOffer{offer}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	got := origin.received()
	if len(got.GetItems()) != 1 || got.GetAgentRequestAcceptance() == nil || got.GetIdempotencyKey() == "" {
		t.Errorf("want one signed item, a request acceptance and a minted key, got %+v", got)
	}
}

// Every precondition the Broker would refuse is refused HERE, before anything
// leaves the process — the requester-domain one included.
func TestBrokerExecute_RefusesLocallyWithoutSending(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &relayBroker{answer: &forav1.BrokerTransactionResponse{}}
	srv := serveBroker(t, sig, origin)

	good := []core.VerifiedOffer{signedOfferAt(t, "offer-a", "exchange-a.test", "USD")}
	unaddressed := signedOfferAt(t, "offer-x", "exchange-a.test", "USD")
	unaddressed.Offer().Exchange = ""
	otherDomain := testRequester()
	otherDomain.Domain = "someone-else.test"
	noID := testRequester()
	noID.Id = ""
	noDomain := testRequester()
	noDomain.Domain = ""

	tests := map[string]struct {
		client *foraconnect.BrokerClient
		offers []core.VerifiedOffer
		kind   foraconnect.CallErrorKind
	}{
		"requester domain is not the signing directory": {
			brokerClient(srv.URL, sig, foraconnect.WithRequester(otherDomain)), good, foraconnect.CallMalformed,
		},
		"no signature agent": {
			foraconnect.NewBrokerClient(srv.URL, foraconnect.WithSigner(sig.signer),
				foraconnect.WithRequester(testRequester())), good, foraconnect.CallMalformed,
		},
		"no requester": {
			foraconnect.NewBrokerClient(srv.URL, foraconnect.WithSigner(sig.signer),
				foraconnect.WithSignatureAgent(agentDirectory)), good, foraconnect.CallMalformed,
		},
		"requester with no id": {
			brokerClient(srv.URL, sig, foraconnect.WithRequester(noID)), good, foraconnect.CallMalformed,
		},
		"requester with no domain": {
			brokerClient(srv.URL, sig, foraconnect.WithRequester(noDomain)), good, foraconnect.CallMalformed,
		},
		"no signer": {
			foraconnect.NewBrokerClient(srv.URL, foraconnect.WithSignatureAgent(agentDirectory),
				foraconnect.WithRequester(testRequester())), good, foraconnect.CallNotSignable,
		},
		"no offers": {brokerClient(srv.URL, sig), nil, foraconnect.CallMalformed},
		"offer names no exchange": {
			brokerClient(srv.URL, sig), []core.VerifiedOffer{unaddressed}, foraconnect.CallMalformed,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := tc.client.Execute(context.Background(), tc.offers)
			var cerr *foraconnect.CallError
			if !errors.As(err, &cerr) || cerr.Kind != tc.kind {
				t.Fatalf("error = %v, want a CallError of kind %v", err, tc.kind)
			}
		})
	}
	if n := origin.hits.Load(); n != 0 {
		t.Errorf("the Broker was contacted %d time(s); every refusal must be local", n)
	}
}

// The Broker's OWN refusal is an error carrying its typed reason; nothing was bought.
func TestBrokerExecute_BrokerRefusalIsAnError(t *testing.T) {
	sig := newSigningFixture(t)
	refusal := foraserver.AttachDetail(
		connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("broker: requester mismatch")),
		helpers.RequestAuthFailureDetail("fora.v1.BrokerService", "requester mismatch",
			forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID))
	srv := serveBroker(t, sig, &relayBroker{refusal: refusal})

	_, err := brokerClient(srv.URL, sig).Execute(context.Background(),
		[]core.VerifiedOffer{signedOfferAt(t, "offer-a", "exchange-a.test", "USD")})
	detail, ok := foraconnect.ErrorDetailFrom(err)
	if !ok || detail.GetRequestAuthFailure().GetReason() !=
		forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID {
		t.Fatalf("error = %v, want the Broker's request_auth_failure", err)
	}
}

// ExecuteBatch buys several offers from one Exchange in one request, and refuses
// a set that spans Exchanges before sending — that is what a Broker is for.
func TestExecuteBatch_OneExchangeOnly(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &recordingExecute{}
	srv := serveExchange(t, sig, origin)
	client := foraconnect.NewClient(srv.URL,
		foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"), foraconnect.WithRequester(testRequester()))

	same := []core.VerifiedOffer{
		signedOfferAt(t, "offer-1", "exchange.test", "USD"),
		signedOfferAt(t, "offer-2", "exchange.test", "USD"),
	}
	if _, err := client.ExecuteBatch(context.Background(), same); err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}
	if n := len(origin.req.GetItems()); n != 2 {
		t.Fatalf("items = %d, want 2", n)
	}
	if _, err := helpers.VerifyRequestAcceptanceProjection(
		origin.req, origin.req.GetAgentRequestAcceptance(), "exchange.test", sig.pub); err != nil {
		t.Errorf("request acceptance does not verify: %v", err)
	}

	origin.req = nil
	mixed := []core.VerifiedOffer{same[0], signedOfferAt(t, "offer-3", "exchange-b.test", "USD")}
	_, err := client.ExecuteBatch(context.Background(), mixed)
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallMalformed {
		t.Fatalf("error = %v, want CallMalformed", err)
	}
	if origin.req != nil {
		t.Error("a mixed set must be refused before sending")
	}
}
