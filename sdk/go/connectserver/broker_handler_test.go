package connectserver_test

// Tests for the server verify face's context population (verifyMiddleware
// exposes the proven signatures via helpers.AllSignaturesFromContext) and the
// BrokerService handler constructor (NewBrokerServiceHandler mirrors the
// Exchange handler's request-id · verify · interceptors stack).

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// ---------------------------------------------------------------------------
// Test doubles for connectserver context-population and broker handler tests.
// ---------------------------------------------------------------------------

// contextCapturingExchange wraps an echo exchange and records the
// AllSignaturesFromContext value seen on each call to DiscoverResources.
type contextCapturingExchange struct {
	forav1connect.UnimplementedExchangeServiceHandler
	mu   sync.Mutex
	sigs []helpers.VerifiedRequest // last captured from AllSignaturesFromContext
}

func (e *contextCapturingExchange) DiscoverResources(
	ctx context.Context, _ *connectrpc.Request[forav1.ResourceQuery],
) (*connectrpc.Response[forav1.ResourceResponse], error) {
	captured := helpers.AllSignaturesFromContext(ctx)
	e.mu.Lock()
	e.sigs = captured
	e.mu.Unlock()
	return connectrpc.NewResponse(&forav1.ResourceResponse{}), nil
}

func (e *contextCapturingExchange) capturedSigs() []helpers.VerifiedRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.sigs
}

// brokerEcho is a minimal BrokerServiceHandler echo for the broker handler test.
type brokerEcho struct {
	forav1connect.UnimplementedBrokerServiceHandler
	mu   sync.Mutex
	hits int
}

func (b *brokerEcho) Resolve(
	ctx context.Context, _ *connectrpc.Request[forav1.DiscoveryRequest],
) (*connectrpc.Response[forav1.DiscoveryResponse], error) {
	// Like a real platform handler: no verified signature in context → typed
	// Unauthenticated BEFORE any side effect (hits counts business effects only).
	if helpers.FromContext(ctx) == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	b.mu.Lock()
	b.hits++
	b.mu.Unlock()
	return connectrpc.NewResponse(&forav1.DiscoveryResponse{}), nil
}

func (b *brokerEcho) hitCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.hits
}

// ---------------------------------------------------------------------------
// 1c-a. Context-population test (ASSERTION-LEVEL red on HEAD).
// ---------------------------------------------------------------------------

// TestServerVerify_ContextPopulated pins that after a successful verify the SDK
// populates the request context with the verified signatures so that
// helpers.AllSignaturesFromContext returns a non-empty slice inside the origin
// handler. Specifically:
//   - len(sigs) == 1 (single-sig request)
//   - sigs[0].KeyID matches the signing key's ID
//
// RED reason (assertion): verifyMiddleware (connectserver/verify.go) calls
// cfg.verify(r, body) which returns only an error, never the []VerifiedRequest
// slice needed for r.WithContext(helpers.NewMultisigContext(...)). On HEAD,
// helpers.AllSignaturesFromContext inside the handler returns nil, so
// len(captured) == 0 and the assertion fails.
//
// After Gap 3 fix: cfg.verify returns ([]VerifiedRequest, error); verifyMiddleware
// calls r.WithContext(helpers.NewMultisigContext(r.Context(), sigs)); the handler
// sees a non-nil slice; the test PASSES.
func TestServerVerify_ContextPopulated(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "agent.ctx.v1"
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub})

	origin := &contextCapturingExchange{}
	path, h := foraserver.NewExchangeServiceHandler(
		origin,
		foraserver.WithKeyResolver(resolver),
		foraserver.WithReplayStore(newCountingReplayStore()),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	client := foraconnect.NewClient(srv.URL, foraconnect.WithSigner(signer))
	if _, err := client.Discover(context.Background(), &forav1.ResourceQuery{}); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	captured := origin.capturedSigs()
	// On HEAD: captured is nil (context never populated) → len == 0 → FAIL.
	if len(captured) != 1 {
		t.Fatalf("AllSignaturesFromContext: got %d sigs; want 1 (verifyMiddleware must populate context)", len(captured))
	}
	if captured[0].KeyID != keyID {
		t.Errorf("sigs[0].KeyID = %q; want %q", captured[0].KeyID, keyID)
	}
}

// ---------------------------------------------------------------------------
// 1c-b. Broker handler test (COMPILE-LEVEL red on HEAD).
// ---------------------------------------------------------------------------

// TestServerVerify_BrokerHandlerRejectsUnsigned pins that NewBrokerServiceHandler
// exists in the SDK and enforces the same fail-closed verification as the
// Exchange handler. An unsigned request to the Broker's Resolve RPC must be
// rejected with CodeUnauthenticated, and the origin handler must NOT run.
//
// COMPILE-RED reason: foraserver.NewBrokerServiceHandler is undefined on HEAD.
// The compile error is the TDD red for Gap 4.
//
// After Gap 4 fix: NewBrokerServiceHandler exists; this test compiles, runs, and
// PASSES because the broker handler shares the same verifyMiddleware stack as the
// Exchange handler.
func TestServerVerify_BrokerHandlerRejectsUnsigned(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const keyID = "agent.broker.v1"
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{keyID: pub})

	origin := &brokerEcho{}

	// COMPILE ERROR on HEAD: foraserver.NewBrokerServiceHandler undefined.
	path, h := foraserver.NewBrokerServiceHandler(
		origin,
		foraserver.WithKeyResolver(resolver),
		foraserver.WithReplayStore(alwaysReplayStore{}),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Send an UNSIGNED request directly via an unadorned HTTP client (no signing
	// transport). The seam passes an unsigned request through (typed-fault
	// contract); the ORIGIN rejects it with CodeUnauthenticated before acting, so
	// its business side effects (hits) stay absent.
	brokerClient := forav1connect.NewBrokerServiceClient(&http.Client{}, srv.URL)
	_, err = brokerClient.Resolve(context.Background(), connectrpc.NewRequest(&forav1.DiscoveryRequest{}))
	if err == nil {
		t.Fatal("unsigned request must be rejected by broker server face")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Fatalf("unsigned request: want CodeUnauthenticated, got %v (err=%v)", got, err)
	}
	if origin.hitCount() != 0 {
		t.Fatalf("origin Resolve must NOT run on a rejected unsigned request; ran %d times", origin.hitCount())
	}
}
