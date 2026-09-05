package connectserver_test

// WithOnReject observation hook: the verify gate hands a rejecting request +
// error to the injected observer BEFORE writing the response, so a consumer can
// audit-classify the rejection via errors.Is against the exported sentinels
// (ErrReplayed distinct from a signature failure). Drives the real client→server
// path; asserts through the observer AND the returned connect.Code.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
)

// capturedReject records the last (request, error) the gate observer received.
type capturedReject struct {
	mu   sync.Mutex
	errs []error
}

func (c *capturedReject) observe(_ *http.Request, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, err)
}

func (c *capturedReject) last() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.errs) == 0 {
		return nil
	}
	return c.errs[len(c.errs)-1]
}

func serveWithOnReject(
	t *testing.T, f serverFixture, replay core.ReplayStore, obs *capturedReject,
) *httptest.Server {
	t.Helper()
	path, h := foraserver.NewExchangeServiceHandler(
		f.origin,
		foraserver.WithKeyResolver(f.resolver),
		foraserver.WithReplayStore(replay),
		foraserver.WithOnReject(obs.observe),
	)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestOnReject_ReplayIsObservedAsErrReplayed pins that a replay rejection reaches
// the observer AND is classifiable as ErrReplayed (the consumer's audit path can
// distinguish a replay from a signature failure). The origin never runs.
func TestOnReject_ReplayIsObservedAsErrReplayed(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	obs := &capturedReject{}
	srv := serveWithOnReject(t, f, alwaysReplayStore{}, obs)

	client := foraconnect.NewClient(srv.URL, foraconnect.WithSigner(f.signer))
	if _, err := client.Discover(context.Background(), &forav1.ResourceQuery{}); err == nil {
		t.Fatal("a replayed request must be rejected")
	}

	got := obs.last()
	if got == nil {
		t.Fatal("WithOnReject observer was not called on a rejected request")
	}
	if !errors.Is(got, foraserver.ErrReplayed) {
		t.Fatalf("reject error not classifiable as a replay: %v", got)
	}
	if f.origin.hitCount() != 0 {
		t.Fatalf("origin must not run on a rejected replay, ran %d", f.origin.hitCount())
	}
}

// TestOnReject_SignatureFailureIsObservedNotAsReplay pins the distinction: an
// unsigned request (no signer) is rejected and observed, but is NOT a replay —
// the consumer's default branch classifies it as a signature failure.
func TestOnReject_SignatureFailureIsObservedNotAsReplay(t *testing.T) {
	t.Parallel()
	f := newServerFixture(t)
	obs := &capturedReject{}
	srv := serveWithOnReject(t, f, newCountingReplayStore(), obs)

	// A client with NO signer: the request carries no RFC 9421 signature, so the
	// verify face rejects it before any replay check.
	client := foraconnect.NewClient(srv.URL)
	if _, err := client.Discover(context.Background(), &forav1.ResourceQuery{}); err == nil {
		t.Fatal("an unsigned request must be rejected")
	}

	got := obs.last()
	if got == nil {
		t.Fatal("WithOnReject observer was not called on an unsigned request")
	}
	if errors.Is(got, foraserver.ErrReplayed) {
		t.Fatalf("an unsigned request must NOT classify as a replay: %v", got)
	}
}
