package connect_test

// The pre-signing hook, driven through the real client against a real Connect
// CatalogService handler running the SDK's own server verify face. The verify face
// is what proves the signature covers the PATCHED bytes: a hook whose changes were
// signed before they were made would be refused as unauthenticated, never reach the
// application, and never earn its typed refusal.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// strictCatalog refuses a push carrying no entries with a typed catalog rejection,
// the refusal a malformed push earns at an Exchange.
type strictCatalog struct {
	forav1connect.UnimplementedCatalogServiceHandler
	hits int
}

func (c *strictCatalog) PushResources(
	ctx context.Context, req *connectrpc.Request[forav1.PushResourcesRequest],
) (*connectrpc.Response[forav1.PushResourcesResponse], error) {
	c.hits++
	if helpers.FromContext(ctx) == nil {
		return nil, connectrpc.NewError(connectrpc.CodeUnauthenticated, errors.New("origin: unverified caller"))
	}
	if len(req.Msg.GetEntries()) == 0 {
		return nil, foraserver.AttachDetail(
			connectrpc.NewError(connectrpc.CodeInvalidArgument, errors.New("no entries")),
			helpers.CatalogRejectionDetail("fora.v1.CatalogService", "a push carries at least one entry",
				forav1.CatalogRejectionReason_CATALOG_REJECTION_REASON_MALFORMED_ENTRY))
	}
	return connectrpc.NewResponse(&forav1.PushResourcesResponse{
		Ver: helpers.ProtocolVersion, Accepted: int32(len(req.Msg.GetEntries())),
	}), nil
}

func validPush() *forav1.PushResourcesRequest {
	return &forav1.PushResourcesRequest{
		Exchange: "exchange.test", TenantId: "tenant-1",
		Entries: []*forav1.ResourceEntry{catalogEntry()},
	}
}

// dropEntries is a hook that removes every entry from the push it is handed.
func dropEntries(req *http.Request) (*http.Request, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	var push forav1.PushResourcesRequest
	if err := proto.Unmarshal(body, &push); err != nil {
		return nil, err
	}
	push.Entries = nil
	patched, err := proto.Marshal(&push)
	if err != nil {
		return nil, err
	}
	out := req.Clone(req.Context())
	out.Body = io.NopCloser(bytes.NewReader(patched))
	return out, nil
}

// A valid request patched into a malformed one comes back as the server's typed
// refusal, read through CallError: the Connect code, and the ErrorDetail.
func TestBeforeSign_APatchedRequestEarnsATypedRefusal(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &strictCatalog{}
	srv := serveCatalog(t, sig, origin)
	client := foraconnect.NewCatalogClient(srv.URL,
		foraconnect.WithSigner(sig.signer), foraconnect.WithBeforeSign(dropEntries))

	_, err := client.PushResources(context.Background(), validPush())
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("error = %v, want a CallError", err)
	}
	if cerr.Kind != foraconnect.CallRefused || cerr.Code != connectrpc.CodeInvalidArgument {
		t.Fatalf("kind = %v, code = %v; want the peer's invalid_argument refusal", cerr.Kind, cerr.Code)
	}
	detail, ok := foraconnect.ErrorDetailFrom(err)
	if !ok || detail.GetCatalogRejection().GetReason() !=
		forav1.CatalogRejectionReason_CATALOG_REJECTION_REASON_MALFORMED_ENTRY {
		t.Fatalf("typed reason = %v, want MALFORMED_ENTRY", detail)
	}
	// Without the hook the same request is accepted, so the refusal is the patch's.
	plain := foraconnect.NewCatalogClient(srv.URL, foraconnect.WithSigner(sig.signer))
	if _, err := plain.PushResources(context.Background(), validPush()); err != nil {
		t.Fatalf("the unpatched push was refused: %v", err)
	}
}

// The hook's refusals are local: nothing reaches the server.
func TestBeforeSign_RefusesWithoutSending(t *testing.T) {
	cases := map[string]foraconnect.BeforeSign{
		"hook error":  func(*http.Request) (*http.Request, error) { return nil, errors.New("boom") },
		"nil request": func(*http.Request) (*http.Request, error) { return nil, nil },
		"changed URL": func(r *http.Request) (*http.Request, error) {
			out := r.Clone(r.Context())
			out.URL.Path = "/fora.v1.CatalogService/RemoveResources"
			return out, nil
		},
		"changed method": func(r *http.Request) (*http.Request, error) {
			out := r.Clone(r.Context())
			out.Method = http.MethodPut
			return out, nil
		},
		"signer header": func(r *http.Request) (*http.Request, error) {
			out := r.Clone(r.Context())
			out.Header.Set("signature-agent", "https://elsewhere.test")
			return out, nil
		},
	}
	for name, hook := range cases {
		t.Run(name, func(t *testing.T) {
			sig := newSigningFixture(t)
			origin := &strictCatalog{}
			srv := serveCatalog(t, sig, origin)
			client := foraconnect.NewCatalogClient(srv.URL,
				foraconnect.WithSigner(sig.signer), foraconnect.WithBeforeSign(hook))
			_, err := client.PushResources(context.Background(), validPush())
			var cerr *foraconnect.CallError
			if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallMalformed {
				t.Fatalf("error = %v, want CallMalformed", err)
			}
			if cerr.Code != 0 {
				t.Errorf("code = %v on a local refusal, want none", cerr.Code)
			}
			if origin.hits != 0 {
				t.Errorf("the server was reached %d time(s)", origin.hits)
			}
		})
	}
}

// A hook that leaves the request alone sends what the SDK built, Content-Length a
// hook might set stale included.
func TestBeforeSign_AnUnchangedRequestIsAccepted(t *testing.T) {
	sig := newSigningFixture(t)
	srv := serveCatalog(t, sig, &strictCatalog{})
	client := foraconnect.NewCatalogClient(srv.URL, foraconnect.WithSigner(sig.signer),
		foraconnect.WithBeforeSign(func(r *http.Request) (*http.Request, error) {
			r.Header.Set("Content-Length", "1")
			return r, nil
		}))
	resp, err := client.PushResources(context.Background(), validPush())
	if err != nil || resp.GetAccepted() != 1 {
		t.Fatalf("push = %v, %v", resp, err)
	}
}
