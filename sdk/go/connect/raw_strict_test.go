package connect_test

// Raw mode and strict decoding, through the real client against real Connect
// handlers behind the SDK's server verify face.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// bodyRecorder records the request body every call carried, then hands the request
// on unchanged.
type bodyRecorder struct {
	mu     sync.Mutex
	bodies [][]byte
	next   http.Handler
}

func (b *bodyRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	b.mu.Lock()
	b.bodies = append(b.bodies, body)
	b.mu.Unlock()
	r.Body = io.NopCloser(bytes.NewReader(body))
	b.next.ServeHTTP(w, r)
}

func (b *bodyRecorder) last(t *testing.T) []byte {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.bodies) == 0 {
		t.Fatal("the server received no request")
	}
	return b.bodies[len(b.bodies)-1]
}

// withUnknown appends an unknown varint field to a binary message.
func withUnknown(b []byte) []byte {
	b = protowire.AppendTag(b, 99, protowire.VarintType)
	return protowire.AppendVarint(b, 7)
}

// Raw mode puts the caller's bytes on the wire exactly: no ver, no recipient check,
// an unknown field kept. The call is still signed — the verify face admitted it —
// and the answer is still decoded.
func TestRawBody_SendsTheBodyUnchanged(t *testing.T) {
	sig := newSigningFixture(t)
	path, h := foraserver.NewCatalogServiceHandler(&strictCatalog{}, foraserver.WithKeyResolver(sig.resolver))
	rec := &bodyRecorder{next: h}
	mux := http.NewServeMux()
	mux.Handle(path, rec)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// No exchange and no ver: both are what the built path refuses or fills in.
	msg, err := proto.Marshal(&forav1.PushResourcesRequest{TenantId: "t", Entries: []*forav1.ResourceEntry{catalogEntry()}})
	if err != nil {
		t.Fatal(err)
	}
	raw := withUnknown(msg)

	client := foraconnect.NewCatalogClient(srv.URL, foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))
	resp, err := client.PushResources(context.Background(), nil, foraconnect.WithRawBody(raw))
	if err != nil {
		t.Fatalf("raw push: %v", err)
	}
	if resp.GetAccepted() != 1 {
		t.Errorf("answer = %v, want it decoded", resp)
	}
	if got := rec.last(t); !bytes.Equal(got, raw) {
		t.Errorf("server received %x, want the raw body %x", got, raw)
	}

	// The built path refuses the same message locally: it names no recipient.
	var built forav1.PushResourcesRequest
	_ = proto.Unmarshal(msg, &built)
	_, err = client.PushResources(context.Background(), &built)
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallNotSent {
		t.Fatalf("built push = %v, want CallNotSent", err)
	}
}

// A raw body on a verb that routes on its request still routes on the body's own
// exchange, and one that names none is refused, since there is nowhere to send it.
func TestRawBody_RoutesOnTheBodysExchange(t *testing.T) {
	sig := newSigningFixture(t)
	origin := &groupExchange{}
	domain, _ := selfAdvertisingExchange(t, sig, origin)
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))...)

	body, _ := proto.Marshal(&forav1.UsageReport{Exchange: domain, TransactionId: "txn-raw"})
	if _, err := client.ReportUsage(context.Background(), nil, foraconnect.WithRawBody(body)); err != nil {
		t.Fatalf("raw report: %v", err)
	}
	if got := origin.gotReport; got.GetTransactionId() != "txn-raw" || got.GetVer() != "" || got.GetIdempotencyKey() != "" {
		t.Errorf("origin received %v, want the body as sent, nothing stamped", got)
	}

	nowhere, _ := proto.Marshal(&forav1.UsageReport{TransactionId: "txn-raw"})
	_, err := client.ReportUsage(context.Background(), nil, foraconnect.WithRawBody(nowhere))
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallNotSent {
		t.Fatalf("error = %v, want CallNotSent", err)
	}
}

// unknownCatalog answers a push carrying a field this SDK does not define.
type unknownCatalog struct {
	forav1connect.UnimplementedCatalogServiceHandler
}

func (unknownCatalog) PushResources(
	context.Context, *connectrpc.Request[forav1.PushResourcesRequest],
) (*connectrpc.Response[forav1.PushResourcesResponse], error) {
	resp := &forav1.PushResourcesResponse{Ver: helpers.ProtocolVersion, Accepted: 1}
	resp.ProtoReflect().SetUnknown(withUnknown(nil))
	return connectrpc.NewResponse(resp), nil
}

// Strict decoding refuses an answer carrying an unknown field, which the default
// decode keeps quietly.
func TestStrictDecoding_RefusesAnUnknownField(t *testing.T) {
	sig := newSigningFixture(t)
	srv := serveCatalog(t, sig, unknownCatalog{})

	lenient := foraconnect.NewCatalogClient(srv.URL, foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))
	if _, err := lenient.PushResources(context.Background(), validPush()); err != nil {
		t.Fatalf("default decode refused the answer: %v", err)
	}
	strict := foraconnect.NewCatalogClient(srv.URL,
		foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"), foraconnect.WithStrictDecoding())
	_, err := strict.PushResources(context.Background(), validPush())
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallMalformed {
		t.Fatalf("error = %v, want CallMalformed", err)
	}
	if cerr.Code != 0 {
		t.Errorf("code = %v; the peer answered OK and reached no error verdict", cerr.Code)
	}
}

// statusAccount answers an account status breaking a cross-field rule: a terms
// digest with no account handle to hang it on.
type statusAccount struct {
	forav1connect.UnimplementedExchangeServiceHandler
}

func (statusAccount) GetAccountStatus(
	context.Context, *connectrpc.Request[forav1.GetAccountStatusRequest],
) (*connectrpc.Response[forav1.GetAccountStatusResponse], error) {
	// A well-formed digest, so the cross-field rule is the only one broken.
	digest := "sha256:" + strings.Repeat("0", 64)
	return connectrpc.NewResponse(&forav1.GetAccountStatusResponse{
		Ver: helpers.ProtocolVersion, TermsDigest: &digest,
	}), nil
}

// Strict decoding applies the proto's cross-field rules to the answer.
func TestStrictDecoding_RefusesACrossFieldViolation(t *testing.T) {
	sig := newSigningFixture(t)
	domain, _ := selfAdvertisingExchange(t, sig, statusAccount{})
	req := &forav1.GetAccountStatusRequest{Exchange: domain}

	lenient := foraconnect.NewClient("http://home.invalid", append(allowLoopback(t), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))...)
	if _, err := lenient.GetAccountStatus(context.Background(), req); err != nil {
		t.Fatalf("default decode refused the answer: %v", err)
	}
	strict := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"), foraconnect.WithStrictDecoding())...)
	_, err := strict.GetAccountStatus(context.Background(), req)
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallMalformed {
		t.Fatalf("error = %v, want CallMalformed", err)
	}
	if !strings.Contains(err.Error(), "billing_ref") {
		t.Errorf("error = %v, want the cross-field rule named", err)
	}
}

// A peer that never answered has no Connect code, whatever connect-go synthesized
// for the dial failure.
func TestCallErrorCode_NoAnswerCarriesNoCode(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, err := foraconnect.NewClient(url).Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallUnreachable {
		t.Fatalf("error = %v, want CallUnreachable", err)
	}
	if cerr.Code != 0 {
		t.Errorf("code = %v for a peer that never answered, want none", cerr.Code)
	}
}
