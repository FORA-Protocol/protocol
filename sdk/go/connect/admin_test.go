package connect_test

// AdminClient against the real generated handlers: AdminService mounted directly
// (the admin plane carries no request signing), and the two domain-verification
// RPCs on an ExchangeService behind the SDK's server verify face, both on one
// origin as the client addresses them.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	foraadminv1 "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1/foraadminv1connect"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// operatorPlane records which RPC it answered and the version each request carried.
type operatorPlane struct {
	foraadminv1connect.UnimplementedAdminServiceHandler
	forav1connect.UnimplementedExchangeServiceHandler
	mu   sync.Mutex
	seen map[string]string // method -> request ver
}

func (o *operatorPlane) record(method, ver string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.seen == nil {
		o.seen = map[string]string{}
	}
	o.seen[method] = ver
}

func (o *operatorPlane) SetTenantFeeRate(
	_ context.Context, req *connectrpc.Request[foraadminv1.SetTenantFeeRateRequest],
) (*connectrpc.Response[foraadminv1.SetTenantFeeRateResponse], error) {
	o.record("SetTenantFeeRate", req.Msg.GetVer())
	return connectrpc.NewResponse(&foraadminv1.SetTenantFeeRateResponse{Ver: helpers.ProtocolVersion, Rate: req.Msg.GetRate()}), nil
}

func (o *operatorPlane) SetReportingPolicy(
	_ context.Context, req *connectrpc.Request[foraadminv1.SetReportingPolicyRequest],
) (*connectrpc.Response[foraadminv1.SetReportingPolicyResponse], error) {
	o.record("SetReportingPolicy", req.Msg.GetVer())
	return connectrpc.NewResponse(&foraadminv1.SetReportingPolicyResponse{Ver: helpers.ProtocolVersion, Policy: req.Msg.GetPolicy()}), nil
}

func (o *operatorPlane) RequestDomainVerification(
	_ context.Context, req *connectrpc.Request[forav1.DomainVerificationRequest],
) (*connectrpc.Response[forav1.DomainVerificationChallenge], error) {
	o.record("RequestDomainVerification", req.Msg.GetVer())
	return connectrpc.NewResponse(&forav1.DomainVerificationChallenge{Ver: helpers.ProtocolVersion, Token: "tok-1"}), nil
}

func (o *operatorPlane) ConfirmDomainVerification(
	_ context.Context, req *connectrpc.Request[forav1.DomainVerificationConfirmation],
) (*connectrpc.Response[forav1.DomainVerificationResult], error) {
	o.record("ConfirmDomainVerification", req.Msg.GetVer())
	keyID := "key-1"
	return connectrpc.NewResponse(&forav1.DomainVerificationResult{Ver: helpers.ProtocolVersion, KeyId: &keyID}), nil
}

func serveOperatorPlane(t *testing.T, sig signingFixture, plane *operatorPlane) string {
	t.Helper()
	mux := http.NewServeMux()
	adminPath, admin := foraadminv1connect.NewAdminServiceHandler(plane)
	mux.Handle(adminPath, admin)
	exPath, ex := foraserver.NewExchangeServiceHandler(plane, foraserver.WithKeyResolver(sig.resolver))
	mux.Handle(exPath, ex)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

// Every AdminService RPC — enumerated from the compiled descriptor, so a new one
// fails here until the client carries it — has an AdminClient method of the same
// name, and each is exercised against the real handler.
func TestAdminClient_CoversEveryAdminRPC(t *testing.T) {
	sig := newSigningFixture(t)
	plane := &operatorPlane{}
	client := foraconnect.NewAdminClient(serveOperatorPlane(t, sig, plane), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))

	methods := foraadminv1.File_fora_admin_v1_admin_proto.Services().ByName("AdminService").Methods()
	if methods.Len() == 0 {
		t.Fatal("AdminService declares no methods; the enumeration would assert nothing")
	}
	for i := 0; i < methods.Len(); i++ {
		md := methods.Get(i)
		name := string(md.Name())
		t.Run(name, func(t *testing.T) {
			resp := callByName(t, client, name, md.Input())
			if resp == nil {
				t.Fatalf("%s returned no answer", name)
			}
			if got := plane.seen[name]; got != helpers.ProtocolVersion {
				t.Errorf("%s reached the server with ver %q, want it stamped", name, got)
			}
		})
	}
}

// callByName calls the AdminClient method named for an RPC with an empty request of
// its input type, and returns the answer.
func callByName(t *testing.T, client *foraconnect.AdminClient, name string, input protoreflect.MessageDescriptor) proto.Message {
	t.Helper()
	method := reflect.ValueOf(client).MethodByName(name)
	if !method.IsValid() {
		t.Fatalf("AdminClient has no method %s", name)
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByName(input.FullName())
	if err != nil {
		t.Fatal(err)
	}
	out := method.Call([]reflect.Value{reflect.ValueOf(context.Background()), reflect.ValueOf(mt.New().Interface())})
	if errV := out[1].Interface(); errV != nil {
		t.Fatalf("%s: %v", name, errV)
	}
	msg, _ := out[0].Interface().(proto.Message)
	return msg
}

// The two domain-verification RPCs are signed calls to the Exchange the request
// names; one that names none is refused before anything is sent.
func TestAdminClient_DomainVerification(t *testing.T) {
	sig := newSigningFixture(t)
	plane := &operatorPlane{}
	client := foraconnect.NewAdminClient(serveOperatorPlane(t, sig, plane), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))
	ctx := context.Background()

	challenge, err := client.RequestDomainVerification(ctx, &forav1.DomainVerificationRequest{
		Exchange: "exchange.test", Domain: "publisher.test"})
	if err != nil || challenge.GetToken() != "tok-1" {
		t.Fatalf("RequestDomainVerification = %v, %v", challenge, err)
	}
	result, err := client.ConfirmDomainVerification(ctx, &forav1.DomainVerificationConfirmation{
		Exchange: "exchange.test", Domain: "publisher.test", Token: challenge.GetToken()})
	if err != nil || result.GetKeyId() != "key-1" {
		t.Fatalf("ConfirmDomainVerification = %v, %v", result, err)
	}

	_, err = client.RequestDomainVerification(ctx, &forav1.DomainVerificationRequest{Domain: "publisher.test"})
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) || cerr.Kind != foraconnect.CallNotSent {
		t.Fatalf("an unaddressed request = %v, want CallNotSent", err)
	}
	if _, ok := plane.seen["RequestDomainVerification"]; !ok {
		t.Fatal("the addressed request never reached the Exchange")
	}
}
