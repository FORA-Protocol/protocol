package connect_test

// Connect error-envelope cross-language golden-vector emitter.
//
// The ADR-019 ErrorDetail corpus (sdk/go/helpers/testdata/error-detail-vectors.json)
// pins the DETAIL's own proto-JSON. It says nothing about the ENVELOPE the detail
// arrives in, and the envelope is where the JSON-only SDKs actually read from: they
// have no protobuf binary codec, so they cannot open the detail's `value` (a base64
// Any) and must read Connect's `debug` projection instead.
//
// That projection does not follow the FORA wire naming, and no server option changes
// it. connect-go builds it with its own protojson codec at default options, so the
// keys are lowerCamelCase — `transactionDenial`, `fieldErrors` — while everything else
// on the FORA wire, including the response bodies the same server emits through
// connectserver.EmitUnpopulatedJSONCodec, is snake_case. A reader that parses `debug`
// with a snake-only schema therefore finds `domain` and `message` (single words spell
// the same either way), silently drops the typed reason block, and reports no reason at
// all for a refusal the server named precisely. That is a fail-OPEN read of the one
// field a caller is supposed to branch on.
//
// So the vectors are CAPTURED from a real round trip rather than written by hand: a
// generated ExchangeService handler returns a classified *connect.Error carrying a
// detail built by the real helpers.*Detail constructors, and the emitter records the
// bytes that came back over HTTP. Nothing here restates what connect-go emits; if a
// future version changes the envelope, the drift gate reports it.
//
// Each vector carries the envelope AS SERVED plus the projection every SDK must extract
// from it. The Go replay (connect_error_corpus_test.go) serves the recorded bytes back
// through a real client and asserts ErrorDetailFrom reaches the projection; the Python
// and TS replays parse the same envelope with their own error_detail_from / reason.
//
// Like the other emitters this test is a verification no-op by default (it asserts the
// committed file matches a fresh emit) and (re)writes it under FORA_UPDATE_VECTORS=1.
// It is TEST INFRASTRUCTURE, not the code under test.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

const connectErrorVectorsPath = "testdata/connect-error-vectors.json"

// exchangeDomain is the service domain every vector's detail names. A stable grouping
// key for tooling, and the value the ADR-019 builders take first.
const exchangeDomain = "fora.v1.ExchangeService"

// connectErrorVector is one captured envelope plus what every SDK must read out of it.
type connectErrorVector struct {
	Name string `json:"name"`
	// Code is the Connect error code the server classified the failure as.
	Code string `json:"code"`
	// HTTPStatus is the status connect-go maps that code onto.
	HTTPStatus int `json:"http_status"`
	// Envelope is the response body AS SERVED, parsed back to JSON so the committed
	// bytes are stable (protojson varies its whitespace on purpose).
	Envelope any `json:"envelope"`
	// Expect is the projection every SDK must extract. A vector carrying no detail
	// leaves HasDetail false and the rest empty — "no ErrorDetail" is an answer.
	Expect connectErrorExpectation `json:"expect"`
	// PeerMessage is the peer's own sentence as the CLIENT reports it, not as the
	// envelope spells it. It is the typed detail's developer message and nothing else:
	// EMPTY when no detail is attached, even where the envelope carries a `message` of
	// its own, because that text is the transport's rather than a FORA service's —
	// connect-go writes a status line there where a fetch-based client writes nothing,
	// so filling the field from it would make its value a property of the language.
	//
	// Top-level rather than inside Expect, which projects the ErrorDetail: this is a
	// property of the CallError one tier up. The column gate reads top-level keys, so
	// placing it here is also what obliges all three replays to assert it.
	PeerMessage string `json:"peer_message"`
}

// connectErrorExpectation mirrors the error-detail corpus's projection so the two read
// the same way, plus the has-detail verdict the envelope adds.
type connectErrorExpectation struct {
	HasDetail  bool              `json:"has_detail"`
	Domain     string            `json:"domain"`
	Message    string            `json:"message"`
	Metadata   map[string]string `json:"metadata"`
	ReasonFrom string            `json:"reason_field"`
	ReasonEnum string            `json:"reason_enum"`
}

// errorCase is one server-side failure to capture.
type errorCase struct {
	name   string
	code   connectrpc.Code
	msg    string
	detail *forav1.ErrorDetail
}

// connectErrorCases are the failures the envelope must carry faithfully.
//
// Coverage is chosen by DECODE SHAPE, not by how many reasons exist: a reason block one
// level down (transaction_denial), a reason block with a nested repeated message two
// levels down (registration_failure.field_errors — the deepest camelCase path on this
// wire), a detail with no reason at all, a detail whose metadata keys are CALLER-chosen
// and must survive verbatim, and an error carrying no detail whatsoever.
//
// Metadata is kept to a single entry on purpose. The detail's `value` is binary
// protobuf, and Go does not sort map keys when marshaling it, so a second entry would
// make the captured bytes differ run to run and the drift gate would fire on noise.
func connectErrorCases() []errorCase {
	fieldErr := &forav1.RegistrationFieldError{
		Path:  "/operator/legal_name",
		Error: "required property is missing",
	}
	metadata := helpers.TransactionDenialDetail(exchangeDomain, "slow down",
		forav1.DenialReason_DENIAL_REASON_RATE_LIMITED)
	// A deliberately lowerCamelCase key: metadata is a map<string,string> whose keys the
	// EMITTER chooses, so a reader normalizing wire names must not touch them.
	metadata.Metadata = map[string]string{"retryAfterSeconds": "30"}
	return []errorCase{
		{
			name: "transaction_denial_insufficient_balance",
			code: connectrpc.CodePermissionDenied, msg: "balance too low",
			detail: helpers.TransactionDenialDetail(exchangeDomain, "balance too low",
				forav1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE),
		},
		{
			name: "retrieval_auth_failure_url_expired",
			code: connectrpc.CodeUnauthenticated, msg: "signed URL expired",
			detail: helpers.RetrievalAuthFailureDetail("fora.v1.Edge", "signed URL expired",
				forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED),
		},
		{
			name: "registration_failure_with_field_errors",
			code: connectrpc.CodeInvalidArgument, msg: "registration data rejected",
			detail: helpers.RegistrationFailureDetail(exchangeDomain, "registration data rejected",
				forav1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
				fieldErr),
		},
		{
			name: "usage_report_rejection",
			code: connectrpc.CodeFailedPrecondition, msg: "no such transaction",
			detail: helpers.UsageReportRejectionDetail(exchangeDomain, "no such transaction",
				forav1.UsageReportRejectionReason_USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND),
		},
		{
			name: "dispute_failure",
			code: connectrpc.CodeFailedPrecondition, msg: "dispute window closed",
			detail: helpers.DisputeFailureDetail(exchangeDomain, "dispute window closed",
				forav1.DisputeFailureReason_DISPUTE_FAILURE_REASON_WINDOW_EXPIRED),
		},
		{
			name: "catalog_rejection",
			code: connectrpc.CodeInvalidArgument, msg: "entry rejected",
			detail: helpers.CatalogRejectionDetail("fora.v1.CatalogService", "entry rejected",
				forav1.CatalogRejectionReason_CATALOG_REJECTION_REASON_MALFORMED_ENTRY),
		},
		{
			name: "domain_verification_failure",
			code: connectrpc.CodeFailedPrecondition, msg: "challenge not found",
			detail: helpers.DomainVerificationFailureDetail(exchangeDomain, "challenge not found",
				forav1.DomainVerificationFailureReason_DOMAIN_VERIFICATION_FAILURE_REASON_CHALLENGE_NOT_FOUND),
		},
		{
			name: "generic_detail_no_reason",
			code: connectrpc.CodeInternal, msg: "internal error",
			detail: connectserver.NewErrorDetail(exchangeDomain, "internal error", nil),
		},
		{
			name: "metadata_keys_are_caller_chosen",
			code: connectrpc.CodeResourceExhausted, msg: "slow down",
			detail: metadata,
		},
		{
			// No detail at all — the transport failed before any service opinion existed.
			// A reader must answer "no ErrorDetail" rather than inventing one.
			name: "no_detail_attached",
			code: connectrpc.CodeUnavailable, msg: "exchange is draining",
		},
	}
}

// TestGenerateConnectErrorVectors emits the Connect error-envelope golden corpus.
func TestGenerateConnectErrorVectors(t *testing.T) {
	doc := map[string]any{
		"note": "Connect JSON error envelopes captured from a real connect-go handler. " +
			"details[].debug is lowerCamelCase — connect-go builds it with its own protojson " +
			"codec at default options, which no server codec replaces — while every FORA " +
			"message body is snake_case. details[].value is the base64 binary Any, which the " +
			"JSON-only SDKs deliberately cannot open.",
		"vectors": buildConnectErrorVectors(t),
	}
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(connectErrorVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", connectErrorVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(connectErrorVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", connectErrorVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", connectErrorVectorsPath)
	}
}

func buildConnectErrorVectors(t *testing.T) []connectErrorVector {
	t.Helper()
	cases := connectErrorCases()
	out := make([]connectErrorVector, 0, len(cases))
	for _, c := range cases {
		status, envelope, peerMessage := captureEnvelope(t, c)
		out = append(out, connectErrorVector{
			Name:        c.name,
			Code:        c.code.String(),
			HTTPStatus:  status,
			Envelope:    envelope,
			Expect:      expectationOf(c.detail),
			PeerMessage: peerMessage,
		})
	}
	return out
}

// expectationOf renders what every SDK must read out of the envelope, DERIVED from the
// detail the server attached rather than restated — the reason is read back through the
// real helpers.Reason accessor, so the corpus cannot claim a reason Go would not report.
func expectationOf(detail *forav1.ErrorDetail) connectErrorExpectation {
	if detail == nil {
		return connectErrorExpectation{}
	}
	exp := connectErrorExpectation{
		HasDetail: true,
		Domain:    detail.GetDomain(),
		Message:   detail.GetMessage(),
		Metadata:  detail.GetMetadata(),
	}
	switch r := helpers.Reason(detail).(type) {
	case nil:
	case forav1.DenialReason:
		exp.ReasonFrom, exp.ReasonEnum = "transaction_denial", r.String()
	case forav1.CatalogRejectionReason:
		exp.ReasonFrom, exp.ReasonEnum = "catalog_rejection", r.String()
	case forav1.RegistrationFailureReason:
		exp.ReasonFrom, exp.ReasonEnum = "registration_failure", r.String()
	case forav1.DisputeFailureReason:
		exp.ReasonFrom, exp.ReasonEnum = "dispute_failure", r.String()
	case forav1.DomainVerificationFailureReason:
		exp.ReasonFrom, exp.ReasonEnum = "domain_verification_failure", r.String()
	case forav1.RetrievalAuthFailureReason:
		exp.ReasonFrom, exp.ReasonEnum = "retrieval_auth_failure", r.String()
	case forav1.UsageReportRejectionReason:
		exp.ReasonFrom, exp.ReasonEnum = "usage_report_rejection", r.String()
	}
	return exp
}

// captureEnvelope runs one failure through a real generated handler over HTTP and
// returns the status and the response body, parsed back to JSON.
//
// Parsed back rather than kept as bytes for two reasons: protojson varies its
// whitespace deliberately, and the committed corpus is byte-compared. Re-encoding
// through encoding/json (which sorts object keys) makes the file stable while leaving
// the KEYS — the whole point of this corpus — exactly as connect-go spelled them.
func captureEnvelope(t *testing.T, c errorCase) (int, any, string) {
	t.Helper()
	// The FORA JSON codec is registered so the capture is the shape a FORA deployment
	// actually serves. It changes response BODIES to snake_case and leaves the error
	// envelope alone, which is the asymmetry this corpus exists to record.
	path, handler := forav1connect.NewExchangeServiceHandler(
		&failingExchange{c: c},
		connectrpc.WithCodec(connectserver.EmitUnpopulatedJSONCodec()),
	)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/fora.v1.ExchangeService/ExecuteTransaction", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", helpers.ContentTypeJSON)
	req.Header.Set(helpers.ConnectProtocolVersionHeader, helpers.ConnectProtocolVersion)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var envelope any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("parse envelope %q: %v", body, err)
	}

	// The peer's sentence, CAPTURED FROM THE REAL CLIENT against this same handler
	// rather than derived from the detail the server attached. Derived, the column would
	// restate `expect.message` on every row and assert nothing; captured, it records
	// what a caller actually reads — including on the row where the envelope carries a
	// message and the client reports none.
	_, derr := foraconnect.NewClient(srv.URL).Discover(
		context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	var callErr *foraconnect.CallError
	if !errors.As(derr, &callErr) {
		t.Fatalf("%s: the client did not report a typed failure: %v", c.name, derr)
	}
	return resp.StatusCode, envelope, callErr.PeerMessage
}

// failingExchange answers ExecuteTransaction with one classified failure.
type failingExchange struct {
	forav1connect.UnimplementedExchangeServiceHandler
	c errorCase
}

func (f *failingExchange) ExecuteTransaction(
	context.Context, *connectrpc.Request[forav1.TransactionRequest],
) (*connectrpc.Response[forav1.TransactionResponse], error) {
	cerr := connectrpc.NewError(f.c.code, errStatic(f.c.msg))
	if f.c.detail == nil {
		return nil, cerr
	}
	return nil, connectserver.AttachDetail(cerr, f.c.detail)
}

// DiscoverResources answers the same classified failure, so the peer message can be
// captured from a real client verb against this same handler.
func (f *failingExchange) DiscoverResources(
	context.Context, *connectrpc.Request[forav1.ResourceQuery],
) (*connectrpc.Response[forav1.ResourceResponse], error) {
	cerr := connectrpc.NewError(f.c.code, errStatic(f.c.msg))
	if f.c.detail == nil {
		return nil, cerr
	}
	return nil, connectserver.AttachDetail(cerr, f.c.detail)
}

// errStatic is a fixed error value, so the envelope's `message` is the case's own text
// and carries nothing incidental (a wrapped path, an address) that would vary per run.
type errStatic string

func (e errStatic) Error() string { return string(e) }
