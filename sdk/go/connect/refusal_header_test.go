package connect_test

// A refusal carries the status and header fields of the answer that refused, and
// only a refusal does. An error answer, 400 or above, puts both on the CallError on
// every RPC face and on the delivery fetch; a redirect, a 2xx the client could not
// read, and a failure where nothing answered carry neither. The redirect is the case
// the rule exists for: its Location names a URL the peer chose, so a refused redirect
// must not hand its target back through the header fields.
//
// Every case runs the real client against a real HTTP answer.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connectrpc "connectrpc.com/connect"

	foraadminv1 "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	foraserver "github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// fieldLine is one header line an answer is served with.
type fieldLine struct{ name, value string }

// refusalAnswer serves one fixed answer to every request: the status, the content
// type, the body and each header line in order, a repeated name as repeated lines.
func refusalAnswer(t *testing.T, status int, contentType, body string, lines ...fieldLine) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(refusalHandler(status, contentType, body, lines...))
	t.Cleanup(srv.Close)
	return srv
}

func refusalHandler(status int, contentType, body string, lines ...fieldLine) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		for _, line := range lines {
			w.Header().Add(line.name, line.value)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func callErrorFrom(t *testing.T, err error) *foraconnect.CallError {
	t.Helper()
	var cerr *foraconnect.CallError
	if !errors.As(err, &cerr) {
		t.Fatalf("not a typed failure: %v", err)
	}
	return cerr
}

// fieldValue reads a field the way the Python and TypeScript clients return it: every
// line of it, joined with ", ".
func fieldValue(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

// assertFieldsNotRendered fails when a carried value appears in the error's message.
// The values are the peer's, so a log line must never repeat them.
func assertFieldsNotRendered(t *testing.T, cerr *foraconnect.CallError) {
	t.Helper()
	for name, values := range cerr.Header {
		for _, value := range values {
			if strings.Contains(cerr.Error(), value) {
				t.Errorf("the message renders the %s value %q: %s", name, value, cerr.Error())
			}
		}
	}
}

const (
	unauthenticatedEnvelope = `{"code":"unauthenticated","message":"the request is not signed"}`
	// headerProbe is a value no message carries by accident, so its absence from
	// Error() is evidence rather than luck.
	headerProbe = "probe-6c1f0e"
)

var acceptSignatureLine = fieldLine{helpers.AcceptSignatureHeader, helpers.AcceptSignature(false)}

func TestARefusalCarriesItsStatusAndHeaderFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		lines       []fieldLine
		kind        foraconnect.CallErrorKind
		want        map[string]string
	}{
		{
			name:   "an envelope refusal names what the verifier requires",
			status: http.StatusUnauthorized, contentType: "application/json", body: unauthenticatedEnvelope,
			lines: []fieldLine{acceptSignatureLine},
			kind:  foraconnect.CallRefused,
			want:  map[string]string{helpers.AcceptSignatureHeader: helpers.AcceptSignature(false)},
		},
		{
			name:   "a draining gateway says when to come back",
			status: http.StatusServiceUnavailable, contentType: "text/plain", body: "draining",
			lines: []fieldLine{{"Retry-After", "86400"}},
			kind:  foraconnect.CallUnreachable,
			want:  map[string]string{"Retry-After": "86400"},
		},
		{
			name:   "a field sent on two lines keeps both",
			status: http.StatusBadRequest, contentType: "application/json",
			body:  `{"code":"invalid_argument","message":"refused"}`,
			lines: []fieldLine{{"X-Fora-Probe", headerProbe + "-first"}, {"X-Fora-Probe", headerProbe + "-second"}},
			kind:  foraconnect.CallRefused,
			want:  map[string]string{"X-Fora-Probe": headerProbe + "-first, " + headerProbe + "-second"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			srv := refusalAnswer(t, c.status, c.contentType, c.body, c.lines...)
			_, err := foraconnect.NewClient(srv.URL).Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
			cerr := callErrorFrom(t, err)
			if cerr.Kind != c.kind {
				t.Errorf("Kind = %v, want %v", cerr.Kind, c.kind)
			}
			if cerr.Status != c.status {
				t.Errorf("Status = %d, want %d", cerr.Status, c.status)
			}
			for name, want := range c.want {
				if got := fieldValue(cerr.Header, name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			// Lowercase reads the same field: http.Header canonicalizes on read.
			for name, want := range c.want {
				if got := fieldValue(cerr.Header, strings.ToLower(name)); got != want {
					t.Errorf("lowercase %s = %q, want %q", name, got, want)
				}
			}
			assertFieldsNotRendered(t, cerr)
		})
	}
}

// TestARefusalsStatusIsRendered pins the visible half of the status: an RPC refusal
// now names it, as the content leg's always did.
func TestARefusalsStatusIsRendered(t *testing.T) {
	t.Parallel()
	srv := refusalAnswer(t, http.StatusUnauthorized, "application/json", unauthenticatedEnvelope, acceptSignatureLine)
	_, err := foraconnect.NewClient(srv.URL).Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	if msg := callErrorFrom(t, err).Error(); !strings.Contains(msg, "(HTTP 401 Unauthorized)") {
		t.Errorf("the message does not name the status: %s", msg)
	}
}

func TestARedirectOrAnUnreadableSuccessCarriesNoStatusOrHeaderFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		lines       []fieldLine
	}{
		{
			name:   "a refused redirect",
			status: http.StatusFound, contentType: "text/plain",
			lines: []fieldLine{
				{"Location", "https://elsewhere.test/next?token=" + headerProbe},
				{"X-Fora-Probe", headerProbe},
			},
		},
		{
			name:   "a 2xx that is not a FORA answer",
			status: http.StatusOK, contentType: "text/html", body: "<html></html>",
			lines: []fieldLine{{"X-Fora-Probe", headerProbe}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			srv := refusalAnswer(t, c.status, c.contentType, c.body, c.lines...)
			_, err := foraconnect.NewClient(srv.URL).Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
			cerr := callErrorFrom(t, err)
			if cerr.Status != 0 {
				t.Errorf("Status = %d, want 0", cerr.Status)
			}
			if cerr.Header != nil {
				t.Errorf("Header = %v, want nil", cerr.Header)
			}
		})
	}
}

func TestAStrictlyRefusedEnvelopeKeepsItsStatusAndHeaderFields(t *testing.T) {
	t.Parallel()
	// An unknown envelope member: the answer is refused, and what the peer said about
	// itself — its code, its status, its header fields — stays readable.
	srv := refusalAnswer(t, http.StatusUnauthorized, "application/json",
		`{"code":"unauthenticated","message":"the request is not signed","bogus":true}`, acceptSignatureLine)
	_, err := foraconnect.NewClient(srv.URL, foraconnect.WithStrictDecoding()).
		Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	cerr := callErrorFrom(t, err)
	if cerr.Kind != foraconnect.CallMalformed {
		t.Fatalf("Kind = %v, want CallMalformed: %v", cerr.Kind, err)
	}
	if cerr.Code != connectrpc.CodeUnauthenticated {
		t.Errorf("Code = %v, want unauthenticated", cerr.Code)
	}
	if cerr.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", cerr.Status)
	}
	if got := fieldValue(cerr.Header, helpers.AcceptSignatureHeader); got != helpers.AcceptSignature(false) {
		t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
	}
}

func TestEveryRPCFaceCarriesARefusalsHeaderFields(t *testing.T) {
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
			srv := refusalAnswer(t, http.StatusUnauthorized, "application/json", unauthenticatedEnvelope, acceptSignatureLine)
			cerr := callErrorFrom(t, face.call(srv.URL))
			if cerr.Status != http.StatusUnauthorized {
				t.Errorf("Status = %d, want 401: %v", cerr.Status, cerr)
			}
			if got := fieldValue(cerr.Header, helpers.AcceptSignatureHeader); got != helpers.AcceptSignature(false) {
				t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
			}
		})
	}
}

// TestTheOfferDerivedLegCarriesARefusalsHeaderFields covers the leg a usage report
// takes: an Exchange the offer named, resolved from its own manifest, over the
// guarded transport. Not parallel: the loopback posture is set in the environment.
func TestTheOfferDerivedLegCarriesARefusalsHeaderFields(t *testing.T) {
	sig := newSigningFixture(t)
	domain, _ := loopbackManifestServer(t,
		refusalHandler(http.StatusUnauthorized, "application/json", unauthenticatedEnvelope, acceptSignatureLine))
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t), foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"))...)
	_, err := client.ReportUsage(context.Background(), &forav1.UsageReport{
		Exchange:      domain,
		TransactionId: "txn-1",
		Usage:         &forav1.Usage{Function: []string{"ai-input"}},
	})
	cerr := callErrorFrom(t, err)
	if cerr.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401: %v", cerr.Status, cerr)
	}
	if got := fieldValue(cerr.Header, helpers.AcceptSignatureHeader); got != helpers.AcceptSignature(false) {
		t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
	}
}

// TestTheSDKsOwnServerRefusalIsReadable closes the loop with the server binding: an
// unsigned call to a real verifying handler is answered 401, and the Accept-Signature
// that handler writes reaches the caller on the CallError.
func TestTheSDKsOwnServerRefusalIsReadable(t *testing.T) {
	t.Parallel()
	sig := newSigningFixture(t)
	path, h := foraserver.NewExchangeServiceHandler(&stubExchange{}, foraserver.WithKeyResolver(sig.resolver))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	_, err := foraconnect.NewClient(srv.URL).Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	cerr := callErrorFrom(t, err)
	if cerr.Kind != foraconnect.CallRefused || cerr.Status != http.StatusUnauthorized {
		t.Fatalf("got %v with status %d, want a 401 refusal: %v", cerr.Kind, cerr.Status, cerr)
	}
	if got := cerr.Header.Get(helpers.AcceptSignatureHeader); got != helpers.AcceptSignature(false) {
		t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
	}
}

// TestTheDeliveryFetchCarriesTheEdgesRefusalFields covers the content leg: a refused
// proof is answered with the Accept-Signature that asks for the right one, a 403
// carries the discovery headers helpers.ParseDiscoveryHint reads, and a redirect
// carries nothing. Not parallel: the loopback posture is set in the environment.
func TestTheDeliveryFetchCarriesTheEdgesRefusalFields(t *testing.T) {
	sig := newSigningFixture(t)
	client := foraconnect.NewClient("http://home.invalid",
		append(allowLoopback(t),
			foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"),
			foraconnect.WithAgentKey(sig.pub),
		)...)
	fetch := func(t *testing.T, srv *httptest.Server) *foraconnect.CallError {
		t.Helper()
		_, err := client.Fetch(context.Background(), srv.URL+"/doc?agent_id=tp")
		return callErrorFrom(t, err)
	}

	t.Run("a refused proof is asked for again", func(t *testing.T) {
		edge := refusalAnswer(t, http.StatusUnauthorized, "application/json",
			`{"error":"unauthorized","reason":"pop_sig_invalid"}`,
			fieldLine{helpers.AcceptSignatureHeader, helpers.PoPAcceptSignature})
		cerr := fetch(t, edge)
		if cerr.Status != http.StatusUnauthorized {
			t.Errorf("Status = %d, want 401", cerr.Status)
		}
		if got := fieldValue(cerr.Header, helpers.AcceptSignatureHeader); got != helpers.PoPAcceptSignature {
			t.Errorf("Accept-Signature = %q, want %q", got, helpers.PoPAcceptSignature)
		}
		assertFieldsNotRendered(t, cerr)
	})

	t.Run("a 403 names where the terms are", func(t *testing.T) {
		const rules = "https://publisher.test/.well-known/fora.json"
		edge := refusalAnswer(t, http.StatusForbidden, "application/json", `{"error":"forbidden"}`,
			fieldLine{helpers.ContentRulesHeader, rules}, fieldLine{helpers.ExchangeHeader, "exchange.test"})
		cerr := fetch(t, edge)
		hint := helpers.ParseDiscoveryHint(cerr.Status, cerr.Header)
		if hint.ContentRulesState != helpers.HintValid || hint.ContentRules != rules {
			t.Errorf("content rules = %q (%v), want %q valid", hint.ContentRules, hint.ContentRulesState, rules)
		}
		if hint.ExchangeState != helpers.HintValid || hint.Exchange != "exchange.test" {
			t.Errorf("exchange = %q (%v), want exchange.test valid", hint.Exchange, hint.ExchangeState)
		}
	})

	t.Run("a redirect carries nothing", func(t *testing.T) {
		edge := refusalAnswer(t, http.StatusFound, "text/plain", "",
			fieldLine{"Location", "https://elsewhere.test/doc?token=" + headerProbe},
			fieldLine{"X-Fora-Probe", headerProbe})
		cerr := fetch(t, edge)
		if cerr.Header != nil {
			t.Errorf("Header = %v, want nil", cerr.Header)
		}
	})
}
