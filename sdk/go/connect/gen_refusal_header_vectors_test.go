package connect_test

// Refusal-header golden-vector emitter: which failures carry the header fields of the
// answer that produced them, and what those fields read as.
//
// A peer's error answer says what it wants next in its header fields — the signature a
// verifier requires, when a draining gateway will take the call again, where a
// publisher's terms are — and all three clients carry them on their typed failure. They
// read them through three different HTTP libraries: net/http canonicalizes names and
// keeps each line of a repeated field, undici lowercases names and decodes values as
// UTF-8, httpx keeps names as sent. So what the corpus pins is the reading a caller sees:
// a field looked up by any spelling of its name, a repeated field joined with ", ", and
// the rule for when there are fields at all — an answer of status 400 or above, on both
// legs, and never a redirect, whose Location names a URL the peer chose, nor a 2xx the
// client could not read.
//
// Each row records the row's own fields only. The served answer also carries Date and
// Content-Length, which change with the run and say nothing about the rule.
//
// The failure class is deliberately not recorded: a 2xx that is not a FORA answer is a
// refusal in Go, which connect-go classifies by its content type, and malformed in the
// two JSON clients. That difference predates this corpus and is not what it pins.
//
// Captured by driving the REAL client against each answer. Verification no-op by default;
// (re)writes under FORA_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

const refusalHeaderVectorsPath = "testdata/refusal-header-vectors.json"

// refusalHeaderVector is one answer a peer gave, and what the client's failure carries.
type refusalHeaderVector struct {
	Name string `json:"name"`
	// Leg is "rpc" for a Connect call or "content" for the delivery fetch.
	Leg string `json:"leg"`
	// Strict decodes the answer strictly (an RPC leg only): an envelope the contract
	// does not accept is refused, and keeps its fields.
	Strict      bool   `json:"strict"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
	// Headers are the answer's own field lines, in order; a repeated name is a field
	// sent on several lines.
	Headers [][2]string `json:"headers"`
	// Carried maps each of the row's field names, lowercased, to the value the failure
	// carries for it, a repeated field joined with ", ". Empty when the failure carries
	// no fields at all, which a replay checks of the WHOLE set, not only the row's names.
	Carried map[string]string `json:"carried"`
	// Hint is helpers.ParseDiscoveryHint over the failure's own status and fields: what a
	// caller reads from an edge's 403 without touching the raw answer.
	Hint refusalHint `json:"hint"`
}

type refusalHint struct {
	ContentRules      string `json:"content_rules"`
	ContentRulesState string `json:"content_rules_state"`
	Exchange          string `json:"exchange"`
	ExchangeState     string `json:"exchange_state"`
}

// The answers, before the client has read them.
var refusalHeaderCases = []refusalHeaderVector{
	{
		Name: "rpc_401_accept_signature", Leg: "rpc", Status: http.StatusUnauthorized,
		ContentType: "application/json", Body: unauthenticatedEnvelope,
		Headers: [][2]string{{helpers.AcceptSignatureHeader, helpers.AcceptSignature(false)}},
	},
	{
		Name: "rpc_401_strict_envelope_refused", Leg: "rpc", Strict: true, Status: http.StatusUnauthorized,
		ContentType: "application/json",
		Body:        `{"code":"unauthenticated","message":"the request is not signed","bogus":true}`,
		Headers:     [][2]string{{helpers.AcceptSignatureHeader, helpers.AcceptSignature(false)}},
	},
	{
		Name: "rpc_503_retry_after", Leg: "rpc", Status: http.StatusServiceUnavailable,
		ContentType: "text/plain", Body: "draining",
		Headers: [][2]string{{"Retry-After", "86400"}},
	},
	{
		Name: "rpc_400_two_field_lines", Leg: "rpc", Status: http.StatusBadRequest,
		ContentType: "application/json", Body: `{"code":"invalid_argument","message":"refused"}`,
		Headers: [][2]string{{"X-Fora-Probe", "first"}, {"X-Fora-Probe", "second"}},
	},
	{
		Name: "rpc_302_location", Leg: "rpc", Status: http.StatusFound,
		ContentType: "text/plain",
		Headers: [][2]string{
			{"Location", "https://elsewhere.test/next?token=s3cret"}, {"X-Fora-Probe", "redirect"},
		},
	},
	{
		Name: "rpc_200_not_json", Leg: "rpc", Status: http.StatusOK,
		ContentType: "text/html", Body: "<html></html>",
		Headers: [][2]string{{"X-Fora-Probe", "success"}},
	},
	{
		Name: "content_401_pop_accept_signature", Leg: "content", Status: http.StatusUnauthorized,
		ContentType: "application/json", Body: `{"error":"unauthorized","reason":"pop_sig_invalid"}`,
		Headers: [][2]string{{helpers.AcceptSignatureHeader, helpers.PoPAcceptSignature}},
	},
	{
		Name: "content_403_discovery_hint", Leg: "content", Status: http.StatusForbidden,
		ContentType: "application/json", Body: `{"error":"forbidden"}`,
		Headers: [][2]string{
			{helpers.ContentRulesHeader, "https://publisher.test/.well-known/fora.json"},
			{helpers.ExchangeHeader, "exchange.test"},
		},
	},
	{
		Name: "content_302_location", Leg: "content", Status: http.StatusFound,
		ContentType: "text/plain",
		Headers: [][2]string{
			{"Location", "https://elsewhere.test/doc?token=s3cret"}, {"X-Fora-Probe", "redirect"},
		},
	},
}

func TestGenerateRefusalHeaderVectors(t *testing.T) {
	doc := map[string]any{
		"note": "Which failures carry the header fields of the answer that produced them, " +
			"captured from the real Go client: an answer of status 400 or above on either " +
			"leg, and never a redirect or a 2xx the client could not read. Each row records " +
			"its own field lines only; carried maps each lowercased name to the value read, " +
			"a repeated field joined with \", \", and is empty when no field is carried at all.",
		"refusals": buildRefusalHeaderVectors(t),
	}
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(refusalHeaderVectorsPath, doc); err != nil {
			t.Fatalf("write %s: %v", refusalHeaderVectorsPath, err)
		}
		return
	}
	stale, err := vectorio.Stale(refusalHeaderVectorsPath, doc)
	if err != nil {
		t.Fatalf("read %s: %v", refusalHeaderVectorsPath, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", refusalHeaderVectorsPath)
	}
}

func buildRefusalHeaderVectors(t *testing.T) []refusalHeaderVector {
	t.Helper()
	out := make([]refusalHeaderVector, 0, len(refusalHeaderCases))
	for _, c := range refusalHeaderCases {
		cerr := refusalHeaderFailure(t, c)
		c.Carried, c.Hint = refusalHeaderOutcome(c, cerr)
		// The emitter checks the rule it records, so a corpus that broke it could not be
		// written in the first place.
		if (len(c.Carried) > 0) != (c.Status >= http.StatusBadRequest) {
			t.Fatalf("%s: status %d carries %v", c.Name, c.Status, c.Carried)
		}
		if len(c.Carried) > 0 && cerr.Status != c.Status {
			t.Fatalf("%s: carried fields beside status %d, want %d", c.Name, cerr.Status, c.Status)
		}
		for name, value := range c.Carried {
			if strings.Contains(cerr.Error(), value) {
				t.Fatalf("%s: the message renders %s: %s", c.Name, name, cerr.Error())
			}
		}
		out = append(out, c)
	}
	return out
}

// refusalHeaderFailure serves the row's answer and drives the real client at it.
func refusalHeaderFailure(t *testing.T, v refusalHeaderVector) *foraconnect.CallError {
	t.Helper()
	lines := make([]fieldLine, 0, len(v.Headers))
	for _, h := range v.Headers {
		lines = append(lines, fieldLine{h[0], h[1]})
	}
	srv := httptest.NewServer(refusalHandler(v.Status, v.ContentType, v.Body, lines...))
	defer srv.Close()

	ctx := context.Background()
	switch v.Leg {
	case "rpc":
		var opts []foraconnect.ClientOption
		if v.Strict {
			opts = append(opts, foraconnect.WithStrictDecoding())
		}
		_, err := foraconnect.NewClient(srv.URL, opts...).
			Discover(ctx, &forav1.ResourceQuery{Exchange: "exchange.test"})
		return callErrorFrom(t, err)
	case "content":
		sig := newSigningFixture(t)
		client := foraconnect.NewClient("http://home.invalid",
			append(allowLoopback(t),
				foraconnect.WithSigner(sig.signer), foraconnect.WithSignatureAgent("https://agent.test"),
				foraconnect.WithAgentKey(sig.pub),
			)...)
		_, err := client.Fetch(ctx, srv.URL+"/doc?agent_id=tp")
		return callErrorFrom(t, err)
	}
	t.Fatalf("%s: unknown leg %q", v.Name, v.Leg)
	return nil
}

// refusalHeaderOutcome reads what the failure carries for the row's own field names, and
// the discovery hint a caller parses from it.
func refusalHeaderOutcome(v refusalHeaderVector, cerr *foraconnect.CallError) (map[string]string, refusalHint) {
	carried := map[string]string{}
	if len(cerr.Header) > 0 {
		for _, h := range v.Headers {
			name := strings.ToLower(h[0])
			carried[name] = fieldValue(cerr.Header, name)
		}
	}
	hint := helpers.ParseDiscoveryHint(cerr.Status, cerr.Header)
	return carried, refusalHint{
		ContentRules:      hint.ContentRules,
		ContentRulesState: hint.ContentRulesState.String(),
		Exchange:          hint.Exchange,
		ExchangeState:     hint.ExchangeState.String(),
	}
}
