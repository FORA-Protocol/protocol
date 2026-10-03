package connect_test

// Strict decoding of error answers, through the real client against a server that
// writes the bytes under test. The shared connect-error corpus holds the three SDKs to
// one verdict on captured envelopes; these cases cover the envelope rules the corpus
// does not exercise one by one.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// denialValue is a valid binary ErrorDetail, base64 as connect-go writes it.
func denialValue(t *testing.T, extra func([]byte) []byte) string {
	t.Helper()
	b, err := proto.Marshal(helpers.TransactionDenialDetail("fora.v1.ExchangeService", "no",
		forav1.DenialReason_DENIAL_REASON_INSUFFICIENT_BALANCE))
	if err != nil {
		t.Fatal(err)
	}
	if extra != nil {
		b = extra(b)
	}
	return base64.RawStdEncoding.EncodeToString(b)
}

// discoverAgainst answers every call with status and body, and returns the strict
// client's typed failure.
func discoverAgainst(t *testing.T, status int, body []byte, gzipped bool) *foraconnect.CallError {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", helpers.ContentTypeJSON)
		out := body
		if gzipped {
			var buf bytes.Buffer
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(body)
			_ = zw.Close()
			out = buf.Bytes()
			w.Header().Set("Content-Encoding", "gzip")
		}
		w.WriteHeader(status)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	_, err := foraconnect.NewClient(srv.URL, foraconnect.WithStrictDecoding()).Discover(
		context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	var callErr *foraconnect.CallError
	if !errors.As(err, &callErr) {
		t.Fatalf("no typed failure: %v", err)
	}
	return callErr
}

func TestStrictDecoding_ErrorEnvelopeRules(t *testing.T) {
	valid := denialValue(t, nil)
	unknownBinary := denialValue(t, func(b []byte) []byte {
		b = protowire.AppendTag(b, 99, protowire.VarintType)
		return protowire.AppendVarint(b, 1)
	})
	cases := []struct {
		name      string
		status    int
		body      string
		gzipped   bool
		malformed bool
	}{
		{name: "valid envelope", status: 403,
			body: `{"code":"permission_denied","message":"no","details":[{"type":"fora.v1.ErrorDetail","value":"` + valid + `"}]}`},
		{name: "null members read as absent", status: 500,
			body: `{"code":"internal","message":null,"details":null}`},
		{name: "a detail of another type is not decoded", status: 500,
			body: `{"code":"internal","details":[{"type":"google.rpc.RetryInfo","value":"AA","debug":{"any":"thing"}}]}`},
		{name: "a body that is not JSON is a gateway's", status: 502, body: `<html>bad gateway</html>`},
		{name: "an empty body is a gateway's", status: 503, body: ``},
		{name: "no code", status: 500, body: `{"message":"x"}`, malformed: true},
		{name: "code not a Connect code", status: 500, body: `{"code":"teapot"}`, malformed: true},
		{name: "code not a string", status: 500, body: `{"code":13}`, malformed: true},
		{name: "message not a string", status: 500, body: `{"code":"internal","message":1}`, malformed: true},
		{name: "JSON but not an object", status: 500, body: `["internal"]`, malformed: true},
		{name: "details not an array", status: 500, body: `{"code":"internal","details":{}}`, malformed: true},
		{name: "entry with an unknown member", status: 500,
			body: `{"code":"internal","details":[{"type":"x","value":"AA","extra":1}]}`, malformed: true},
		{name: "entry with no type", status: 500,
			body: `{"code":"internal","details":[{"value":"AA"}]}`, malformed: true},
		{name: "entry with neither value nor debug", status: 500,
			body: `{"code":"internal","details":[{"type":"x"}]}`, malformed: true},
		{name: "value not base64", status: 500,
			body: `{"code":"internal","details":[{"type":"x","value":"*not*"}]}`, malformed: true},
		{name: "binary ErrorDetail with an unknown field", status: 403,
			body:      `{"code":"permission_denied","details":[{"type":"fora.v1.ErrorDetail","value":"` + unknownBinary + `"}]}`,
			malformed: true},
		{name: "debug projection that is not an object", status: 403,
			body:      `{"code":"permission_denied","details":[{"type":"fora.v1.ErrorDetail","debug":"x"}]}`,
			malformed: true},
		{name: "gzip-coded envelope with an unknown member", status: 500,
			body: `{"code":"internal","extra":true}`, gzipped: true, malformed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := discoverAgainst(t, tc.status, []byte(tc.body), tc.gzipped)
			if (got.Kind == foraconnect.CallMalformed) != tc.malformed {
				t.Fatalf("kind = %v, want malformed = %v (%v)", got.Kind, tc.malformed, got)
			}
			if tc.malformed && got.Code == 0 {
				t.Errorf("a refused envelope lost the peer's code: %v", got)
			}
		})
	}
}
