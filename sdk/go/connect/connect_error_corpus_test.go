package connect_test

// Go replay of the Connect error-envelope corpus (connect-error-vectors.json).
//
// The corpus is the cross-language contract for reading a failure off the wire, so Go
// replays it too rather than only emitting it — a corpus its own oracle does not consume
// proves nothing about the oracle.
//
// The replay is deliberately end-to-end from BYTES: a bare HTTP server writes the
// recorded envelope verbatim, a real generated client calls it, and the error it hands
// back goes through the public ErrorDetailFrom. So this exercises connect-go's own
// envelope parsing, not a hand-rolled one — which matters, because Go reaches the detail
// through the binary `value` while Python and TypeScript reach it through the
// lowerCamelCase `debug` projection. Two different paths to the same projection is
// exactly the property the corpus exists to hold.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func loadConnectErrorVectors(t *testing.T) []connectErrorVector {
	t.Helper()
	b, err := os.ReadFile(connectErrorVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", connectErrorVectorsPath, err)
	}
	var doc struct {
		Vectors []connectErrorVector `json:"vectors"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse %s: %v", connectErrorVectorsPath, err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", connectErrorVectorsPath)
	}
	return doc.Vectors
}

func TestConnectErrorCorpusReplay(t *testing.T) {
	for _, v := range loadConnectErrorVectors(t) {
		t.Run(v.name(), func(t *testing.T) {
			err := callServing(t, v)
			if err == nil {
				t.Fatalf("envelope %q produced no error", v.Name)
			}
			detail, ok := foraconnect.ErrorDetailFrom(err)
			if ok != v.Expect.HasDetail {
				t.Fatalf("ErrorDetailFrom has-detail = %v, want %v", ok, v.Expect.HasDetail)
			}
			// BEFORE the early return, because the row that carries no detail is the one
			// this column exists for: its envelope has a `message` of its own and the
			// client must still report none.
			if got := peerMessageServing(t, v); got != v.PeerMessage {
				t.Errorf("peer message = %q, want %q", got, v.PeerMessage)
			}
			if !ok {
				return
			}
			if got := detail.GetDomain(); got != v.Expect.Domain {
				t.Errorf("domain = %q, want %q", got, v.Expect.Domain)
			}
			if got := detail.GetMessage(); got != v.Expect.Message {
				t.Errorf("message = %q, want %q", got, v.Expect.Message)
			}
			for k, want := range v.Expect.Metadata {
				if got := detail.GetMetadata()[k]; got != want {
					t.Errorf("metadata[%q] = %q, want %q", k, got, want)
				}
			}
			field, enum := reasonProjection(detail)
			if field != v.Expect.ReasonFrom || enum != v.Expect.ReasonEnum {
				t.Errorf("reason = (%q, %q), want (%q, %q)",
					field, enum, v.Expect.ReasonFrom, v.Expect.ReasonEnum)
			}
		})
	}
}

// name is the subtest name; the vector's own, so a failure names the case.
func (v connectErrorVector) name() string { return v.Name }

// reasonProjection reads the typed reason back through the real accessor, the same way
// the emitter derived what the corpus claims.
func reasonProjection(detail *forav1.ErrorDetail) (string, string) {
	return expectationOf(detail).ReasonFrom, expectationOf(detail).ReasonEnum
}

// callServing serves the vector's recorded envelope verbatim and calls it with a real
// generated client, returning the error connect-go produced from those bytes.
func callServing(t *testing.T, v connectErrorVector) error {
	t.Helper()
	body, err := json.Marshal(v.Envelope)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", helpers.ContentTypeJSON)
		w.WriteHeader(v.HTTPStatus)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// The JSON codec is pinned: the corpus records a JSON envelope, and a client left on
	// the default binary codec would ask for application/proto and never reach it.
	client := forav1connect.NewExchangeServiceClient(srv.Client(), srv.URL,
		connectrpc.WithProtoJSON())
	_, err = client.ExecuteTransaction(context.Background(),
		connectrpc.NewRequest(&forav1.TransactionRequest{}))
	return err
}

// peerMessageServing serves the same recorded envelope and reads the peer's sentence back
// off the CLIENT's own failure, which is where the field lives — one tier above the
// ErrorDetail the rest of this replay projects.
//
// The rule it pins is provenance: the field carries a message the PEER emitted and
// nothing else. A transport's synthesized text is not that. connect-go writes a status
// line where a fetch-based client writes nothing, so a client filling the field from the
// envelope would make its value a property of the language rather than of the answer —
// which is the drift a shared corpus exists to catch, and could not have caught while
// each language was faithfully reporting its own transport.
func peerMessageServing(t *testing.T, v connectErrorVector) string {
	t.Helper()
	body, err := json.Marshal(v.Envelope)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", helpers.ContentTypeJSON)
		w.WriteHeader(v.HTTPStatus)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	_, derr := foraconnect.NewClient(srv.URL).Discover(
		context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	var callErr *foraconnect.CallError
	if !errors.As(derr, &callErr) {
		t.Fatalf("the client did not report a typed failure: %v", derr)
	}
	return callErr.PeerMessage
}
