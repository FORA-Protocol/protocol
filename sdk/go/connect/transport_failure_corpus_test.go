package connect

// Go replay of the transport-failure corpus (transport-failure-vectors.json).
//
// The corpus is the cross-language contract for what class an answer that did NOT come
// from the service falls into, so Go replays it too rather than only emitting it — a
// corpus its own oracle does not consume proves nothing about the oracle.
//
// What it holds is one distinction: a gateway draining is transient and a service saying
// no is final. Collapse them and a caller either retries a refusal forever or drops a
// usage report over a momentary outage.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

func TestTransportFailureCorpusReplay(t *testing.T) {
	raw, err := os.ReadFile(transportFailureVectorsPath) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", transportFailureVectorsPath, err)
	}
	var doc struct {
		TransportFailures []transportFailureVector `json:"transport_failures"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", transportFailureVectorsPath, err)
	}
	if len(doc.TransportFailures) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", transportFailureVectorsPath)
	}

	fresh := buildTransportFailureVectors(t)
	if len(fresh) != len(doc.TransportFailures) {
		t.Fatalf("the committed corpus has %d vectors and a fresh capture has %d",
			len(doc.TransportFailures), len(fresh))
	}
	var retryable, final int
	for i, want := range doc.TransportFailures {
		t.Run(want.Name, func(t *testing.T) {
			if got := fresh[i]; got != want {
				t.Errorf("captured %+v, committed %+v", got, want)
			}
			// The label and the consequence are pinned together: a replay comparing only
			// the string would still pass if the two classes swapped meanings.
			if want.Retryable != (want.Kind == CallUnreachable.String()) {
				t.Errorf("kind %q and retryable %v disagree", want.Kind, want.Retryable)
			}
			// An answer that did not come from the service still came from a peer: its
			// status is classified by its code, and that code is the failure's Code.
			if got := transportFailureCode(t, i); got != want.Reason {
				t.Errorf("code = %q, want %q", got, want.Reason)
			}
		})
		if want.Retryable {
			retryable++
		} else {
			final++
		}
	}
	// Both sides present, or the corpus asserts only half a distinction.
	if retryable == 0 || final == 0 {
		t.Errorf("corpus carries %d retryable and %d final vectors; both are needed",
			retryable, final)
	}
}

// transportFailureCode replays case i through the real client and returns the
// Connect code its CallError carries.
func transportFailureCode(t *testing.T, i int) string {
	t.Helper()
	c := transportFailureCases[i]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", c.contentType)
		w.WriteHeader(c.status)
		_, _ = w.Write([]byte(c.body))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL).Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	var callErr *CallError
	if !errors.As(err, &callErr) {
		t.Fatalf("%s: not a typed failure: %v", c.name, err)
	}
	return callErr.Code.String()
}
