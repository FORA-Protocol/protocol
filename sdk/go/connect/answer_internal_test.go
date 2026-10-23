package connect

// The answer recorder keeps the record of one round trip. Each request clears what an
// earlier request on the same call recorded before it is sent, so no answer at all, or
// an answer that stores nothing, leaves nothing of an earlier attempt behind; an answer
// that does store something is recorded as before.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// answering is a transport that returns resp, or fails with err.
func answering(resp *http.Response, err error) http.RoundTripper {
	return roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if resp != nil {
			resp.Request = req
		}
		return resp, err
	})
}

func answerWith(status int, header http.Header, body io.ReadCloser) *http.Response {
	return &http.Response{StatusCode: status, Header: header, Body: body}
}

const earlierEnvelope = `{"code":"resource_exhausted","message":"slow down","bogus":true}`

// afterAnEarlierAttempt returns a request on a call whose holder and capture already
// hold an earlier attempt's record: a 503 with its Retry-After, and that answer's error
// body.
func afterAnEarlierAttempt(t *testing.T) (*http.Request, *answerHolder, *envelopeCapture) {
	t.Helper()
	holder := &answerHolder{}
	holder.last.Store(&answer{status: http.StatusServiceUnavailable, header: http.Header{"Retry-After": {"86400"}}})
	capture := &envelopeCapture{}
	capture.store([]byte(earlierEnvelope))
	ctx := context.WithValue(context.WithValue(context.Background(), answerKey{}, holder), envelopeKey{}, capture)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://exchange.test/fora.v1.ExchangeService/DiscoverResources", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	return req, holder, capture
}

func assertNoCapture(t *testing.T, capture *envelopeCapture) {
	t.Helper()
	if body, ok := capture.load(); ok {
		t.Errorf("the capture keeps an error body this round trip did not receive: %q", body)
	}
}

func readAll(t *testing.T, body io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read the body: %v", err)
	}
	return string(b)
}

func TestARoundTripThatGetsNoAnswerLeavesNoRecord(t *testing.T) {
	t.Parallel()
	req, holder, capture := afterAnEarlierAttempt(t)
	reset := errors.New("connection reset by peer")
	resp, err := answerRecorder{next: answering(nil, reset)}.RoundTrip(req)
	if resp != nil || !errors.Is(err, reset) {
		t.Fatalf("got %v, %v; want the transport's failure unchanged", resp, err)
	}
	if last := holder.last.Load(); last != nil {
		t.Errorf("the holder keeps an earlier attempt's answer: %+v", *last)
	}
	assertNoCapture(t, capture)
}

func TestARoundTripRecordsOnlyWhatItReceived(t *testing.T) {
	t.Parallel()

	t.Run("a success", func(t *testing.T) {
		t.Parallel()
		req, holder, capture := afterAnEarlierAttempt(t)
		ok := answerWith(http.StatusOK, http.Header{"Content-Type": {"application/json"}},
			io.NopCloser(strings.NewReader("{}")))
		if _, err := (answerRecorder{next: answering(ok, nil)}).RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		last := holder.last.Load()
		if last == nil || last.status != http.StatusOK || last.header != nil {
			t.Errorf("record = %+v, want status 200 and no header fields", last)
		}
		assertNoCapture(t, capture)
	})

	t.Run("an error answer", func(t *testing.T) {
		t.Parallel()
		req, holder, capture := afterAnEarlierAttempt(t)
		const envelope = `{"code":"unauthenticated","message":"the request is not signed"}`
		header := http.Header{"Content-Type": {"application/json"}, "Accept-Signature": {"sig1=()"}}
		got, err := answerRecorder{next: answering(
			answerWith(http.StatusUnauthorized, header, io.NopCloser(strings.NewReader(envelope))), nil)}.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		last := holder.last.Load()
		if last == nil || last.status != http.StatusUnauthorized {
			t.Fatalf("record = %+v, want status 401", last)
		}
		if v := last.header.Get("Retry-After"); v != "" {
			t.Errorf("the record keeps the earlier attempt's Retry-After %q", v)
		}
		header.Set("Accept-Signature", "changed after the round trip")
		if v := last.header.Get("Accept-Signature"); v != "sig1=()" {
			t.Errorf("Accept-Signature = %q; the record must hold a copy of the answer's fields", v)
		}
		if body, ok := capture.load(); !ok || string(body) != envelope {
			t.Errorf("capture = %q (%v), want this answer's envelope", body, ok)
		}
		if body := readAll(t, got.Body); body != envelope {
			t.Errorf("the body reads %q downstream, want it whole", body)
		}
	})
}

// An error answer can arrive and still store no body: one past the read cap, one in a
// coding this client did not ask for, or one with no body. The earlier attempt's body
// must not stand in for it.
func TestAnErrorAnswerThatStoresNoBodyLeavesNoEarlierOne(t *testing.T) {
	t.Parallel()
	pastTheCap := strings.Repeat("x", DefaultMaxRPCReadBytes+1)
	cases := []struct {
		name   string
		header http.Header
		body   io.ReadCloser
		reads  string
	}{
		{"past the read cap", http.Header{"Content-Type": {"application/json"}},
			io.NopCloser(strings.NewReader(pastTheCap)), pastTheCap},
		{"in a coding this client did not ask for", http.Header{"Content-Type": {"application/json"}, "Content-Encoding": {"br"}},
			io.NopCloser(bytes.NewReader([]byte{0x0b, 0x02})), "\x0b\x02"},
		{"with no body", http.Header{"Content-Type": {"application/json"}}, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			req, holder, capture := afterAnEarlierAttempt(t)
			got, err := answerRecorder{next: answering(answerWith(http.StatusServiceUnavailable, c.header, c.body), nil)}.RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			if last := holder.last.Load(); last == nil || last.status != http.StatusServiceUnavailable {
				t.Errorf("record = %+v, want this answer's status", last)
			}
			assertNoCapture(t, capture)
			if got.Body != nil {
				if body := readAll(t, got.Body); body != c.reads {
					t.Errorf("the body reads %d bytes downstream, want %d", len(body), len(c.reads))
				}
			}
		})
	}
}

func TestARequestNoVerbSentPassesThroughUntouched(t *testing.T) {
	t.Parallel()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://exchange.test/", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	body := io.NopCloser(strings.NewReader("draining"))
	want := answerWith(http.StatusServiceUnavailable, http.Header{"Retry-After": {"1"}}, body)
	got, err := answerRecorder{next: answering(want, nil)}.RoundTrip(req)
	if err != nil || got != want || got.Body != body {
		t.Fatalf("got %v, %v; want the transport's response untouched", got, err)
	}
}
