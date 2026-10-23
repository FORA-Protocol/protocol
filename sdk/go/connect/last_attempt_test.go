package connect_test

// A call an interceptor retries reports its last attempt. The client records what each
// request it sends receives, and clears that record before every request, so a failure
// never describes an earlier attempt: not its status, not its header fields, not the
// judgment that the peer answered, and, under strict decoding, not its error envelope.
//
// The base transport is scripted rather than served, so each attempt's outcome is exact;
// the client composes its own transports on top of it, so all of them run.

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	foraconnect "github.com/FORA-Protocol/protocol/sdk/go/connect"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// attempt is what the scripted transport does with one request: answer it, or fail it
// the way a dropped connection does.
type attempt func(*http.Request) (*http.Response, error)

// answers serves one answer: the status, the content type, the body and each header
// line in order.
func answers(status int, contentType, body string, lines ...fieldLine) attempt {
	return func(req *http.Request) (*http.Response, error) {
		header := http.Header{"Content-Type": {contentType}}
		for _, line := range lines {
			header.Add(line.name, line.value)
		}
		return &http.Response{
			Status:        strconv.Itoa(status) + " " + http.StatusText(status),
			StatusCode:    status,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        header,
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	}
}

// drops fails the request with no answer at all, as a connection reset does.
func drops(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF }

// scripted answers the nth request with the nth attempt, and repeats the last attempt
// for any request past the script.
type scripted struct {
	attempts []attempt
	sent     atomic.Int32
}

func (s *scripted) RoundTrip(req *http.Request) (*http.Response, error) {
	n := int(s.sent.Add(1)) - 1
	if req.Body != nil {
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
	}
	return s.attempts[min(n, len(s.attempts)-1)](req)
}

// retryOnce is an application interceptor that sends a failed call once more.
var retryOnce = connectrpc.UnaryInterceptorFunc(func(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		if resp, err := next(ctx, req); err == nil {
			return resp, nil
		}
		return next(ctx, req)
	}
})

// retriedFailure runs one Discover through retryOnce against the two attempts and
// returns its typed failure.
func retriedFailure(t *testing.T, first, second attempt, opts ...foraconnect.ClientOption) *foraconnect.CallError {
	t.Helper()
	script := &scripted{attempts: []attempt{first, second}}
	opts = append(opts,
		foraconnect.WithHTTPClient(&http.Client{Transport: script}),
		foraconnect.WithInterceptors(retryOnce))
	_, err := foraconnect.NewClient("https://exchange.test", opts...).
		Discover(context.Background(), &forav1.ResourceQuery{Exchange: "exchange.test"})
	if sent := script.sent.Load(); sent != 2 {
		t.Fatalf("the call sent %d requests, want 2", sent)
	}
	return callErrorFrom(t, err)
}

var retryAfterLine = fieldLine{"Retry-After", "86400"}

func TestARetriedCallReportsItsLastAttempt(t *testing.T) {
	t.Parallel()

	t.Run("an answer and then none carries nothing of the answer", func(t *testing.T) {
		t.Parallel()
		cerr := retriedFailure(t,
			answers(http.StatusServiceUnavailable, "text/plain", "draining", retryAfterLine),
			drops)
		if cerr.Kind != foraconnect.CallUnreachable {
			t.Errorf("Kind = %v, want CallUnreachable: %v", cerr.Kind, cerr)
		}
		if cerr.Status != 0 {
			t.Errorf("Status = %d, want 0: the last request got no answer", cerr.Status)
		}
		if cerr.Header != nil {
			t.Errorf("Header = %v, want nil", cerr.Header)
		}
		if cerr.Code != 0 {
			t.Errorf("Code = %v, want none: no peer answered the last request", cerr.Code)
		}
		if msg := cerr.Error(); strings.Contains(msg, "HTTP 503") {
			t.Errorf("the message names the earlier attempt's status: %s", msg)
		}
	})

	t.Run("two answers report the second, and only its fields", func(t *testing.T) {
		t.Parallel()
		cerr := retriedFailure(t,
			answers(http.StatusServiceUnavailable, "text/plain", "draining", retryAfterLine),
			answers(http.StatusUnauthorized, "application/json", unauthenticatedEnvelope, acceptSignatureLine))
		if cerr.Kind != foraconnect.CallRefused || cerr.Status != http.StatusUnauthorized {
			t.Fatalf("got %v with status %d, want a 401 refusal: %v", cerr.Kind, cerr.Status, cerr)
		}
		if cerr.Code != connectrpc.CodeUnauthenticated {
			t.Errorf("Code = %v, want unauthenticated", cerr.Code)
		}
		if got := fieldValue(cerr.Header, helpers.AcceptSignatureHeader); got != helpers.AcceptSignature(false) {
			t.Errorf("Accept-Signature = %q, want %q", got, helpers.AcceptSignature(false))
		}
		if got := cerr.Header.Values("Retry-After"); got != nil {
			t.Errorf("Retry-After = %q, want none: it was the earlier attempt's", got)
		}
	})

	t.Run("under strict decoding an earlier envelope is not judged in place of the last request", func(t *testing.T) {
		t.Parallel()
		cerr := retriedFailure(t,
			answers(http.StatusTooManyRequests, "application/json",
				`{"code":"resource_exhausted","message":"slow down","bogus":true}`, retryAfterLine),
			drops,
			foraconnect.WithStrictDecoding())
		if cerr.Kind != foraconnect.CallUnreachable {
			t.Errorf("Kind = %v, want CallUnreachable: the last request got no answer to refuse: %v", cerr.Kind, cerr)
		}
		if cerr.Status != 0 || cerr.Code != 0 {
			t.Errorf("Status = %d, Code = %v; want neither", cerr.Status, cerr.Code)
		}
	})
}
