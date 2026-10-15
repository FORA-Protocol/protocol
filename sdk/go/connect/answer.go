package connect

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"

	connectrpc "connectrpc.com/connect"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/failure"
)

// CallError.Code is the Connect code of the peer's ANSWER. connect-go hands back a
// *connect.Error for every failed call, but it cannot say whether a peer answered:
// a code it derived from a non-JSON HTTP status (a gateway's 502, a proxy's 403) is
// not marked as one the server sent, and neither is CodeUnavailable for a dial that
// never connected. Python and TypeScript both report a code for the first and none
// for the second, so this client records the fact itself: the interceptor below
// puts a holder on the call's context, and the client's transport writes the
// answer that arrived into it. connect-go builds the HTTP request with the context
// the interceptor chain passed down, so the two meet without any verb knowing.
//
// The same record supplies CallError.Status and CallError.Header. connect-go's own
// Error.Meta() cannot: it is filled only when the body decoded as a Connect error
// envelope, so a gateway's 503 and its Retry-After, which arrive as plain text,
// would carry nothing.

type answerKey struct{}

// answer is the response that arrived on a call: its status, and the header fields
// a failure may carry for it (failure.RefusalHeader).
type answer struct {
	status int
	header http.Header
}

// answerHolder carries the answer that arrived on a call, if any. It is written by
// the transport and read by the interceptor, so it is held atomically rather than
// relying on the two running on one goroutine.
type answerHolder struct{ last atomic.Pointer[answer] }

// answeredError marks a failure whose call received an HTTP error status: the
// peer answered, so its Connect code is the peer's, and the status and header
// fields are those of its refusal. It wraps rather than replaces the error, so
// errors.As still reaches the *connect.Error and its details.
type answeredError struct {
	err    error
	status int
	header http.Header
}

func (e *answeredError) Error() string { return e.err.Error() }
func (e *answeredError) Unwrap() error { return e.err }

// peerAnswer returns the error answer err came from, when the peer answered the
// call with one.
func peerAnswer(err error) (*answeredError, bool) {
	var a *answeredError
	if errors.As(err, &a) {
		return a, true
	}
	return nil, false
}

// answerInterceptor is the outermost client interceptor: it opens the holder the
// transport writes into, and marks a failure the peer answered.
type answerInterceptor struct{}

func (answerInterceptor) WrapUnary(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		holder := &answerHolder{}
		resp, err := next(context.WithValue(ctx, answerKey{}, holder), req)
		// Only an error status is an answer with a code. An OK status that still failed
		// is a body this client could not accept (the read cap, strict decoding), and a
		// 3xx is a redirect this client refused to follow — a server that did not
		// answer the call. Neither carries a verdict of the peer's.
		if err != nil {
			if last := holder.last.Load(); last != nil && last.status >= http.StatusBadRequest {
				return resp, &answeredError{err: err, status: last.status, header: last.header}
			}
		}
		return resp, err
	}
}

func (answerInterceptor) WrapStreamingClient(next connectrpc.StreamingClientFunc) connectrpc.StreamingClientFunc {
	return next
}

func (answerInterceptor) WrapStreamingHandler(next connectrpc.StreamingHandlerFunc) connectrpc.StreamingHandlerFunc {
	return next
}

// answerRecorder is the outermost RoundTripper on every signed leg: it records the
// answer that came back into the call's holder, and, under strict decoding, the
// error body into the call's envelope capture. The header fields are copied here,
// under failure.RefusalHeader, so the record holds nothing of a redirect's and
// keeps no reference to a response the caller will close.
type answerRecorder struct{ next http.RoundTripper }

func (r answerRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if resp != nil {
		if holder, ok := req.Context().Value(answerKey{}).(*answerHolder); ok {
			holder.last.Store(&answer{
				status: resp.StatusCode,
				header: failure.RefusalHeader(resp.StatusCode, resp.Header),
			})
		}
		captureErrorBody(req, resp)
	}
	return resp, err
}
