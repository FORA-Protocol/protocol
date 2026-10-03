package connect

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"

	connectrpc "connectrpc.com/connect"
)

// CallError.Code is the Connect code of the peer's ANSWER. connect-go hands back a
// *connect.Error for every failed call, but it cannot say whether a peer answered:
// a code it derived from a non-JSON HTTP status (a gateway's 502, a proxy's 403) is
// not marked as one the server sent, and neither is CodeUnavailable for a dial that
// never connected. Python and TypeScript both report a code for the first and none
// for the second, so this client records the fact itself: the interceptor below
// puts a holder on the call's context, and the client's transport writes the status
// of whatever response arrived into it. connect-go builds the HTTP request with the
// context the interceptor chain passed down, so the two meet without any verb
// knowing.

type answerKey struct{}

// answerHolder carries the HTTP status of the response that arrived, if any.
type answerHolder struct{ status atomic.Int64 }

// answeredError marks a failure whose call received an HTTP error status: the
// peer answered, so its Connect code is the peer's. It wraps rather than replaces
// the error, so errors.As still reaches the *connect.Error and its details.
type answeredError struct{ err error }

func (e *answeredError) Error() string { return e.err.Error() }
func (e *answeredError) Unwrap() error { return e.err }

// peerAnswered reports whether err came from a call the peer answered.
func peerAnswered(err error) bool {
	var a *answeredError
	return errors.As(err, &a)
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
			if holder.status.Load() >= http.StatusBadRequest {
				return resp, &answeredError{err: err}
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
// status of the response that came back into the call's holder.
type answerRecorder struct{ next http.RoundTripper }

func (r answerRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.next.RoundTrip(req)
	if resp != nil {
		if holder, ok := req.Context().Value(answerKey{}).(*answerHolder); ok {
			holder.status.Store(int64(resp.StatusCode))
		}
	}
	return resp, err
}
