package connect

import (
	"context"
	"errors"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// WithStrictDecoding makes every RPC answer pass two checks before a verb hands it
// back, and refuses it as CallMalformed otherwise:
//
//   - no unknown field at any depth. The default decode keeps a field this SDK does
//     not know as unknown bytes and moves on, which is right for a reader that must
//     accept a newer protocol version and wrong for a conformance check, where an
//     unknown field is a server sending something the contract does not define;
//   - the proto's own rules, field-level and cross-field, applied by protovalidate.
//
// Both checks are helpers.CheckStrictMessage, and read the compiled descriptor: the
// one definition of the message shape, which the document readers and
// helpers.CheckStrict also read, and which the Python and TypeScript clients reach
// through the published strict JSON Schemas and the cross-field rules.
//
// An error answer is checked too, from the bytes that arrived: the Connect error
// envelope (its members, a known Connect code, well-formed details) and every
// ErrorDetail it carries, both the binary value and the debug projection, against
// the same two checks. An envelope that fails is refused as CallMalformed, and
// CallError.Code still holds the Connect code the peer answered with; the detail is
// not reported, because it is part of what was refused. A body that is empty or not
// JSON is a gateway's answer rather than an envelope, and its status classifies it
// as before. Without this option an error answer is read leniently, as connect-go
// reads it.
//
// It is independent of WithValidation, which governs the REQUEST and, under
// ValidationStrict, re-validates the answer too; strict decoding adds the
// unknown-field check that validation does not make.
func WithStrictDecoding() ClientOption {
	return func(c *clientConfig) { c.strictDecoding = true }
}

// strictDecodeError marks an answer strict decoding refused, so sendError reports
// it as malformed rather than as a peer that did not answer. For an error envelope
// it also carries the Connect code the peer answered with, which the refusal keeps.
type strictDecodeError struct {
	err      error
	envelope bool
	code     connectrpc.Code
}

func (e *strictDecodeError) Error() string { return "strict decoding: " + e.err.Error() }
func (e *strictDecodeError) Unwrap() error { return e.err }

// strictInterceptor applies the two checks to every successful unary answer, and
// the envelope checks to every error answer.
type strictInterceptor struct{}

func (strictInterceptor) WrapUnary(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		capture := &envelopeCapture{}
		resp, err := next(context.WithValue(ctx, envelopeKey{}, capture), req)
		if err != nil {
			return resp, strictErrorAnswer(err, capture)
		}
		if resp == nil {
			return resp, nil
		}
		msg, ok := resp.Any().(proto.Message)
		if !ok {
			return resp, nil
		}
		if err := helpers.CheckStrictMessage(msg); err != nil {
			return nil, &strictDecodeError{err: err}
		}
		return resp, nil
	}
}

// strictErrorAnswer returns the refusal for an error answer whose envelope fails the
// strict checks, and err unchanged otherwise. Only a Connect error the peer's body
// produced is checked: a local failure has no envelope, and an error body that did
// not fit under the read cap is never captured.
func strictErrorAnswer(err error, capture *envelopeCapture) error {
	var cerr *connectrpc.Error
	if !errors.As(err, &cerr) {
		return err
	}
	body, ok := capture.load()
	if !ok {
		return err
	}
	if verr := checkStrictEnvelope(body); verr != nil {
		return &strictDecodeError{err: verr, envelope: true, code: cerr.Code()}
	}
	return err
}

func (strictInterceptor) WrapStreamingClient(next connectrpc.StreamingClientFunc) connectrpc.StreamingClientFunc {
	return next
}

func (strictInterceptor) WrapStreamingHandler(next connectrpc.StreamingHandlerFunc) connectrpc.StreamingHandlerFunc {
	return next
}
