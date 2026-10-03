package connect

import (
	"context"
	"fmt"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

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
// Both checks read the compiled descriptor, the one definition of the message
// shape the Python and TypeScript clients reach through the published strict JSON
// Schemas and the cross-field rules. Error answers are not affected: a refusal is
// read the same way in either mode.
//
// It is independent of WithValidation, which governs the REQUEST and, under
// ValidationStrict, re-validates the answer too; strict decoding adds the
// unknown-field check that validation does not make.
func WithStrictDecoding() ClientOption {
	return func(c *clientConfig) { c.strictDecoding = true }
}

// strictDecodeError marks an answer strict decoding refused, so sendError reports
// it as malformed rather than as a peer that did not answer.
type strictDecodeError struct{ err error }

func (e *strictDecodeError) Error() string { return "strict decoding: " + e.err.Error() }
func (e *strictDecodeError) Unwrap() error { return e.err }

// strictInterceptor applies the two checks to every successful unary answer.
type strictInterceptor struct{}

func (strictInterceptor) WrapUnary(next connectrpc.UnaryFunc) connectrpc.UnaryFunc {
	return func(ctx context.Context, req connectrpc.AnyRequest) (connectrpc.AnyResponse, error) {
		resp, err := next(ctx, req)
		if err != nil || resp == nil {
			return resp, err
		}
		msg, ok := resp.Any().(proto.Message)
		if !ok {
			return resp, nil
		}
		if err := checkStrict(msg); err != nil {
			return nil, &strictDecodeError{err: err}
		}
		return resp, nil
	}
}

func (strictInterceptor) WrapStreamingClient(next connectrpc.StreamingClientFunc) connectrpc.StreamingClientFunc {
	return next
}

func (strictInterceptor) WrapStreamingHandler(next connectrpc.StreamingHandlerFunc) connectrpc.StreamingHandlerFunc {
	return next
}

// checkStrict refuses msg if it carries an unknown field anywhere, or fails its
// protovalidate rules.
func checkStrict(msg proto.Message) error {
	if path := unknownFieldPath(msg.ProtoReflect(), string(msg.ProtoReflect().Descriptor().FullName())); path != "" {
		return fmt.Errorf("answer carries a field the contract does not define, in %s", path)
	}
	if err := helpers.Validate(msg); err != nil {
		return fmt.Errorf("answer breaks a rule of its message: %w", err)
	}
	return nil
}

// unknownFieldPath returns the path of the first message holding unknown fields, or
// "" when there is none. Every populated message is visited: singular, repeated and
// map values alike.
func unknownFieldPath(m protoreflect.Message, path string) string {
	if len(m.GetUnknown()) > 0 {
		return path
	}
	found := ""
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		here := path + "." + string(fd.Name())
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(k protoreflect.MapKey, mv protoreflect.Value) bool {
					found = unknownFieldPath(mv.Message(), fmt.Sprintf("%s[%v]", here, k.Interface()))
					return found == ""
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind {
				for i := 0; i < v.List().Len() && found == ""; i++ {
					found = unknownFieldPath(v.List().Get(i).Message(), fmt.Sprintf("%s[%d]", here, i))
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			found = unknownFieldPath(v.Message(), here)
		}
		return found == ""
	})
	return found
}
