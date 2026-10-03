package connect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// WithRawBody sends body in place of the request the verb would build — raw mode,
// for a test that must put a message on the wire the SDK would never assemble.
//
// The bytes are sent exactly as given, as the binary protobuf body of the call
// (application/proto, the encoding this client speaks). Nothing is filled in —
// not ver, not the idempotency key, not the requester — and none of the local
// refusals about the message apply: the recipient-shape check, the requester and
// signer checks, the registration_data bounds and the terms-digest read, the
// offer checks, and request validation. The call is still signed when a signer
// is configured, still runs the pre-signing hook, and its answer is still read
// under the read cap and decoded into the verb's response type, strict decoding
// included.
//
// The verb's own message argument is ignored and may be nil (Execute's offer may
// be the zero VerifiedOffer). A verb whose destination is read off the request —
// ReportUsage, Dispute, Register, GetAccountStatus — reads `exchange` by decoding
// the body as its request type, and routes it exactly as it routes a built
// request; a body that does not decode, or names no exchange, is refused as
// CallNotSent, because there is nowhere to send it.
//
// An empty body is a valid raw body: the empty message.
func WithRawBody(body []byte) CallOption {
	return func(c *callConfig) {
		c.rawBody = append([]byte(nil), body...)
		c.rawSet = true
	}
}

// rawBody is the request type of a raw call: bytes the codec passes through.
type rawBody struct{ b []byte }

// rawCodec sends a rawBody verbatim and decodes the answer with the binary
// protobuf codec, which keeps unknown fields for strict decoding to see. It takes
// the name of connect-go's own binary codec, so the call carries the content type
// a FORA server already accepts.
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }

func (rawCodec) Marshal(v any) ([]byte, error) {
	switch m := v.(type) {
	case *rawBody:
		return m.b, nil
	case proto.Message:
		return proto.Marshal(m)
	default:
		return nil, fmt.Errorf("connect: raw codec cannot marshal %T", v)
	}
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	m, ok := v.(proto.Message)
	if !ok {
		return fmt.Errorf("connect: raw codec cannot unmarshal into %T", v)
	}
	return proto.Unmarshal(data, m)
}

// rawLeg is what a raw call is sent over: the leg's signing HTTP client, and the
// client's Connect options with the validate interceptor left out and the raw
// codec last, so it wins over a codec the caller configured.
type rawLeg struct {
	http connectrpc.HTTPClient
	opts []connectrpc.ClientOption
}

func newRawLeg(cfg clientConfig, httpClient connectrpc.HTTPClient) rawLeg {
	opts := append([]connectrpc.ClientOption{
		connectrpc.WithInterceptors(interceptorStack(cfg, false)...),
		connectrpc.WithReadMaxBytes(DefaultMaxRPCReadBytes),
	}, cfg.connectOpts...)
	return rawLeg{http: httpClient, opts: append(opts, connectrpc.WithCodec(rawCodec{}))}
}

// rawCall sends body to procedure at baseURL and decodes the answer as Res.
func rawCall[Res any](ctx context.Context, leg rawLeg, op, baseURL, procedure string, body []byte) (*Res, error) {
	client := connectrpc.NewClient[rawBody, Res](leg.http, strings.TrimRight(baseURL, "/")+procedure, leg.opts...)
	resp, err := client.CallUnary(ctx, connectrpc.NewRequest(&rawBody{b: body}))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// rawExchange reads the `exchange` member of a raw body decoded as msg's type, for
// the verbs that route on it.
func rawExchange(op string, body []byte, msg proto.Message) (string, error) {
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, msg); err != nil {
		return "", notSent(op, fmt.Errorf("raw body does not decode as %s, so it names no exchange to route to: %w",
			msg.ProtoReflect().Descriptor().FullName(), err))
	}
	fd := msg.ProtoReflect().Descriptor().Fields().ByName("exchange")
	if fd == nil || fd.Kind() != protoreflect.StringKind {
		return "", notSent(op, errors.New("raw body's message carries no exchange field"))
	}
	exchange := msg.ProtoReflect().Get(fd).String()
	if exchange == "" {
		return "", notSent(op, errors.New("raw body names no exchange to route to"))
	}
	return exchange, nil
}
