package connect

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// Strict decoding of an error answer.
//
// connect-go parses a Connect error envelope itself and is lenient about it, as a reader
// must be: an unknown member is ignored, a code it does not know becomes one derived from
// the HTTP status, and a detail that does not decode is skipped. Under
// WithStrictDecoding those are findings, so the envelope is checked from the bytes that
// arrived, not from the error connect-go built out of them. The interceptor puts a
// capture on the call's context and the client's transport fills it with the error body,
// the same way the answer recorder reports the status.
//
// The checks are the ones the Python and TypeScript clients make, so one envelope gets
// one verdict in all three:
//
//   - a JSON error body is an object whose members are code, message and details, and
//     nothing else. A null member is read as absent, as proto-JSON reads it;
//   - code is present and is one of the sixteen Connect codes; message is a string;
//   - details is an array of objects whose members are type, value and debug. type is a
//     non-empty string, value is base64 (standard or URL alphabet, padded or not), and an
//     entry carries a value, a debug projection or both;
//   - for an entry of type fora.v1.ErrorDetail, the value decodes as an ErrorDetail with
//     no unknown field and passes its protovalidate rules, and the debug projection, when
//     present, decodes as proto-JSON with no unknown field and passes the same rules.
//
// A body that is empty or not JSON is not an envelope at all: it is a gateway or a proxy
// answering for the service, and its status classifies it in either mode.

// errorDetailType is the type name Connect writes on a FORA ErrorDetail entry.
const errorDetailType = "fora.v1.ErrorDetail"

// envelopeKey keys the capture the strict interceptor opens on a call's context.
type envelopeKey struct{}

// envelopeCapture holds the error body of the response that arrived, when there was one
// and it fit under the read cap.
type envelopeCapture struct {
	mu   sync.Mutex
	body []byte
	ok   bool
}

func (c *envelopeCapture) store(body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.body, c.ok = body, true
}

func (c *envelopeCapture) load() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.body, c.ok
}

// captureErrorBody copies an error response's body into the call's capture, when the
// strict interceptor opened one, and hands connect-go a body that reads the same bytes.
// A body past the read cap is not captured: connect-go refuses it on its own.
func captureErrorBody(req *http.Request, resp *http.Response) {
	capture, ok := req.Context().Value(envelopeKey{}).(*envelopeCapture)
	if !ok || resp.StatusCode < http.StatusBadRequest || resp.Body == nil {
		return
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, DefaultMaxRPCReadBytes+1))
	var rest io.Reader = resp.Body
	if err != nil {
		rest = errReader{err: err}
	}
	resp.Body = replayBody{Reader: io.MultiReader(bytes.NewReader(head), rest), Closer: resp.Body}
	if err != nil || len(head) > DefaultMaxRPCReadBytes {
		return
	}
	body, ok := decodedErrorBody(head, resp.Header.Get("Content-Encoding"))
	if ok {
		capture.store(body)
	}
}

// decodedErrorBody undoes the content coding a Connect server may put on an error body.
// connect-go asks for gzip and reads it; another coding is not one this client asked for.
func decodedErrorBody(body []byte, coding string) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(coding)) {
	case "", "identity":
		return body, true
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, false
		}
		plain, err := io.ReadAll(io.LimitReader(zr, DefaultMaxRPCReadBytes+1))
		if err != nil || len(plain) > DefaultMaxRPCReadBytes {
			return nil, false
		}
		return plain, true
	default:
		return nil, false
	}
}

type replayBody struct {
	io.Reader
	io.Closer
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// envelopeMembers and entryMembers are the members the Connect protocol defines.
var (
	envelopeMembers = map[string]bool{"code": true, "message": true, "details": true}
	entryMembers    = map[string]bool{"type": true, "value": true, "debug": true}
)

// connectCodes is the set of codes an error envelope may name, rendered by connect-go
// itself so the spelling cannot drift from it.
var connectCodes = func() map[string]bool {
	out := map[string]bool{}
	for c := connectrpc.CodeCanceled; c <= connectrpc.CodeUnauthenticated; c++ {
		out[c.String()] = true
	}
	return out
}()

// checkStrictEnvelope returns why body is not a Connect error envelope the contract
// accepts, or nil when it is one or is not JSON at all.
func checkStrictEnvelope(body []byte) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return nil
	}
	envelope, ok := jsonObject(trimmed)
	if !ok {
		return errors.New("error body is JSON but not a Connect error envelope object")
	}
	if name := firstUnknown(envelope, envelopeMembers); name != "" {
		return fmt.Errorf("error envelope carries %q, a member the Connect protocol does not define", name)
	}
	if err := checkEnvelopeCode(envelope); err != nil {
		return err
	}
	if raw, ok := present(envelope, "message"); ok {
		if _, isString := jsonString(raw); !isString {
			return errors.New("error envelope message is not a string")
		}
	}
	raw, ok := present(envelope, "details")
	if !ok {
		return nil
	}
	var details []json.RawMessage
	if err := json.Unmarshal(raw, &details); err != nil {
		return errors.New("error envelope details is not an array")
	}
	for i, entry := range details {
		if err := checkDetailEntry(i, entry); err != nil {
			return err
		}
	}
	return nil
}

func checkEnvelopeCode(envelope map[string]json.RawMessage) error {
	raw, ok := present(envelope, "code")
	if !ok {
		return errors.New("error envelope names no code")
	}
	code, isString := jsonString(raw)
	if !isString {
		return errors.New("error envelope code is not a string")
	}
	if !connectCodes[code] {
		return fmt.Errorf("error envelope code %q is not a Connect code", code)
	}
	return nil
}

// checkDetailEntry checks one details entry, and the ErrorDetail it carries when it
// carries one.
func checkDetailEntry(i int, raw json.RawMessage) error {
	entry, ok := jsonObject(raw)
	if !ok {
		return fmt.Errorf("details[%d] is not an object", i)
	}
	if name := firstUnknown(entry, entryMembers); name != "" {
		return fmt.Errorf("details[%d] carries %q, a member the Connect protocol does not define", i, name)
	}
	typeRaw, _ := present(entry, "type")
	typ, isString := jsonString(typeRaw)
	if !isString || typ == "" {
		return fmt.Errorf("details[%d] names no type", i)
	}
	var value []byte
	valueRaw, hasValue := present(entry, "value")
	if hasValue {
		text, isString := jsonString(valueRaw)
		decoded, err := decodeDetailValue(text)
		if !isString || err != nil {
			return fmt.Errorf("details[%d].value is not base64", i)
		}
		value = decoded
	}
	debug, hasDebug := present(entry, "debug")
	if !hasValue && !hasDebug {
		return fmt.Errorf("details[%d] carries neither a value nor a debug projection", i)
	}
	if typ != errorDetailType {
		return nil
	}
	if hasValue {
		msg := &forav1.ErrorDetail{}
		if err := proto.Unmarshal(value, msg); err != nil {
			return fmt.Errorf("details[%d].value does not decode as %s: %w", i, errorDetailType, err)
		}
		if err := helpers.CheckStrictMessage(msg); err != nil {
			return fmt.Errorf("details[%d].value: %w", i, err)
		}
	}
	if hasDebug {
		if err := checkDebugProjection(debug); err != nil {
			return fmt.Errorf("details[%d].debug: %w", i, err)
		}
	}
	return nil
}

// checkDebugProjection checks the proto-JSON rendering of an ErrorDetail: an unknown
// field, under either spelling of the field names, is refused by the parse.
func checkDebugProjection(raw json.RawMessage) error {
	if _, ok := jsonObject(raw); !ok {
		return errors.New("projection is not an object")
	}
	msg := &forav1.ErrorDetail{}
	if err := protojson.Unmarshal(raw, msg); err != nil {
		return fmt.Errorf("projection is not a %s the contract defines: %w", errorDetailType, err)
	}
	if err := helpers.CheckStrictMessage(msg); err != nil {
		return fmt.Errorf("projection: %w", err)
	}
	return nil
}

// decodeDetailValue reads a details value: base64 in the standard or the URL alphabet,
// padded or not, which is what the Python and TypeScript readers accept.
func decodeDetailValue(text string) ([]byte, error) {
	normalized := strings.NewReplacer("-", "+", "_", "/").Replace(strings.TrimRight(text, "="))
	return base64.RawStdEncoding.DecodeString(normalized)
}

// present returns a member, treating a JSON null as an absent member.
func present(obj map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	raw, ok := obj[name]
	if !ok || string(bytes.TrimSpace(raw)) == "null" {
		return nil, false
	}
	return raw, true
}

// jsonObject parses raw as a JSON object; false for any other JSON value.
func jsonObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, false
	}
	return obj, true
}

func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// firstUnknown returns the first member, in sorted order, that known does not name.
func firstUnknown(obj map[string]json.RawMessage, known map[string]bool) string {
	names := make([]string, 0, len(obj))
	for name := range obj {
		if !known[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}
