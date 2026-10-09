package helpers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Registers the fora.admin.v1 messages, so CheckStrict resolves them by name the
	// way it resolves fora.v1, which this package already imports.
	_ "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
)

// ErrStrictViolation is wrapped by every refusal CheckStrict and CheckStrictMessage
// return: a message carrying a field the contract does not define, a value written
// in a form the canonical proto-JSON does not use, or a broken field-level or
// cross-field rule. Peer of Python StrictViolationError and TypeScript
// StrictViolation.
var ErrStrictViolation = errors.New("helpers: message refused by the strict contract")

// CheckStrict refuses payload, the proto-JSON of the message name (for example
// "fora.v1.WellKnownManifest"), unless the strict contract accepts it. It is the
// check a conformance harness runs on a document or an answer it read itself, and
// the one the document readers in package resolvers run.
//
// The checks are the ones the Python and TypeScript SDKs make against the
// published strict JSON Schema of the message and the cross-field rules, so one
// payload gets one verdict in all three:
//
//   - no member the message does not define, at any depth;
//   - every member under its proto field name. protojson also reads the
//     lowerCamelCase json_name, and the FORA wire does not use it;
//   - a 32-bit integer, a float, a double and a bool as a JSON number or boolean,
//     never as a string. protojson reads those strings, and no FORA sender writes
//     them. A 64-bit integer may be either, as canonical proto-JSON writes it;
//   - the message's field-level and cross-field rules, applied by protovalidate.
//
// A null member reads as absent, as proto-JSON reads it. A refusal wraps
// ErrStrictViolation. A name no registered message has, or a payload that is not
// JSON, is an error that does not: it says nothing about the payload's contract.
func CheckStrict(name string, payload []byte) error {
	mt, err := protoregistry.GlobalTypes.FindMessageByName(protoreflect.FullName(name))
	if err != nil {
		return fmt.Errorf("helpers: check strict: no message named %q: %w", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil || dec.More() {
		return fmt.Errorf("helpers: check strict: payload is not JSON")
	}
	msg := mt.New().Interface()
	if err := protojson.Unmarshal(payload, msg); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrStrictViolation, name, err)
	}
	if where := spellingViolation(mt.Descriptor(), value, ""); where != "" {
		return fmt.Errorf("%w: %s: %s", ErrStrictViolation, name, where)
	}
	return CheckStrictMessage(msg)
}

// CheckStrictMessage refuses a decoded message that carries a field the contract
// does not define, at any depth, or breaks one of its field-level or cross-field
// rules. The binary decode keeps a field this SDK does not know as unknown bytes
// and moves on, which is right for a reader that must accept a newer protocol
// version and wrong for a conformance check. A refusal wraps ErrStrictViolation.
//
// It is the second half of CheckStrict, and the whole of the check the client's
// strict decoding makes on a binary answer and on every ErrorDetail an error
// envelope carries: the shape is the compiled descriptor, read in one place.
func CheckStrictMessage(msg proto.Message) error {
	m := msg.ProtoReflect()
	if path := unknownFieldPath(m, string(m.Descriptor().FullName())); path != "" {
		return fmt.Errorf("%w: carries a field the contract does not define, in %s", ErrStrictViolation, path)
	}
	if err := Validate(msg); err != nil {
		return fmt.Errorf("%w: breaks a rule of its message: %w", ErrStrictViolation, err)
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

// spellingViolation returns where value, already accepted by protojson as a md
// message, uses a spelling the canonical proto-JSON does not: a member named by its
// json_name, or a 32-bit number or a bool written as a string. "" when there is
// none. Members are visited in sorted order, so the first one reported is stable.
func spellingViolation(md protoreflect.MessageDescriptor, value any, path string) string {
	obj, ok := value.(map[string]any)
	if !ok || strings.HasPrefix(string(md.FullName()), "google.protobuf.") {
		return ""
	}
	fields := md.Fields()
	for _, key := range slices.Sorted(maps.Keys(obj)) {
		here := path + "/" + key
		fd := fields.ByName(protoreflect.Name(key))
		if fd == nil {
			if alt := fields.ByJSONName(key); alt != nil {
				return fmt.Sprintf("at %s: the json_name of %q, which the FORA wire does not use", here, alt.Name())
			}
			continue // an unknown member: protojson has already refused it
		}
		if where := fieldSpelling(fd, obj[key], here); where != "" {
			return where
		}
	}
	return ""
}

func fieldSpelling(fd protoreflect.FieldDescriptor, value any, path string) string {
	switch {
	case value == nil:
		return ""
	case fd.IsMap():
		obj, _ := value.(map[string]any)
		for _, key := range slices.Sorted(maps.Keys(obj)) {
			if where := valueSpelling(fd.MapValue(), obj[key], path+"/"+key); where != "" {
				return where
			}
		}
	case fd.IsList():
		items, _ := value.([]any)
		for i, item := range items {
			if where := valueSpelling(fd, item, fmt.Sprintf("%s/%d", path, i)); where != "" {
				return where
			}
		}
	default:
		return valueSpelling(fd, value, path)
	}
	return ""
}

func valueSpelling(fd protoreflect.FieldDescriptor, value any, path string) string {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return spellingViolation(fd.Message(), value, path)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.FloatKind, protoreflect.DoubleKind, protoreflect.BoolKind:
		if _, isString := value.(string); isString {
			return fmt.Sprintf("at %s: a %s written as a string", path, fd.Kind())
		}
	default:
	}
	return ""
}
