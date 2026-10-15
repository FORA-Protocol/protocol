package conformance

// The published JSON Schemas (gen/jsonschema/) against the proto.
//
// The drift gate proves the committed schemas are what the generator emits today; this
// proves what the generator emits is right about the contract, read from the compiled
// descriptors, independently of the generator's own guards:
//
//   - exactly one default and one strict file per contract message, and no other file;
//   - each schema's properties are the message's proto field names (the snake_case wire
//     naming), in both variants;
//   - the strict variant closes every message object it defines, the default variant
//     closes none, and neither closes a google.protobuf.Struct field;
//   - a 64-bit integer field accepts the decimal-string form canonical proto-JSON emits.
//
// The verdicts themselves (a value accepted or refused) are asserted against the
// conformance corpus by gen/python/tests/test_jsonschema.py and
// sdk/ts/tests/jsonschema.test.ts; Go has no draft 2020-12 validator in this module.

import (
	"encoding/json"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/FORA-Protocol/protocol/gen/jsonschema"
)

type schemaDoc struct {
	ID         string                     `json:"$id"`
	Properties map[string]json.RawMessage `json:"properties"`
	Defs       map[string]json.RawMessage `json:"$defs"`
	Additional *bool                      `json:"additionalProperties"`
}

func loadSchema(t *testing.T, name string, strict bool) schemaDoc {
	t.Helper()
	b, err := jsonschema.Load(name, strict)
	if err != nil {
		t.Fatal(err)
	}
	var d schemaDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d
}

func TestPublishedSchemasCoverExactlyTheContract(t *testing.T) {
	var want []string
	EachMessage(func(md protoreflect.MessageDescriptor) {
		n := string(md.FullName())
		want = append(want, n+".schema.json", n+".schema.strict.json")
	})
	got, err := fs.Glob(jsonschema.FS, "*.json")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("gen/jsonschema/ does not match the contract messages:\n got %d files\nwant %d files", len(got), len(want))
	}
	if _, err := jsonschema.Load("fora.v1.NoSuchMessage", true); err == nil {
		t.Fatal("Load accepted an unknown message name")
	}
	if _, err := jsonschema.Load("../jsonschema/fora.v1.ResourceResponse", false); err == nil {
		t.Fatal("Load accepted a path outside the schema directory")
	}
}

func TestPublishedSchemasMatchTheDescriptor(t *testing.T) {
	EachMessage(func(md protoreflect.MessageDescriptor) {
		name := string(md.FullName())
		for _, strict := range []bool{false, true} {
			d := loadSchema(t, name, strict)
			checkFields(t, d, md)
			checkClosed(t, d, strict)
		}
	})
}

// checkFields asserts the property set is the proto field names, that a Struct field
// is an open object and that a 64-bit integer admits its decimal-string form.
func checkFields(t *testing.T, d schemaDoc, md protoreflect.MessageDescriptor) {
	t.Helper()
	fields := md.Fields()
	if len(d.Properties) != fields.Len() {
		t.Errorf("%s: %d properties, the message has %d fields", d.ID, len(d.Properties), fields.Len())
	}
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		raw, ok := d.Properties[string(fd.Name())]
		if !ok {
			t.Errorf("%s: no property for field %s", d.ID, fd.Name())
			continue
		}
		var prop map[string]any
		if err := json.Unmarshal(raw, &prop); err != nil {
			t.Fatal(err)
		}
		if fd.Message() != nil && fd.Message().FullName() == "google.protobuf.Struct" {
			if prop["type"] != "object" || prop["additionalProperties"] != nil {
				t.Errorf("%s: Struct field %s is not an open object: %s", d.ID, fd.Name(), raw)
			}
		}
		switch fd.Kind() {
		case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
			protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
			if !hasStringArm(prop) {
				t.Errorf("%s: int64 field %s has no decimal-string form: %s", d.ID, fd.Name(), raw)
			}
		}
	}
}

func hasStringArm(prop map[string]any) bool {
	arms, _ := prop["anyOf"].([]any)
	for _, a := range arms {
		if arm, ok := a.(map[string]any); ok && arm["type"] == "string" {
			return true
		}
	}
	return false
}

// checkClosed asserts the unknown-field policy of every message object in the file.
func checkClosed(t *testing.T, d schemaDoc, strict bool) {
	t.Helper()
	closed := func(where string, additional *bool) {
		switch {
		case strict && (additional == nil || *additional):
			t.Errorf("%s: %s is not closed in the strict variant", d.ID, where)
		case !strict && additional != nil:
			t.Errorf("%s: %s sets additionalProperties in the default variant", d.ID, where)
		}
	}
	closed("the root message", d.Additional)
	for name, raw := range d.Defs {
		var def schemaDoc
		if err := json.Unmarshal(raw, &def); err != nil {
			t.Fatal(err)
		}
		closed(name, def.Additional)
	}
}
