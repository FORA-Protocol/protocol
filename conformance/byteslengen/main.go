// Command byteslengen emits bytes_max_len.json: per message, the JSON field names of
// every bytes field declaring (buf.validate.field).bytes.max_len, with the byte limit.
//
// It exists because protoschema-plugins renders that rule as a maxLength on the base64
// string that counts the padding characters, which is not exact: 32768 bytes and 32769
// bytes both encode to 43692 characters, so a token one byte over the limit passes the
// JSON Schema while Go protovalidate rejects it. merge_schema.py and gen_jsonschema.py
// read this manifest and rewrite the field's pattern to allow at most ceil(4n/3) data
// characters, which is exact, so the generated Pydantic/Zod models, the published
// schemas and the strict validators refuse exactly what the Go server refuses.
//
// Like requiredgen and uniquegen, this is a Go program because Go protovalidate is the
// authoritative view of the rules. Scope comes from conformance.Contract.
package main

import (
	"encoding/json"
	"os"

	protovalidate "buf.build/go/protovalidate"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/FORA-Protocol/protocol/conformance"
)

func main() {
	out := "bytes_max_len.json"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	limits := map[string]map[string]uint64{}
	conformance.EachMessage(func(md protoreflect.MessageDescriptor) {
		for i := 0; i < md.Fields().Len(); i++ {
			fd := md.Fields().Get(i)
			if n := bytesMaxLen(fd); n > 0 {
				if limits[string(md.Name())] == nil {
					limits[string(md.Name())] = map[string]uint64{}
				}
				limits[string(md.Name())][string(fd.Name())] = n
			}
		}
	})
	b, err := json.MarshalIndent(limits, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		panic(err)
	}
}

// bytesMaxLen returns the bytes.max_len rule of a singular bytes field, or 0.
func bytesMaxLen(fd protoreflect.FieldDescriptor) uint64 {
	if fd.Kind() != protoreflect.BytesKind || fd.IsList() {
		return 0
	}
	fr, err := protovalidate.ResolveFieldRules(fd)
	if err != nil || fr == nil {
		return 0
	}
	return fr.GetBytes().GetMaxLen()
}
