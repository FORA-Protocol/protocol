// Command protoc-gen-foraversion is a buf/protoc plugin that emits the FORA
// protocol version and the /.well-known/fora.json document version as constants
// for Go, TypeScript and Python.
//
// Both values are authored once, as the file options (fora.v1.protocol_version)
// and (fora.v1.well_known_manifest_version) that fora/v1/fora.proto sets; the
// "Protocol version" block there says what each one versions and how a receiver
// treats it. Exactly one file of the request may set the options, it must set
// both, and each value must be a canonical MAJOR.MINOR. buf runs this plugin with
// strategy all, so one request sees every file of the module and "exactly one
// file" holds across all of it.
//
// The Go constants go into the generated package of the file that sets the
// options, beside protoc-gen-go's output (paths=source_relative); the TypeScript
// and Python constants go into the wire modules of the generated types export.
// The options are read through cmd/internal/protoopts, so this plugin never links
// the generated fora.v1 package, which is its own output.
package main

import (
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/types/pluginpb"
)

func main() {
	protogen.Options{}.Run(run)
}

// run emits the version constants when the request declares the two options.
func run(gen *protogen.Plugin) error {
	gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)
	exts, declared, err := versionExtensions(gen.Request.GetProtoFile())
	if err != nil || !declared {
		return err
	}
	src, err := versionSource(gen.Files, exts)
	if err != nil {
		return err
	}
	emit(gen, src)
	return nil
}
