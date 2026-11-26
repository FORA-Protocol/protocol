package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"

	compv1 "github.com/FORA-Protocol/protocol/gen/go/comp/v1"
	foraadminv1 "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// pluginBinary is the plugin, built once. Every test drives it as buf does: a
// CodeGeneratorRequest on stdin, a CodeGeneratorResponse on stdout. The binary
// does not link fora.v1, so the version options reach it as unknown bytes, as
// they do under buf.
var pluginBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "protoc-gen-foraversion")
	if err != nil {
		fmt.Fprintln(os.Stderr, "make a directory for the plugin:", err)
		os.Exit(1)
	}
	pluginBinary = filepath.Join(dir, "protoc-gen-foraversion")
	build := exec.CommandContext(context.Background(), "go", "build", "-o", pluginBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build the plugin:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// moduleFiles are the module's proto files, every one of which buf asks the
// plugin to generate under strategy all.
func moduleFiles() []protoreflect.FileDescriptor {
	return []protoreflect.FileDescriptor{
		compv1.File_comp_v1_comp_proto,
		foraadminv1.File_fora_admin_v1_admin_proto,
		forav1.File_fora_v1_fora_proto,
		forav1.File_fora_v1_vocab_proto,
	}
}

// request builds the CodeGeneratorRequest for generate: those files to generate,
// and every file they import, dependencies first.
func request(generate ...protoreflect.FileDescriptor) *pluginpb.CodeGeneratorRequest {
	req := &pluginpb.CodeGeneratorRequest{}
	seen := map[string]bool{}
	var visit func(fd protoreflect.FileDescriptor)
	visit = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		for i := 0; i < fd.Imports().Len(); i++ {
			visit(fd.Imports().Get(i).FileDescriptor)
		}
		req.ProtoFile = append(req.ProtoFile, protodesc.ToFileDescriptorProto(fd))
	}
	for _, fd := range generate {
		visit(fd)
		req.FileToGenerate = append(req.FileToGenerate, fd.Path())
	}
	return req
}

// fileProto returns the request's descriptor for the file at path.
func fileProto(t *testing.T, req *pluginpb.CodeGeneratorRequest, path string) *descriptorpb.FileDescriptorProto {
	t.Helper()
	for _, f := range req.GetProtoFile() {
		if f.GetName() == path {
			if f.Options == nil {
				f.Options = &descriptorpb.FileOptions{}
			}
			return f
		}
	}
	t.Fatalf("the request carries no %s", path)
	return nil
}

// generate runs the plugin on req and returns its response.
func generate(t *testing.T, req *pluginpb.CodeGeneratorRequest) *pluginpb.CodeGeneratorResponse {
	t.Helper()
	in, err := proto.Marshal(req)
	if err != nil {
		t.Fatalf("marshal the request: %v", err)
	}
	run := exec.CommandContext(t.Context(), pluginBinary)
	run.Stdin = bytes.NewReader(in)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("run the plugin: %v", err)
	}
	resp := &pluginpb.CodeGeneratorResponse{}
	if err := proto.Unmarshal(out, resp); err != nil {
		t.Fatalf("unmarshal the response: %v", err)
	}
	return resp
}

// refusal runs the plugin on req and returns its error, failing the test when
// the plugin accepts the request or writes a file anyway.
func refusal(t *testing.T, req *pluginpb.CodeGeneratorRequest) string {
	t.Helper()
	resp := generate(t, req)
	if resp.GetError() == "" {
		t.Fatalf("the plugin accepted the request and wrote %d files", len(resp.GetFile()))
	}
	if len(resp.GetFile()) != 0 {
		t.Errorf("the plugin refused the request but still wrote %d files", len(resp.GetFile()))
	}
	return resp.GetError()
}

func assertReason(t *testing.T, got string, reasons ...string) {
	t.Helper()
	for _, reason := range reasons {
		if !strings.Contains(got, reason) {
			t.Errorf("the refusal %q does not say %q", got, reason)
		}
	}
}

func TestEmitsTheCommittedConstants(t *testing.T) {
	resp := generate(t, request(moduleFiles()...))
	if resp.GetError() != "" {
		t.Fatalf("the plugin refused the module: %s", resp.GetError())
	}
	committed := map[string]string{
		"go/fora/v1/fora_version.pb.go": "../../gen/go/fora/v1/fora_version.pb.go",
		"ts/wire/version.ts":            "../../gen/ts/wire/version.ts",
		"python/wire/version.py":        "../../gen/python/wire/version.py",
	}
	if len(resp.GetFile()) != len(committed) {
		t.Errorf("the plugin wrote %d files, want %d", len(resp.GetFile()), len(committed))
	}
	for _, f := range resp.GetFile() {
		path, ok := committed[f.GetName()]
		if !ok {
			t.Errorf("the plugin wrote %s, which nothing expects", f.GetName())
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read the committed %s: %v", path, err)
		}
		if f.GetContent() != string(want) {
			t.Errorf("%s differs from the committed %s; regenerate gen/", f.GetName(), path)
		}
	}
}

func TestIgnoresARequestThatDeclaresNoVersionOption(t *testing.T) {
	resp := generate(t, request(compv1.File_comp_v1_comp_proto))
	if resp.GetError() != "" || len(resp.GetFile()) != 0 {
		t.Errorf("got error %q and %d files, want neither", resp.GetError(), len(resp.GetFile()))
	}
}

func TestRefusesAFileThatSetsOnlyOneOption(t *testing.T) {
	req := request(moduleFiles()...)
	proto.ClearExtension(fileProto(t, req, "fora/v1/fora.proto").GetOptions(), forav1.E_WellKnownManifestVersion)
	assertReason(t, refusal(t, req), "fora/v1/fora.proto", "sets only one of the two version options")
}

func TestRefusesAModuleWhereNoFileSetsTheOptions(t *testing.T) {
	req := request(moduleFiles()...)
	opts := fileProto(t, req, "fora/v1/fora.proto").GetOptions()
	proto.ClearExtension(opts, forav1.E_ProtocolVersion)
	proto.ClearExtension(opts, forav1.E_WellKnownManifestVersion)
	assertReason(t, refusal(t, req), "no file sets")
}

func TestRefusesASecondFileThatSetsTheOptions(t *testing.T) {
	req := request(moduleFiles()...)
	opts := fileProto(t, req, "fora/admin/v1/admin.proto").GetOptions()
	proto.SetExtension(opts, forav1.E_ProtocolVersion, "1.0")
	proto.SetExtension(opts, forav1.E_WellKnownManifestVersion, "1.0")
	assertReason(t, refusal(t, req), "more than one file", "fora/v1/fora.proto", "fora/admin/v1/admin.proto")
}

func TestRefusesAVersionThatIsNotMajorMinor(t *testing.T) {
	for _, version := range []string{"1", "1.0.0", "v1.0", "01.0", "1.00", " 1.0", "1.0 ", "1.-1", "1,0", "١.٠"} {
		for _, ext := range []protoreflect.ExtensionType{forav1.E_ProtocolVersion, forav1.E_WellKnownManifestVersion} {
			req := request(moduleFiles()...)
			proto.SetExtension(fileProto(t, req, "fora/v1/fora.proto").GetOptions(), ext, version)
			assertReason(t, refusal(t, req), string(ext.TypeDescriptor().FullName()), "is not MAJOR.MINOR")
		}
	}
}

func TestRefusesAVersionOptionDeclaredAsAnythingButAString(t *testing.T) {
	req := request(moduleFiles()...)
	for _, ext := range fileProto(t, req, "fora/v1/vocab.proto").GetExtension() {
		if ext.GetName() == "protocol_version" {
			ext.Type = descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum()
		}
	}
	assertReason(t, refusal(t, req), "fora.v1.protocol_version", "must be declared as an optional string")
}

// TestNeverLinksItsOwnOutput holds the reason the options are read dynamically:
// a plugin that linked the generated packages would compile against the output
// it is about to regenerate.
func TestNeverLinksItsOwnOutput(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) == 0 {
		t.Fatal("go list -deps listed nothing; the check would pass vacuously")
	}
	for _, dep := range deps {
		if strings.HasPrefix(dep, "github.com/FORA-Protocol/protocol/gen/") {
			t.Errorf("the plugin links %s, a package it generates", dep)
		}
	}
}
