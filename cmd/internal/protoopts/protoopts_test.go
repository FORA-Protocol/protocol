package protoopts_test

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/FORA-Protocol/protocol/cmd/internal/protoopts"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/vocab/pricingunits"
)

// requestFiles returns fora/v1/vocab.proto, which declares the options these
// tests read, after descriptor.proto, which it imports, as a request lists them.
func requestFiles() []*descriptorpb.FileDescriptorProto {
	return []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(descriptorpb.File_google_protobuf_descriptor_proto),
		protodesc.ToFileDescriptorProto(forav1.File_fora_v1_vocab_proto),
	}
}

func mustResolver(t *testing.T) *protoregistry.Files {
	t.Helper()
	files, err := protoopts.BuildResolver(requestFiles())
	if err != nil {
		t.Fatalf("BuildResolver: %v", err)
	}
	return files
}

// unitOptions returns the options of Pricing.unit as a plugin sees them: the
// plugin binary does not know fora.v1's extensions, so their bytes arrive as
// unknown fields.
func unitOptions(t *testing.T) *descriptorpb.FieldOptions {
	t.Helper()
	unit := forav1.File_fora_v1_fora_proto.Messages().ByName("Pricing").Fields().ByName("unit")
	raw, err := proto.Marshal(unit.Options())
	if err != nil {
		t.Fatalf("marshal Pricing.unit options: %v", err)
	}
	bare := &descriptorpb.FieldOptions{}
	if err := (proto.UnmarshalOptions{Resolver: new(protoregistry.Types)}).Unmarshal(raw, bare); err != nil {
		t.Fatalf("unmarshal Pricing.unit options: %v", err)
	}
	if len(bare.ProtoReflect().GetUnknown()) == 0 {
		t.Fatal("the vocab option did not arrive as unknown bytes; the test would not exercise the resolver")
	}
	return bare
}

func TestBuildResolverKeepsEachPathOnce(t *testing.T) {
	files := requestFiles()
	withDuplicate := append(slices.Clone(files), files[0])
	reg, err := protoopts.BuildResolver(withDuplicate)
	if err != nil {
		t.Fatalf("BuildResolver refused a request that lists a dependency twice: %v", err)
	}
	if reg.NumFiles() != len(files) {
		t.Errorf("registry holds %d files, want %d", reg.NumFiles(), len(files))
	}
}

func TestFindExtensionMatchesNameAndNumber(t *testing.T) {
	files := mustResolver(t)
	ext := protoopts.FindExtension(files, "fora.v1.vocab", 50001)
	if ext == nil {
		t.Fatal("FindExtension did not find (fora.v1.vocab) 50001")
	}
	if ext.Kind() != protoreflect.StringKind || !ext.IsList() {
		t.Errorf("(fora.v1.vocab) resolved as %v list=%v, want a repeated string", ext.Kind(), ext.IsList())
	}
	if got := protoopts.FindExtension(files, "fora.v1.vocab", 50002); got != nil {
		t.Error("FindExtension matched (fora.v1.vocab) under another field number")
	}
	if got := protoopts.FindExtension(files, "fora.v1.no_such_option", 50001); got != nil {
		t.Error("FindExtension matched a name no file declares")
	}
}

func TestReadStringListDecodesUnknownOptionBytes(t *testing.T) {
	ext := protoopts.FindExtension(mustResolver(t), "fora.v1.vocab", 50001)
	got, err := protoopts.ReadStringList(ext, unitOptions(t))
	if err != nil {
		t.Fatalf("ReadStringList: %v", err)
	}
	if !slices.Equal(got, pricingunits.All) {
		t.Errorf("ReadStringList(Pricing.unit) = %v, want the registered units %v", got, pricingunits.All)
	}
}

func TestReadStringDecodesUnknownOptionBytes(t *testing.T) {
	ext := protoopts.FindExtension(mustResolver(t), "fora.v1.vocab_package", 50003)
	got, err := protoopts.ReadString(ext, unitOptions(t))
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got != "pricingunits" {
		t.Errorf("ReadString(Pricing.unit) = %q, want %q", got, "pricingunits")
	}
}

func TestReadersReturnNothingForAnAbsentOption(t *testing.T) {
	files := mustResolver(t)
	list := protoopts.FindExtension(files, "fora.v1.vocab", 50001)
	scalar := protoopts.FindExtension(files, "fora.v1.vocab_package", 50003)
	plain := &descriptorpb.FieldOptions{Deprecated: proto.Bool(true)}
	cases := []struct {
		name   string
		list   protoreflect.ExtensionTypeDescriptor
		scalar protoreflect.ExtensionTypeDescriptor
		opts   proto.Message
	}{
		{"option not set", list, scalar, plain},
		{"extension not declared", nil, nil, unitOptions(t)},
		{"no options", list, scalar, nil},
	}
	for _, c := range cases {
		values, err := protoopts.ReadStringList(c.list, c.opts)
		if err != nil || values != nil {
			t.Errorf("%s: ReadStringList = %v, %v; want nil, nil", c.name, values, err)
		}
		value, err := protoopts.ReadString(c.scalar, c.opts)
		if err != nil || value != "" {
			t.Errorf("%s: ReadString = %q, %v; want \"\", nil", c.name, value, err)
		}
	}
}
