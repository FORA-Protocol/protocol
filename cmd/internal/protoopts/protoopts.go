// Package protoopts reads the custom options a protoc plugin acts on off the
// descriptors of its CodeGeneratorRequest.
//
// A generic plugin binary does not have fora.v1's extensions registered in its
// global proto registry, so reading options through the global registry would
// silently miss them, and linking the generated fora.v1 package instead would
// make a plugin compile against the output it is about to regenerate. So the
// functions here build a dynamicpb-backed extension resolver from the
// FileDescriptorProtos the request carries and re-parse a descriptor's raw
// options bytes through it. They read options structurally; nothing here parses
// CEL.
package protoopts

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// BuildResolver returns a registry of the request's files, so the extensions
// they declare can be found by name. A CodeGeneratorRequest may list a
// transitive dependency more than once, and protodesc.NewFiles rejects a
// duplicate path, so each path is kept once.
func BuildResolver(protoFiles []*descriptorpb.FileDescriptorProto) (*protoregistry.Files, error) {
	seen := make(map[string]struct{}, len(protoFiles))
	deduped := make([]*descriptorpb.FileDescriptorProto, 0, len(protoFiles))
	for _, pf := range protoFiles {
		if _, ok := seen[pf.GetName()]; ok {
			continue
		}
		seen[pf.GetName()] = struct{}{}
		deduped = append(deduped, pf)
	}
	return protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: deduped})
}

// FindExtension returns the extension named name with field number number, or
// nil when no file in files declares it. buf invokes a plugin once per
// code-generation request, and a request whose files do not import the file that
// declares an option legitimately carries no descriptor for it.
func FindExtension(
	files *protoregistry.Files,
	name protoreflect.FullName,
	number protoreflect.FieldNumber,
) protoreflect.ExtensionTypeDescriptor {
	var found protoreflect.ExtensionDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		exts := fd.Extensions()
		for i := 0; i < exts.Len(); i++ {
			ed := exts.Get(i)
			if ed.FullName() == name && ed.Number() == number {
				found = ed
				return false
			}
		}
		return true
	})
	if found == nil {
		return nil
	}
	return dynamicpb.NewExtensionType(found).TypeDescriptor()
}

// ReadStringList returns the values of the repeated string extension ext on
// opts, a descriptor's Options(). It returns nil and no error when opts carries
// none of them, or when ext or opts is nil, and an error only on a real decode
// failure, so a resolver or marshal fault never passes for an absent option.
func ReadStringList(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) ([]string, error) {
	if ext == nil || opts == nil {
		return nil, nil
	}
	m, err := decodeThroughExt(ext, opts)
	if err != nil {
		return nil, err
	}
	list := m.Get(ext).List()
	if list.Len() == 0 {
		return nil, nil
	}
	values := make([]string, 0, list.Len())
	for i := 0; i < list.Len(); i++ {
		values = append(values, list.Get(i).String())
	}
	return values, nil
}

// ReadString returns the value of the scalar string extension ext on opts, a
// descriptor's Options(), or "" when it is unset or when ext or opts is nil.
func ReadString(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) (string, error) {
	if ext == nil || opts == nil {
		return "", nil
	}
	m, err := decodeThroughExt(ext, opts)
	if err != nil {
		return "", err
	}
	if !m.Has(ext) {
		return "", nil
	}
	return m.Get(ext).String(), nil
}

// decodeThroughExt re-parses opts through a resolver that knows the dynamic
// extension ext, so its bytes are decoded into the extension rather than left
// in UnknownFields.
func decodeThroughExt(ext protoreflect.ExtensionTypeDescriptor, opts proto.Message) (protoreflect.Message, error) {
	raw, err := proto.Marshal(opts)
	if err != nil {
		return nil, fmt.Errorf("marshal options: %w", err)
	}
	decoded := opts.ProtoReflect().New().Interface()
	if err := (proto.UnmarshalOptions{Resolver: extResolver{ext: ext}}).Unmarshal(raw, decoded); err != nil {
		return nil, fmt.Errorf("unmarshal options through the extension resolver: %w", err)
	}
	return decoded.ProtoReflect(), nil
}

// extResolver adapts a single ExtensionTypeDescriptor to the
// protoregistry.ExtensionTypeResolver interface Unmarshal takes.
type extResolver struct {
	ext protoreflect.ExtensionTypeDescriptor
}

// FindExtensionByName returns the extension when field names it.
func (r extResolver) FindExtensionByName(field protoreflect.FullName) (protoreflect.ExtensionType, error) {
	if field == r.ext.FullName() {
		return r.ext.Type(), nil
	}
	return nil, protoregistry.NotFound
}

// FindExtensionByNumber returns the extension when message and field identify it.
func (r extResolver) FindExtensionByNumber(
	message protoreflect.FullName,
	field protoreflect.FieldNumber,
) (protoreflect.ExtensionType, error) {
	if message == r.ext.ContainingMessage().FullName() && field == r.ext.Number() {
		return r.ext.Type(), nil
	}
	return nil, protoregistry.NotFound
}
