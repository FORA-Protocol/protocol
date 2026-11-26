package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/FORA-Protocol/protocol/cmd/internal/protoopts"
)

// The two options, as fora/v1/vocab.proto declares them.
const (
	protocolExtName   = "fora.v1.protocol_version"
	protocolExtNumber = 50007
	manifestExtName   = "fora.v1.well_known_manifest_version"
	manifestExtNumber = 50008
)

// canonicalVersion is a MAJOR.MINOR with no sign, no padding and no leading zero,
// the only spelling a version option may carry.
var canonicalVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// versionExts holds the two resolved extensions.
type versionExts struct {
	protocol protoreflect.ExtensionTypeDescriptor
	manifest protoreflect.ExtensionTypeDescriptor
}

// source is the one file that sets the options, with the two values it sets.
type source struct {
	file     *protogen.File
	protocol string
	manifest string
}

// versionExtensions resolves the two options from the request's files. declared
// is false when the request declares neither, and an error comes back when it
// declares one without the other or declares one as anything but a scalar string.
func versionExtensions(files []*descriptorpb.FileDescriptorProto) (versionExts, bool, error) {
	resolver, err := protoopts.BuildResolver(files)
	if err != nil {
		return versionExts{}, false, fmt.Errorf("build extension resolver: %w", err)
	}
	exts := versionExts{
		protocol: protoopts.FindExtension(resolver, protocolExtName, protocolExtNumber),
		manifest: protoopts.FindExtension(resolver, manifestExtName, manifestExtNumber),
	}
	if exts.protocol == nil && exts.manifest == nil {
		return versionExts{}, false, nil
	}
	if exts.protocol == nil || exts.manifest == nil {
		return versionExts{}, false, errors.New("the request declares only one of the two version options")
	}
	for _, ext := range []protoreflect.ExtensionTypeDescriptor{exts.protocol, exts.manifest} {
		if ext.Kind() != protoreflect.StringKind || ext.IsList() {
			return versionExts{}, false, fmt.Errorf("(%s) must be declared as an optional string", ext.FullName())
		}
	}
	return exts, true, nil
}

// versionSource returns the one file to generate that sets the options.
func versionSource(files []*protogen.File, exts versionExts) (source, error) {
	found := make([]source, 0, 1)
	for _, f := range files {
		if !f.Generate {
			continue
		}
		src, set, err := readSource(f, exts)
		if err != nil {
			return source{}, err
		}
		if set {
			found = append(found, src)
		}
	}
	switch len(found) {
	case 0:
		return source{}, fmt.Errorf("no file sets (%s) and (%s)", protocolExtName, manifestExtName)
	case 1:
		return found[0], nil
	}
	paths := make([]string, 0, len(found))
	for _, src := range found {
		paths = append(paths, src.file.Desc.Path())
	}
	return source{}, fmt.Errorf("the version options are set on more than one file: %s", strings.Join(paths, ", "))
}

// readSource reads both options off f. set is false when f sets neither; a file
// that sets only one, or a value that is not a canonical MAJOR.MINOR, is an error.
func readSource(f *protogen.File, exts versionExts) (source, bool, error) {
	opts := f.Desc.Options()
	protocol, err := protoopts.ReadString(exts.protocol, opts)
	if err != nil {
		return source{}, false, fmt.Errorf("read (%s) on %s: %w", protocolExtName, f.Desc.Path(), err)
	}
	manifest, err := protoopts.ReadString(exts.manifest, opts)
	if err != nil {
		return source{}, false, fmt.Errorf("read (%s) on %s: %w", manifestExtName, f.Desc.Path(), err)
	}
	if protocol == "" && manifest == "" {
		return source{}, false, nil
	}
	if protocol == "" || manifest == "" {
		return source{}, false, fmt.Errorf("%s sets only one of the two version options; set both", f.Desc.Path())
	}
	if err := checkVersion(protocolExtName, protocol); err != nil {
		return source{}, false, err
	}
	if err := checkVersion(manifestExtName, manifest); err != nil {
		return source{}, false, err
	}
	return source{file: f, protocol: protocol, manifest: manifest}, true, nil
}

// checkVersion refuses a value that is not a canonical MAJOR.MINOR.
func checkVersion(option, value string) error {
	if !canonicalVersion.MatchString(value) {
		return fmt.Errorf("(%s) = %q is not MAJOR.MINOR: two runs of ASCII digits, no leading zero", option, value)
	}
	return nil
}
