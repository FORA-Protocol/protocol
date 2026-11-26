package conformance

// The protocol and manifest versions are written once each: as the file options
// (fora.v1.protocol_version) and (fora.v1.well_known_manifest_version) of exactly
// one contract file, fora.proto, from which buf generates forav1.ProtocolVersion
// and forav1.WellKnownManifestVersion. The generator refuses a second file only
// within the request it is given; this guard holds the rule across the whole
// contract, and holds each generated constant to the option it came from.

import (
	"regexp"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// canonicalVersion is a MAJOR.MINOR with no sign, no padding and no leading zero,
// the only spelling a version option may carry.
var canonicalVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// versionOptions pairs each version option with the constant generated from it.
var versionOptions = []struct {
	ext       protoreflect.ExtensionType
	generated string
}{
	{forav1.E_ProtocolVersion, forav1.ProtocolVersion},
	{forav1.E_WellKnownManifestVersion, forav1.WellKnownManifestVersion},
}

// optionSetters returns each contract file that sets ext, with the value it sets.
func optionSetters(ext protoreflect.ExtensionType) map[string]string {
	setters := map[string]string{}
	for _, c := range Contract {
		if opts := c.File.Options(); proto.HasExtension(opts, ext) {
			value, _ := proto.GetExtension(opts, ext).(string)
			setters[c.File.Path()] = value
		}
	}
	return setters
}

func TestVersionOptionsAreWrittenOnce(t *testing.T) {
	for _, opt := range versionOptions {
		name := opt.ext.TypeDescriptor().FullName()
		setters := optionSetters(opt.ext)
		if len(setters) != 1 {
			t.Errorf("(%s) is set on %d contract files %v, want exactly fora/v1/fora.proto", name, len(setters), setters)
			continue
		}
		for path, value := range setters {
			if !canonicalVersion.MatchString(value) {
				t.Errorf("%s sets (%s) = %q, which is not a canonical MAJOR.MINOR", path, name, value)
			}
			if value != opt.generated {
				t.Errorf("%s sets (%s) = %q, but gen/ holds %q; regenerate gen/", path, name, value, opt.generated)
			}
		}
	}
}

func TestCanonicalVersionMeta(t *testing.T) {
	for _, v := range []string{"1.0", "0.3", "1.10", "10.0"} {
		if !canonicalVersion.MatchString(v) {
			t.Errorf("the canonical check refused %q", v)
		}
	}
	for _, v := range []string{"", "1", "1.0.0", "v1.0", "01.0", "1.00", " 1.0", "1.0 ", "1.-1"} {
		if canonicalVersion.MatchString(v) {
			t.Errorf("the canonical check accepted %q", v)
		}
	}
}
