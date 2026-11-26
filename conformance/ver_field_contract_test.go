package conformance

// Structural guard for the `ver` envelope field's documented contract.
//
// Every message of the wire contract carries `ver` at field 1, and the value is
// "1.0". That was true before this guard existed too — but only ONE of the 29
// fields said so: WellKnownManifest.ver. Of the other 28, twenty-seven read only
// "Protocol version" or "FORA protocol version", and DiscoveryResponse.ver
// carried no comment at all.
// Nobody removed those statements; they were never written, because a per-field
// doc obligation that lives only in a reviewer's head is complete the day it is
// discharged and silently incomplete the day the next message is added.
//
// So this guard derives its scope from the contract rather than from a list: it
// reads the proto SOURCE of every package in Contract (contract.go) and requires
// each `ver` field to state the expected value, and — outside the documented
// exemption — the advisory-on-receive rule. A message added tomorrow with a
// silent `ver` fails on the day it is written.
//
// It reads the .proto source, not the descriptor, because the obligation is on
// the comment text and the generated Go descriptor does not retain source
// comments. That also matches what a human reads when integrating.
//
// This guard binds the comments; the value itself is written once, as the
// (fora.v1.protocol_version) and (fora.v1.well_known_manifest_version) options of
// fora.proto, from which buf generates forav1.ProtocolVersion and
// forav1.WellKnownManifestVersion (version_options_test.go holds that). Neither can
// bind a third party — `ver` is deliberately advisory on the wire, with no
// protovalidate rule. See "Protocol version" in fora.proto for why.
//
// The expected value is READ from those generated constants rather than restated
// here. contract.go already imports the generated package, so this adds no
// dependency, and a version bump that leaves a comment behind goes red instead of
// leaving the value and its description to drift apart.

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

var (
	verFieldRe  = regexp.MustCompile(`^\s*string ver = 1\b`)
	messageDecl = regexp.MustCompile(`^\s*message (\w+) \{`)
	commentLine = regexp.MustCompile(`^\s*//`)
)

// verExemptMessages are messages whose `ver` is NOT the RPC envelope version and
// therefore carries a different, stronger contract. Each entry is proved both
// USED and NECESSARY on every run: an entry naming no real `ver` field fails as
// stale, and an entry whose comment has since adopted the standard advisory
// wording fails as a no-longer-needed exemption.
var verExemptMessages = map[string]string{
	"WellKnownManifest": "the /.well-known/fora.json document's own layout version — a separate " +
		"namespace from the RPC envelope, gated on its MAJOR by consumers rather than advisory; " +
		"its expected value is WellKnownManifestVersion, not ProtocolVersion",
}

// expectedVersionToken is the quoted form a `ver` comment must contain, e.g. `"1.0"`.
func expectedVersionToken() string {
	return strconv.Quote(forav1.ProtocolVersion)
}

// expectedManifestVersionToken is the quoted form the MANIFEST's `ver` comment must
// contain. Read from its own constant, never from ProtocolVersion: the two are
// separate namespaces, so a bump of either alone goes red on exactly the comment it
// invalidates, and checking the manifest against ProtocolVersion would write the
// coupling the contract forbids into the thing that guards it.
func expectedManifestVersionToken() string {
	return strconv.Quote(forav1.WellKnownManifestVersion)
}

// statesExpectedValue is the obligation on EVERY `ver` comment: an integrator
// reading the field must learn what to stamp. Required of exempt fields too —
// the exemption is from the advisory rule, not from naming the value. `token` is
// the generated version in quoted form, so the value lives in one place.
func statesExpectedValue(comment, token string) bool {
	return strings.Contains(comment, token)
}

// statesAdvisoryContract is the obligation on every RPC-envelope `ver`: the
// receive-side rule, which is what stops a reader assuming the field is
// enforced. Exempt messages state a stronger rule instead.
func statesAdvisoryContract(comment string) bool {
	return strings.Contains(comment, "advisory on receive")
}

// verField is one `ver` declaration found in proto source.
type verField struct {
	file    string
	line    int // 1-indexed
	message string
	comment string // the contiguous // block directly above, joined
}

// collectVerFields reads the proto source of every contract package and returns
// every `ver` field with its leading comment block. Enclosing message is the
// most recent `message X {` — `ver` is field 1, so it is always declared before
// any nested message could shadow the attribution.
func collectVerFields(t *testing.T) []verField {
	t.Helper()
	var out []verField
	for _, cf := range Contract {
		// Contract carries the descriptor path (e.g. "fora/v1/fora.proto"); the
		// buf module root is ../proto relative to this package's test dir.
		path := filepath.Join("..", "proto", cf.File.Path())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read proto source for %s: %v", cf.Package, err)
		}
		lines := strings.Split(string(b), "\n")
		msg := ""
		for i, ln := range lines {
			if m := messageDecl.FindStringSubmatch(ln); m != nil {
				msg = m[1]
			}
			if !verFieldRe.MatchString(ln) {
				continue
			}
			var block []string
			for j := i - 1; j >= 0 && commentLine.MatchString(lines[j]); j-- {
				block = append([]string{strings.TrimSpace(lines[j])}, block...)
			}
			out = append(out, verField{
				file:    filepath.ToSlash(path),
				line:    i + 1,
				message: msg,
				comment: strings.Join(block, " "),
			})
		}
	}
	return out
}

func TestVerFieldsDocumentTheirContract(t *testing.T) {
	fields := collectVerFields(t)
	if len(fields) == 0 {
		t.Fatal(
			"no `ver` fields found in the contract protos — the guard would vacuously pass; check the source paths derived from Contract",
		)
	}

	token := expectedVersionToken()
	manifestToken := expectedManifestVersionToken()
	for _, f := range fields {
		if f.comment == "" {
			t.Errorf(
				"%s:%d %s.ver carries no doc comment — every `ver` must state the expected value and its receive-side rule",
				f.file,
				f.line,
				f.message,
			)
			continue
		}
		_, exempt := verExemptMessages[f.message]
		want, owner := token, "ProtocolVersion"
		if exempt {
			want, owner = manifestToken, "WellKnownManifestVersion"
		}
		if !statesExpectedValue(f.comment, want) {
			t.Errorf(
				"%s:%d %s.ver does not state the expected value — the comment must name %s, forav1.%s",
				f.file,
				f.line,
				f.message,
				want,
				owner,
			)
		}
		if exempt {
			continue
		}
		if !statesAdvisoryContract(f.comment) {
			t.Errorf(
				"%s:%d %s.ver does not state the receive-side rule — say it is advisory on receive, or add %s to verExemptMessages with a reason",
				f.file,
				f.line,
				f.message,
				f.message,
			)
		}
	}
}

// TestVerExemptionsAreUsedAndNecessary keeps the exemption list from outliving
// its reasons — the failure mode every hand-maintained list in this package is
// written to avoid.
func TestVerExemptionsAreUsedAndNecessary(t *testing.T) {
	fields := collectVerFields(t)
	byMessage := map[string]verField{}
	for _, f := range fields {
		byMessage[f.message] = f
	}
	for msg, reason := range verExemptMessages {
		if reason == "" {
			t.Errorf("exemption for %s carries no reason", msg)
		}
		f, ok := byMessage[msg]
		if !ok {
			t.Errorf("stale exemption: %s declares no `ver` field — drop it from verExemptMessages", msg)
			continue
		}
		if statesAdvisoryContract(f.comment) {
			t.Errorf(
				"stale exemption: %s.ver now states the standard advisory contract — drop it from verExemptMessages",
				msg,
			)
		}
	}
}

// --- meta-tests: exercise the detectors against synthetic comment text -------

func TestVerContractDetectors_MetaPositive(t *testing.T) {
	token := expectedVersionToken()
	// Built from the token rather than a baked literal, so these fixtures cannot
	// drift away from the real comments on a version bump.
	std := "// FORA protocol version — " + token + ". Stamped by the sender from a single " +
		`// constant; advisory on receive. See "Protocol version" in the file header.`
	if !statesExpectedValue(std, token) {
		t.Error("detector missed the expected value in the standard comment")
	}
	if !statesAdvisoryContract(std) {
		t.Error("detector missed the advisory rule in the standard comment")
	}
	mtoken := expectedManifestVersionToken()
	manifest := "// Version of THIS MANIFEST DOCUMENT's layout — " + mtoken + ", stamped from WellKnownManifestVersion."
	if !statesExpectedValue(manifest, mtoken) {
		t.Error("detector missed the expected value in the manifest comment")
	}
}

// TestVerExpectedValueComesFromTheGeneratedConstant pins the anchor itself: the
// token is READ from the generated constant, not restated here. A comment naming
// some other version must fail — which is what makes a half-finished bump (option
// moved, comments not, or the reverse) go red instead of silently disagreeing.
func TestVerExpectedValueComesFromTheGeneratedConstant(t *testing.T) {
	token := expectedVersionToken()
	if token == "" || !strings.HasPrefix(token, `"`) {
		t.Fatalf("expected a quoted version token, got %q", token)
	}
	other := `"9.9"`
	if token == other {
		t.Fatalf("the SDK version collides with this test's counter-example %s; pick another", other)
	}
	if statesExpectedValue("// FORA protocol version — "+other+". advisory on receive.", token) {
		t.Errorf(
			"a comment naming %s satisfied the check against %s — the guard is not anchored to the generated constant",
			other,
			token,
		)
	}
}

func TestVerContractDetectors_MetaNegative(t *testing.T) {
	token := expectedVersionToken()
	for _, c := range []string{
		"// Protocol version",
		"// FORA protocol version.",
		"",
	} {
		if statesExpectedValue(c, token) {
			t.Errorf("detector false-positived on a comment that names no value: %q", c)
		}
		if statesAdvisoryContract(c) {
			t.Errorf("detector false-positived on a comment that states no receive rule: %q", c)
		}
	}
	// The manifest comment states a value but NOT the advisory rule — that
	// asymmetry is exactly what makes its exemption necessary.
	if statesAdvisoryContract(
		"// They REJECT an unrecognised MAJOR, a value that is not MAJOR.MINOR, and an ABSENT `ver`.",
	) {
		t.Error("detector treated the manifest's major-version gate as the advisory contract")
	}
}

// TestVerFieldScanner_MetaRegexSlip pins the field matcher against the shapes it
// must and must not see, so a loosened regex cannot silently shrink the scope.
func TestVerFieldScanner_MetaRegexSlip(t *testing.T) {
	for _, ln := range []string{"  string ver = 1;", "  string ver = 1 [deprecated = true];"} {
		if !verFieldRe.MatchString(ln) {
			t.Errorf("field matcher missed a `ver` declaration: %q", ln)
		}
	}
	for _, ln := range []string{
		"  string verifier = 1;",
		"  string version = 1;",
		"  repeated string protocol_versions_supported = 16;",
		"  // string ver = 1;",
	} {
		if verFieldRe.MatchString(ln) {
			t.Errorf("field matcher false-positived: %q", ln)
		}
	}
}
