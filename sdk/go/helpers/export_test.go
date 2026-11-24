package helpers

import (
	"context"
	"net/http"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/canonicalsign"
)

// RefusingSchemaLoaderForTest exposes the SSRF backstop to the package's external
// test binary. It is declared in a _test.go file, so it is not part of the shipped
// surface and never reaches the API-parity gate — the loader is an implementation
// detail that only a test needs to reach past the scan to exercise.
func RefusingSchemaLoaderForTest() jsonschema.URLLoader { return refusingSchemaLoader{} }

// MaxRequestAcceptanceItemsForTest exposes the canonicalization item cap so the
// external test binary can pin it to the wire rule on
// AgentRequestAcceptancePayload.items. Declared in a _test.go file, so it never
// reaches the API-parity gate.
const MaxRequestAcceptanceItemsForTest = canonicalsign.MaxRequestAcceptanceItems

// RawSignature describes a signature by its exact covered set and parameters, for
// the tests that need a signature the shipped signers refuse to make: no tag, a
// legacy Signature-Agent form, a member key that differs from the label, an
// incomplete coverage of an earlier signature, an alg other than the signer's or
// none at all. Declared in a _test.go file, so it never reaches the API-parity gate.
type RawSignature struct {
	Label            string
	Covered          []CoveredComponent
	Created, Expires int64
	Nonce, Tag       string
	// Alg replaces the signer's algorithm name when set; OmitAlg sends no alg.
	Alg     string
	OmitAlg bool
}

// SignRawForTest signs req with exactly raw, over whatever headers req already
// carries, replacing Signature-Input and Signature or, with appendMode, appending
// to them. It sets nothing else: the caller writes Content-Digest, Authorization
// and Signature-Agent as the case requires.
func SignRawForTest(req *http.Request, signer Signer, raw RawSignature, appendMode bool) error {
	alg := signer.Algorithm()
	if raw.Alg != "" {
		alg = raw.Alg
	}
	if raw.OmitAlg {
		alg = ""
	}
	p := sigParams{
		Label: raw.Label, Covered: raw.Covered, KeyID: signer.KeyID(), Alg: alg,
		Created: raw.Created, Expires: raw.Expires, Nonce: raw.Nonce, Tag: raw.Tag,
	}
	mode := sigWriteSet
	if appendMode {
		mode = sigWriteAppend
	}
	return signWithParams(context.Background(), req, p, signer, mode)
}

// FORACovered is the covered set the shipped signer gives a FORA RPC signature
// labelled label on req.
func FORACovered(req *http.Request, label string) []CoveredComponent { return coveredFor(req, label) }

// CorruptFirstMemberForTest flips the first base64 character after the opening colon
// of the first Signature dictionary member: the member's signature bytes change and
// the wire form stays well formed, so a verifier refuses it as a signature failure,
// not a parse error.
func CorruptFirstMemberForTest(sig string) string {
	b := []byte(sig)
	for i := 0; i < len(b); i++ {
		if b[i] == ':' && i+1 < len(b) {
			if b[i+1] == 'A' {
				b[i+1] = 'B'
			} else {
				b[i+1] = 'A'
			}
			break
		}
	}
	return string(b)
}

// CrossFieldRuleIDsForTest is every message-level CEL id the contract declares, read
// from the generated descriptor rather than listed here. The license-term emitter
// and its replay both classify a violation as cross-field or field-level by this
// set, so they classify it alike.
func CrossFieldRuleIDsForTest(t *testing.T) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	var walk func(protoreflect.MessageDescriptors)
	walk = func(mds protoreflect.MessageDescriptors) {
		for i := 0; i < mds.Len(); i++ {
			md := mds.Get(i)
			if opts := md.Options(); proto.HasExtension(opts, validate.E_Message) {
				rules, _ := proto.GetExtension(opts, validate.E_Message).(*validate.MessageRules)
				for _, c := range rules.GetCel() {
					ids[c.GetId()] = true
				}
			}
			walk(md.Messages())
		}
	}
	walk(forav1.File_fora_v1_fora_proto.Messages())
	if len(ids) == 0 {
		t.Fatal("no message-level CEL ids found in the descriptor — every cross-field " +
			"violation would be classified as field-level")
	}
	return ids
}
