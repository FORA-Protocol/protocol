package helpers

import (
	"context"
	"net/http"

	"github.com/santhosh-tekuri/jsonschema/v6"
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
const MaxRequestAcceptanceItemsForTest = maxRequestAcceptanceItems

// RawSignature describes a signature by its exact covered set and parameters, for
// the tests that need a signature the shipped signers refuse to make: no tag, a
// legacy Signature-Agent form, a member key that differs from the label, an
// incomplete coverage of an earlier signature. Declared in a _test.go file, so it
// never reaches the API-parity gate.
type RawSignature struct {
	Label            string
	Covered          []CoveredComponent
	Created, Expires int64
	Nonce, Tag       string
}

// SignRawForTest signs req with exactly raw, over whatever headers req already
// carries, replacing Signature-Input and Signature or, with appendMode, appending
// to them. It sets nothing else: the caller writes Content-Digest, Authorization
// and Signature-Agent as the case requires.
func SignRawForTest(req *http.Request, signer Signer, raw RawSignature, appendMode bool) error {
	p := sigParams{
		Label: raw.Label, Covered: raw.Covered, KeyID: signer.KeyID(), Alg: signer.Algorithm(),
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
