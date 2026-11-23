package helpers_test

// The Web Bot Auth -01 Signature-Agent rules at the helpers' public faces: the key
// directory URL a signer writes for the value it is given, and the members and
// values a verifier refuses because they name no key directory.

import (
	"context"
	"errors"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// TestSignRequest_writesTheKeyDirectoryURL: given the well-known URL or the bare
// origin, the signer writes the well-known URL, so no signature carries the bare
// origin a Web Bot Auth -01 verifier would fetch as the key set itself. The
// verifier reads it as the same key directory.
func TestSignRequest_writesTheKeyDirectoryURL(t *testing.T) {
	for _, value := range []string{tWellKnown, tAgent} {
		t.Run(value, func(t *testing.T) {
			body := []byte(`{"offer_id":"of_1"}`)
			signer, pub := mustSigner(t, "agent.v1")
			req := profileRequest(t, body, "")
			opts := helpers.SignOptions{Created: tCreated, Expires: tExpires, SignatureAgent: value}
			if err := helpers.SignRequest(context.Background(), req, body, signer, opts); err != nil {
				t.Fatalf("SignRequest: %v", err)
			}
			if got := req.Header.Get(helpers.SignatureAgentHeader); got != `sig1="`+tWellKnown+`"` {
				t.Errorf("Signature-Agent = %q, want the well-known URL", got)
			}
			vr, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
			if err != nil || vr.KeyDirectory != tWellKnown || vr.SignatureAgent != tAgent {
				t.Fatalf("VerifyRequest = (%+v, %v), want key directory %q of %q", vr, err, tWellKnown, tAgent)
			}
		})
	}
}

// TestVerifyRequest_ignoresAMemberCarryingAParameter: under -01 a covered member
// that carries any parameter is ignored, so the signature names no key directory,
// and a member that is not a String names none either. Each is refused with
// Accept-Signature, which a Web Bot Auth library can answer by signing again.
func TestVerifyRequest_ignoresAMemberCarryingAParameter(t *testing.T) {
	wellKnown := `sig1="` + tWellKnown + `"`
	legacy := func(r *helpers.RawSignature) { r.Covered = plainCovered(append(foraRPC, "signature-agent")...) }
	for _, tc := range []signatureAgentRefusal{
		{
			"a member carrying type=directory as a String",
			wellKnown + `;type="directory"`, nil, helpers.ErrSignatureAgentIgnored,
		},
		{
			"a member carrying type=directory as a Token",
			wellKnown + `;type=directory`, nil, helpers.ErrSignatureAgentIgnored,
		},
		{"a member whose type is not directory", wellKnown + `;type="jwks"`, nil, helpers.ErrSignatureAgentIgnored},
		{
			"a bare origin carrying a parameter",
			`sig1="https://agent.example";x=1`, nil, helpers.ErrSignatureAgentIgnored,
		},
		{
			"the legacy String carrying a parameter", `"` + tWellKnown + `";type=directory`, legacy,
			helpers.ErrSignatureAgentIgnored,
		},
		{"a member that is a token", `sig1=agent`, nil, helpers.ErrSignatureAgentForm},
	} {
		t.Run(tc.name, func(t *testing.T) { assertSignatureAgentRefused(t, tc.header, tc.edit, tc.want) })
	}
}

// TestVerifyRequest_refusesAValueNamingNoKeyDirectory: a covered member whose value
// is not an https origin or its well-known key directory URL is refused with the
// rule it breaks, and with Accept-Signature.
func TestVerifyRequest_refusesAValueNamingNoKeyDirectory(t *testing.T) {
	for _, tc := range []signatureAgentRefusal{
		{"a plaintext origin", `sig1="http://agent.example"`, nil, helpers.ErrSignatureAgentNotOrigin},
		{
			"the well-known URL over http",
			`sig1="http://agent.example/.well-known/http-message-signatures-directory"`, nil,
			helpers.ErrSignatureAgentNotOrigin,
		},
		{
			"the well-known URL with credentials",
			`sig1="https://u@agent.example/.well-known/http-message-signatures-directory"`, nil,
			helpers.ErrSignatureAgentNotOrigin,
		},
		{"an origin with a path", `sig1="https://agent.example/keys"`, nil, helpers.ErrSignatureAgentNotKeyDirectory},
		{
			"a JWK Set at another path",
			`sig1="https://agent.example/jwks.json"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"an origin with a trailing slash",
			`sig1="https://agent.example/"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"the well-known path with a trailing slash",
			`sig1="` + tWellKnown + `/"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"the well-known path in another case",
			`sig1="https://agent.example/.well-known/HTTP-Message-Signatures-Directory"`, nil,
			helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"the well-known URL with a query",
			`sig1="` + tWellKnown + `?v=1"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"a bare origin with a query",
			`sig1="https://agent.example?v=1"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"the well-known URL with a fragment",
			`sig1="` + tWellKnown + `#k"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
		{
			"an escaped quote in the covered value",
			`sig1="` + tWellKnown + `\"x"`, nil, helpers.ErrSignatureAgentNotKeyDirectory,
		},
	} {
		t.Run(tc.name, func(t *testing.T) { assertSignatureAgentRefused(t, tc.header, tc.edit, tc.want) })
	}
}

// signatureAgentRefusal is one Signature-Agent the verifier refuses: the header,
// how the signature covers it, and the rule that refuses it.
type signatureAgentRefusal struct {
	name   string
	header string
	edit   func(*helpers.RawSignature)
	want   error
}

// assertSignatureAgentRefused signs the profile request carrying header, edit
// applied, and requires the verifier to refuse it with want and Accept-Signature.
func assertSignatureAgentRefused(t *testing.T, header string, edit func(*helpers.RawSignature), want error) {
	t.Helper()
	signer, pub := mustSigner(t, "agent.v1")
	body := []byte("x")
	req := profileRequest(t, body, header)
	rawSign(t, req, signer, func(r *helpers.RawSignature) {
		if edit != nil {
			edit(r)
		}
	})
	_, err := helpers.VerifyRequest(req, body, pub, helpers.VerifyOptions{Now: tNow})
	if !errors.Is(err, want) {
		t.Fatalf("VerifyRequest error = %v, want %v", err, want)
	}
	if accept, ok := helpers.AcceptSignatureFor(err); !ok {
		t.Fatalf("AcceptSignatureFor answered no Accept-Signature (%q)", accept)
	}
}
