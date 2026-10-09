package helpers_test

import (
	"errors"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// CheckStrict is the public face of the strict contract. The document-check corpus
// pins its verdicts against the Python and TypeScript checks through the readers;
// this pins the arms only the public call has: a message resolved by name in either
// package, and the two inputs that say nothing about a contract.
func TestCheckStrict(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, message, payload string
		strict, ok             bool
	}{
		{"accepted", "fora.v1.KeyRevocationList", `{"as_of":"2026-05-01T12:00:00Z","revoked":[]}`, false, true},
		{"admin package resolved", "fora.admin.v1.SetTenantFeeRateResponse", `{}`, true, false},
		{"null reads as absent", "fora.v1.WellKnownManifest", `{"role":"ROLE_EXCHANGE","endpoint":null}`, false, true},
		{"unknown member", "fora.v1.KeyRevocationList", `{"revokedd":[]}`, true, false},
		{"json_name spelling", "fora.v1.WellKnownManifest", `{"role":"ROLE_EXCHANGE","termsUri":"x"}`, true, false},
		{"bool as string", "fora.v1.License", `{"immutable":"true"}`, true, false},
		{"cross-field rule", "fora.v1.License", `{"uri":"https://publisher.example/terms"}`, true, false},
		{"no such message", "fora.v1.NoSuchMessage", `{}`, false, false},
		{"not JSON", "fora.v1.License", `{"uri":`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := helpers.CheckStrict(tc.message, []byte(tc.payload))
			if (err == nil) != tc.ok || errors.Is(err, helpers.ErrStrictViolation) != tc.strict {
				t.Fatalf("CheckStrict(%s, %s) = %v", tc.message, tc.payload, err)
			}
		})
	}
}
