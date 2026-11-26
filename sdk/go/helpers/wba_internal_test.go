package helpers

import (
	"net/http"
	"testing"
)

// TestAlgAccepted_readsPresence: the parser records whether a signature carries
// alg at all, so an absent alg is accepted and an empty one is refused. A sigParams
// built by hand reads as alg present, so it is judged by its Alg alone.
func TestAlgAccepted_readsPresence(t *testing.T) {
	for _, tc := range []struct {
		name, params string
		want         bool
	}{
		{"absent", ``, true},
		{"ed25519", `;alg="ed25519"`, true},
		{"ed25519 in upper case", `;alg="ED25519"`, true},
		{"empty", `;alg=""`, false},
		{"another algorithm", `;alg="rsa-pss-sha512"`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			h.Set("Signature-Input", `sig1=("@method");keyid="k"`+tc.params)
			h.Set("Signature", "sig1=:AAAA:")
			all, _, err := parseAllSignatures(h)
			if err != nil {
				t.Fatal(err)
			}
			if got := all[0].algAccepted(); got != tc.want {
				t.Errorf("algAccepted() = %v, want %v", got, tc.want)
			}
		})
	}
	if (sigParams{}).algAccepted() {
		t.Error("a hand-built sigParams with an empty Alg was accepted")
	}
}
