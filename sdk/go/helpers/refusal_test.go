package helpers_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// refusalCase is one way VerifyURLEd25519 refuses a URL: the token ReasonOf must
// read, and the sentinel errors.Is matched before the token existed.
type refusalCase struct {
	name, url, reason string
	now               time.Time
	sentinel          error
}

// signedURLRefusals signs one URL and returns it refused each way the verifier can.
func signedURLRefusals(t *testing.T) (ed25519.PublicKey, []refusalCase) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Unix(1700000300, 0)
	su, err := helpers.SignURLEd25519(priv, "k", "https://cdn.example/a?x=1", "", expiry)
	if err != nil {
		t.Fatal(err)
	}
	return pub, []refusalCase{
		{"expired", su.URL, "expired", expiry.Add(time.Second), helpers.ErrURLExpired},
		{"no sig", "https://cdn.example/a?exp=1700000300", "missing_sig", expiry, helpers.ErrURLMissingSignature},
		{"no exp", "https://cdn.example/a?sig=AAAA", "missing_exp", expiry, helpers.ErrURLMissingExpiry},
		{
			"bad base64", "https://cdn.example/a?exp=1700000300&sig=%21%21", "bad_sig_encoding", expiry,
			helpers.ErrURLSignatureInvalid,
		},
		{"wrong sig", su.URL + "&x=2", "signature_mismatch", expiry, helpers.ErrURLSignatureInvalid},
	}
}

// assertRefusal requires err to carry reason through ReasonOf and a *RefusalError,
// and to still match sentinel.
func assertRefusal(t *testing.T, err error, reason string, sentinel error) {
	t.Helper()
	if err == nil {
		t.Fatal("verify accepted a URL it must refuse")
	}
	if got := helpers.ReasonOf(err); got != reason {
		t.Errorf("ReasonOf = %q, want %q (err=%v)", got, reason, err)
	}
	var refusal *helpers.RefusalError
	if !errors.As(err, &refusal) || refusal.Reason != reason {
		t.Errorf("err = %#v, want a *RefusalError with Reason %q", err, reason)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(err, %v) = false, want true", sentinel)
	}
}

// TestReasonOf_ReadsTheTokenAndKeepsTheSentinel refuses a signed URL each way the
// verifier can, and requires the token ReasonOf reads, the *RefusalError behind it,
// and the sentinel errors.Is matched before the token existed.
func TestReasonOf_ReadsTheTokenAndKeepsTheSentinel(t *testing.T) {
	pub, cases := signedURLRefusals(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := helpers.VerifyURLEd25519(c.url, pub, c.now)
			assertRefusal(t, err, c.reason, c.sentinel)
		})
	}
}

// TestReasonOf_IsEmptyForNoRefusal requires ReasonOf to report no token for a nil
// error, for an error that is not a refusal, and for a wrapped one either.
func TestReasonOf_IsEmptyForNoRefusal(t *testing.T) {
	plain := errors.New("not a refusal")
	for _, err := range []error{nil, plain, errors.Join(plain, errors.New("still not"))} {
		if got := helpers.ReasonOf(err); got != "" {
			t.Errorf("ReasonOf(%v) = %q, want empty", err, got)
		}
	}
}
