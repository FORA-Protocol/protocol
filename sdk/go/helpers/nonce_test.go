package helpers_test

// A caller-supplied nonce must use only base64url characters. Without the check,
// a quote in the nonce ends the quoted parameter early, and the Go, Python and
// TypeScript SDKs write different bytes for the same input. The same cases are
// tested in the Python and TypeScript SDKs.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func TestSignHelpers_RejectNonceOutsideBase64url(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	signer, err := helpers.NewEd25519Signer("agent.test.v1", priv)
	if err != nil {
		t.Fatal(err)
	}
	sign := map[string]func(context.Context, *http.Request, []byte, helpers.Signer, helpers.SignOptions) error{
		"SignRequest":     helpers.SignRequest,
		"AppendSignature": helpers.AppendSignature,
	}
	for name, fn := range sign {
		for _, nonce := range []string{`abc";expires=1`, `a\b`, "a b", "abc=", "a+b/c", "é"} {
			t.Run(name+"/"+nonce, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodPost, "https://broker.example/x", nil)
				err := fn(context.Background(), req, nil, signer, helpers.SignOptions{Created: 1, Expires: 2, Nonce: nonce})
				if !errors.Is(err, helpers.ErrInvalidNonce) {
					t.Fatalf("err = %v, want ErrInvalidNonce", err)
				}
				if req.Header.Get("Signature") != "" {
					t.Fatal("a rejected nonce must not leave a Signature header")
				}
			})
		}
		t.Run(name+"/valid", func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "https://broker.example/x", nil)
			if err := fn(context.Background(), req, nil, signer, helpers.SignOptions{Created: 1, Expires: 2, Nonce: "AZaz09-_"}); err != nil {
				t.Fatalf("valid nonce refused: %v", err)
			}
		})
	}
}
