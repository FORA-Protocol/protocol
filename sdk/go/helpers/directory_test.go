package helpers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// docAuthority is the host the documented agent's directory is served from.
const docAuthority = "research.acme.example"

// The authentication page's Key Directory example: the directory of the agent in
// the single-hop example, signed with the RFC 8037 test key.
const docDirectoryBody = "{\n  \"keys\": [\n    {\n      \"kty\": \"OKP\",\n      \"crv\": \"Ed25519\",\n" +
	"      \"use\": \"sig\",\n      \"alg\": \"EdDSA\",\n" +
	"      \"x\": \"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\n" +
	"      \"not_before\": \"2026-07-01T00:00:00Z\",\n      \"not_after\": \"2027-01-01T00:00:00Z\"\n" +
	"    }\n  ],\n" +
	"  \"revocation_url\": \"https://research.acme.example/.well-known/fora-invalidations.json\"\n}"

func rfc8037Signer(t *testing.T) (helpers.Signer, ed25519.PublicKey) {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	tp, err := helpers.Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer(tp, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, pub
}

// TestSignDirectoryResponse_reproducesTheDocumentedExample signs the page's
// directory response and requires its exact headers, then verifies it.
func TestSignDirectoryResponse_reproducesTheDocumentedExample(t *testing.T) {
	signer, pub := rfc8037Signer(t)
	got, err := helpers.SignDirectoryResponse(context.Background(), docAuthority,
		[]byte(docDirectoryBody), []helpers.Signer{signer}, 1790812200, 1790815800)
	if err != nil {
		t.Fatal(err)
	}
	want := helpers.DirectoryResponseSignature{
		ContentDigest:  "sha-256=:42lr4GiKiJK9tk/oA4H0w+EAuTDKfnGCJX7/uLs/tIQ=:",
		SignatureInput: `sig1=("@authority";req "content-digest");created=1790812200;expires=1790815800;keyid="kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";alg="ed25519";tag="http-message-signatures-directory"`,
		Signature:      "sig1=:oNe5fmnn4tziOEs8aRMpdN3HUXFBrRSg/PG91o9X5ESsX3gHP9hhU6sgDC9/0VPJH46lXNsiCtDrgO9k0OlVDQ==:",
	}
	if got != want {
		t.Fatalf("directory response\n got %+v\nwant %+v", got, want)
	}
	h := http.Header{}
	got.Apply(h)
	verified, err := helpers.VerifyDirectoryResponse(docAuthority, h, []byte(docDirectoryBody),
		[]ed25519.PublicKey{pub}, time.Unix(1790812300, 0))
	if err != nil || !verified[signer.KeyID()] {
		t.Fatalf("verify: %v %v", verified, err)
	}
}

// TestVerifyDirectoryResponse_judgesEachSignature: a response signature is
// accepted only for the authority it was made for, inside its window, with the
// directory tag, and only for a key the body lists. A body that does not match its
// Content-Digest, or a response carrying no signature, fails as a whole.
func TestVerifyDirectoryResponse_judgesEachSignature(t *testing.T) {
	signer, pub := rfc8037Signer(t)
	body := []byte(docDirectoryBody)
	sign := func(authority string, created, expires int64) http.Header {
		t.Helper()
		d, err := helpers.SignDirectoryResponse(
			context.Background(),
			authority,
			body,
			[]helpers.Signer{signer},
			created,
			expires,
		)
		if err != nil {
			t.Fatal(err)
		}
		h := http.Header{}
		d.Apply(h)
		return h
	}
	now := time.Unix(1790812300, 0)
	keys := []ed25519.PublicKey{pub}
	for _, tc := range []struct {
		name      string
		authority string
		header    http.Header
		keys      []ed25519.PublicKey
		body      []byte
		want      bool
		wantErr   error
	}{
		{"valid", docAuthority, sign(docAuthority, 1790812200, 1790815800), keys, body, true, nil},
		{
			"authority compared case-insensitively", "Research.Acme.Example",
			sign(docAuthority, 1790812200, 1790815800), keys, body, true, nil,
		},
		{"signed for another host", docAuthority, sign("evil.example", 1790812200, 1790815800), keys, body, false, nil},
		{"expired", docAuthority, sign(docAuthority, 1790800000, 1790810000), keys, body, false, nil},
		{"created in the future", docAuthority, sign(docAuthority, 1790822200, 1790825800), keys, body, false, nil},
		{"key not listed", docAuthority, sign(docAuthority, 1790812200, 1790815800), nil, body, false, nil},
		{
			"body changed", docAuthority, sign(docAuthority, 1790812200, 1790815800), keys,
			append([]byte("x"), body...), false, helpers.ErrDigestMismatch,
		},
		{
			"unsigned", docAuthority,
			http.Header{"Content-Digest": {helpers.ContentDigest(body)}},
			keys, body,
			false, helpers.ErrDirectoryResponseUnsigned,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verified, err := helpers.VerifyDirectoryResponse(tc.authority, tc.header, tc.body, tc.keys, now)
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if verified[signer.KeyID()] != tc.want {
				t.Fatalf("verified = %v, want key verified %v", verified, tc.want)
			}
		})
	}
}

// TestVerifyDirectoryResponse_eachKeySignsForItself: with two listed keys, a
// response signed by only one verifies only that one.
func TestVerifyDirectoryResponse_eachKeySignsForItself(t *testing.T) {
	a, aPub := rfc8037Signer(t)
	_, bPriv, _ := ed25519.GenerateKey(nil)
	bPub := bPriv.Public().(ed25519.PublicKey)
	body := []byte(`{"keys":[]}`)
	d, err := helpers.SignDirectoryResponse(
		context.Background(),
		"agent.example",
		body,
		[]helpers.Signer{a},
		1790812200,
		1790815800,
	)
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	d.Apply(h)
	verified, err := helpers.VerifyDirectoryResponse(
		"agent.example",
		h,
		body,
		[]ed25519.PublicKey{aPub, bPub},
		time.Unix(1790812300, 0),
	)
	if err != nil {
		t.Fatal(err)
	}
	bTP, _ := helpers.Thumbprint(bPub)
	if !verified[a.KeyID()] || verified[bTP] {
		t.Fatalf("verified = %v, want only the signing key", verified)
	}
}
