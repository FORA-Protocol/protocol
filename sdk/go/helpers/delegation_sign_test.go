package helpers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Test-only minting of profile tokens. The verifier never signs, so the signer
// lives beside the tests: the chain tests and the chain-case generator both
// mint with it from fixed seeds, and nothing here rewrites what it signs.

// delegationTestKey derives a deterministic Ed25519 key pair from one seed byte.
func delegationTestKey(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(fixedSeed(seed))
	return priv.Public().(ed25519.PublicKey), priv
}

// publicJWK renders pub as the OKP JWK the protected jwk header carries.
func publicJWK(pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func mustThumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	thumb, err := Thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	return thumb
}

// signCompact signs header and claims with priv as a compact JWS: the exact
// bytes the verifier checks, with no re-serialization in between.
func signCompact(t *testing.T, priv ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// tokenSpec describes one token of a test chain. Zero values take the profile's
// happy-path defaults so a test names only what it changes.
type tokenSpec struct {
	alg    string         // "" → EdDSA
	header map[string]any // extra or overriding protected header members; a nil value deletes
	claims map[string]any // extra or overriding claims; a nil value deletes
}

// mintChain mints a chain root-first. keys[i] signs token i; holder is the key
// token i's cnf.jkt names, which is keys[i+1] for every token but the last, where
// it is holderPub. Returns the terminal token, the one Delegation.token carries.
func mintChain(t *testing.T, keys []ed25519.PrivateKey, holderPub ed25519.PublicKey, rootIss string, aud []string, scope string, exp float64, specs []tokenSpec) string {
	t.Helper()
	if len(specs) != len(keys) {
		t.Fatalf("mintChain: %d keys, %d specs", len(keys), len(specs))
	}
	var parent string
	for i, priv := range keys {
		spec := specs[i]
		pub := priv.Public().(ed25519.PublicKey)
		var holder ed25519.PublicKey = holderPub
		if i+1 < len(keys) {
			holder = keys[i+1].Public().(ed25519.PublicKey)
		}
		alg := spec.alg
		if alg == "" {
			alg = "EdDSA"
		}
		header := map[string]any{"alg": alg, "typ": DelegationTokenType}
		iss := rootIss
		if i > 0 {
			header["jwk"] = publicJWK(pub)
			iss = mustThumbprint(t, pub)
		}
		claims := map[string]any{
			"iss": iss,
			"aud": aud,
			"exp": exp,
			"cnf": map[string]any{"jkt": mustThumbprint(t, holder)},
		}
		if scope != "" {
			claims["scope"] = scope
		}
		if parent != "" {
			claims["fora_parent"] = parent
		}
		for k, v := range spec.header {
			if v == nil {
				delete(header, k)
			} else {
				header[k] = v
			}
		}
		for k, v := range spec.claims {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		parent = signCompact(t, priv, header, claims)
	}
	return parent
}
