package resolvers_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// TestWBAKeyResolver_JWKAlgIsNotRead pins what the resolver does with a key's
// JWK alg member: nothing. A key is selected by its RFC 7638 thumbprint, its
// OKP/Ed25519 shape and its validity window, so a directory that writes the alg
// the way WG-00 did ("ed25519", the RFC 9421 name) or leaves it out resolves
// exactly as one writing the JOSE name "EdDSA", which WG-01 §5.5.1 requires when an
// alg is present.
func TestWBAKeyResolver_JWKAlgIsNotRead(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{"EdDSA", "ed25519", ""} {
		priv, jwk := newSigningKey("alg-"+alg, wbaAnchor.Add(-time.Hour), wbaAnchor.Add(time.Hour))
		jwk.Alg = alg
		origin := newWBAOrigin(nil)
		origin.setWBA(marshalWBA(jwk))

		r := resolvers.NewWBAKeyResolver(resolvers.WBAKeyResolverOptions{
			HTTP: origin.Client(),
			Now:  func() time.Time { return wbaAnchor },
		})
		ctx := helpers.WithSignatureAgent(context.Background(), origin.url)
		got, err := r.Resolve(ctx, mustThumbprint(t, priv.Public().(ed25519.PublicKey)))
		origin.close()
		if err != nil {
			t.Fatalf("alg %q: Resolve: %v", alg, err)
		}
		if !got.Equal(priv.Public()) {
			t.Fatalf("alg %q: resolved key mismatch", alg)
		}
	}
}
