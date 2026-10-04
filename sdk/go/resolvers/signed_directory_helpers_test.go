package resolvers_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"sync"

	"google.golang.org/protobuf/encoding/protojson"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// A key directory is served under the Web Bot Auth profile: its own media type
// and a response signed by every key it lists, for the authority it was fetched
// from. The test origins here serve directories built from keys the tests mint,
// so every minted private key is registered by its public half and
// writeSignedDirectory signs with the ones a body lists.

var testDirectoryKeys sync.Map // base64url public key -> ed25519.PrivateKey

// registerDirectoryKey makes priv available to writeSignedDirectory.
func registerDirectoryKey(priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	testDirectoryKeys.Store(base64.RawURLEncoding.EncodeToString(pub), priv)
}

// directoryResponseWindow is wide enough to contain every injected test clock.
const (
	directoryResponseCreated = int64(1)
	directoryResponseExpires = int64(1) << 40
)

// writeSignedDirectory answers r with body as a key directory: the profile's
// media type and a response signature by each listed key a test registered. A
// listed key nobody registered is left unsigned, which a reader treats as absent.
func writeSignedDirectory(w http.ResponseWriter, r *http.Request, body []byte) {
	var file forav1.WBAFile
	_ = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(body, &file)
	var signers []helpers.Signer
	for _, k := range file.GetKeys() {
		v, ok := testDirectoryKeys.Load(k.GetX())
		if !ok {
			continue
		}
		priv := v.(ed25519.PrivateKey)
		tp, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s, err := helpers.NewEd25519Signer(tp, priv)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		signers = append(signers, s)
	}
	if len(signers) > 0 {
		sig, err := helpers.SignDirectoryResponse(r.Context(), r.Host, body, signers,
			directoryResponseCreated, directoryResponseExpires)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sig.Apply(w.Header())
	}
	w.Header().Set("Content-Type", resolvers.WBADirectoryMediaType)
	_, _ = w.Write(body)
}
