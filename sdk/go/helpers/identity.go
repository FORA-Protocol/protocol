package helpers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// Minting an Ed25519 identity a FORA verifier can resolve takes three steps a caller
// otherwise assembles by hand: a key and its keyid, the Web Bot Auth key directory
// that publishes it, and a signer that signs as it. GenerateKey and
// DirectoryDocument are the first two; core.SigningTransportFor is the third. The
// directory is built as the generated forav1.WBAFile, the type the SDK's own WBA
// resolver decodes, so its shape is defined once, by that message.

// DefaultKeyValidity is how long a key DirectoryDocument publishes stays valid by
// default.
const DefaultKeyValidity = 365 * 24 * time.Hour

// directoryNotBeforeMargin is how far before now a published key's window opens,
// so a verifier whose clock runs slightly behind still accepts it.
const directoryNotBeforeMargin = 5 * time.Minute

// GenerateKey returns a fresh Ed25519 key and its RFC 7638 thumbprint: the keyid
// every FORA signature names.
func GenerateKey() (ed25519.PrivateKey, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("helpers: generate ed25519 key: %w", err)
	}
	tp, err := Thumbprint(pub)
	if err != nil {
		return nil, "", err
	}
	return priv, tp, nil
}

// DirectoryDocument returns the Web Bot Auth key directory publishing keys, in
// order. Each key carries the not_before / not_after window the WBA resolver
// requires before it hands a key out: it opens five minutes before now and lasts
// validFor (DefaultKeyValidity when validFor <= 0). now is the instant the window
// is computed from, passed in so the document is deterministic.
//
// Render it with protojson and the proto field names (UseProtoNames) to serve it at
// /.well-known/http-message-signatures-directory.
func DirectoryDocument(keys []ed25519.PublicKey, validFor time.Duration, now time.Time) *forav1.WBAFile {
	if validFor <= 0 {
		validFor = DefaultKeyValidity
	}
	notBefore := now.Add(-directoryNotBeforeMargin).UTC().Format(time.RFC3339)
	notAfter := now.Add(validFor).UTC().Format(time.RFC3339)
	out := &forav1.WBAFile{Keys: make([]*forav1.JsonWebKey, 0, len(keys))}
	for _, key := range keys {
		out.Keys = append(out.Keys, &forav1.JsonWebKey{
			Kty:       "OKP",
			Crv:       "Ed25519",
			Alg:       "EdDSA",
			Use:       "sig",
			X:         base64.RawURLEncoding.EncodeToString(key),
			NotBefore: notBefore,
			NotAfter:  notAfter,
		})
	}
	return out
}
