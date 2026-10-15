package core

import (
	"crypto/ed25519"
	"fmt"
	"net/http"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// SigningTransportFor returns a signing RoundTripper over base that signs as priv:
// the RFC 9421 keyid is priv's RFC 7638 thumbprint, and Signature-Agent names
// directory, the WBA key directory that publishes the key (see
// helpers.DirectoryDocument). It is the third step of minting an identity, after
// helpers.GenerateKey and the directory document. A nil base is
// http.DefaultTransport.
func SigningTransportFor(priv ed25519.PrivateKey, directory string, base http.RoundTripper) (http.RoundTripper, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("core: signing transport needs an ed25519 private key of %d bytes", ed25519.PrivateKeySize)
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	keyID, err := helpers.Thumbprint(pub)
	if err != nil {
		return nil, err
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		return nil, err
	}
	return NewSigningTransport(signer, base, WithSignatureAgent(directory)), nil
}
