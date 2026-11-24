package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"net/http"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// acceptanceKey is the key pair acceptanceSeedHex derives, the one every acceptance
// emitter signs with.
func acceptanceKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString(acceptanceSeedHex)
	if err != nil {
		t.Fatalf("decode acceptance seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, priv.Public().(ed25519.PublicKey)
}

// vectorRequest decodes the body of the vector called name and builds its request,
// with no header set.
func vectorRequest(t *testing.T, name, method, url, bodyHex string) (*http.Request, []byte) {
	t.Helper()
	body, err := hex.DecodeString(bodyHex)
	if err != nil {
		t.Fatalf("%s: decode body: %v", name, err)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, nil)
	if err != nil {
		t.Fatalf("%s: new request: %v", name, err)
	}
	return req, body
}

// transactionRequestOf builds the transaction request a request-acceptance vector
// describes: its requester, its idempotency key and one item per offer.
func transactionRequestOf(
	id, domain, idempotencyKey string, items []requestAcceptanceVectorItem,
) *forav1.TransactionRequest {
	req := &forav1.TransactionRequest{
		IdempotencyKey: idempotencyKey,
		Requester:      &forav1.Requester{Id: id, Domain: domain},
	}
	for _, item := range items {
		req.Items = append(req.Items, &forav1.TransactionItem{Offer: &forav1.Offer{
			Signature: item.OfferSig, Exchange: item.Exchange,
		}})
	}
	return req
}
