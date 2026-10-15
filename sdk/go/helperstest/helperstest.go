// Package helperstest signs agent acceptances that name an empty requester, for a
// test proving that a verifier refuses them.
//
// fora.proto requires an acceptance to name its requester: "A signer refuses to sign
// bytes that name an empty requester, and a verifier refuses an acceptance whose
// canonical bytes name one, even when the signature over those bytes verifies." The
// signers in package helpers are that signer, so they cannot produce the one input a
// verifier's refusal is tested with. The four functions here are their twins with that
// single refusal skipped. They render through the same canonical form and keep every
// other refusal, so an acceptance they sign is valid in every respect but the
// requester, and a verifier's refusal of it is attributable to that alone. The refused
// lists of the shared acceptance-vectors.json and request-acceptance-vectors.json record
// exactly what they produce.
//
// It is test support, as net/http/httptest is: production code never imports it, and
// an acceptance it signs is one a conforming party must never send. Python's
// fora_sdk.testing and TypeScript's @fora-protocol/sdk/testing are its twins.
package helperstest

import (
	"crypto/ed25519"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/canonicalsign"
)

// anyRequester admits every requester, an empty one included. It is unexported, so
// nothing outside this package can pass it to the renderer the signers share.
func anyRequester(string, string) error { return nil }

// CanonicalAcceptanceBytesAnyRequester is helpers.CanonicalAcceptanceBytes without its
// refusal of an empty requester id or domain.
func CanonicalAcceptanceBytesAnyRequester(offer *forav1.Offer, requester *forav1.Requester, idempotencyKey string) ([]byte, error) {
	return canonicalsign.AcceptanceBytes(offer, requester, idempotencyKey, anyRequester)
}

// SignOfferAcceptanceAnyRequester is helpers.SignOfferAcceptance without its refusal of
// an empty requester id or domain.
func SignOfferAcceptanceAnyRequester(priv ed25519.PrivateKey, offer *forav1.Offer, requester *forav1.Requester, idempotencyKey string) (string, error) {
	return canonicalsign.SignOfferAcceptance(priv, offer, requester, idempotencyKey, anyRequester)
}

// CanonicalRequestAcceptanceBytesAnyRequester is helpers.CanonicalRequestAcceptanceBytes
// without its refusal of an empty requester id or domain.
func CanonicalRequestAcceptanceBytesAnyRequester(payload *forav1.AgentRequestAcceptancePayload) ([]byte, error) {
	return canonicalsign.RequestAcceptanceBytes(payload, anyRequester)
}

// SignRequestAcceptanceAnyRequester is helpers.SignRequestAcceptance without its refusal
// of an empty requester id or domain.
func SignRequestAcceptanceAnyRequester(priv ed25519.PrivateKey, req *forav1.TransactionRequest) (*forav1.AgentRequestAcceptance, error) {
	return canonicalsign.SignRequestAcceptance(priv, req, anyRequester, helpers.AcceptanceSignatureAlgorithm)
}
