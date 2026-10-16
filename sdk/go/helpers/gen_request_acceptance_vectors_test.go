package helpers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

type requestAcceptanceVectorItem struct {
	OfferSig string `json:"offer_sig"`
	Exchange string `json:"exchange"`
}

type requestAcceptanceVector struct {
	Name            string                        `json:"name"`
	Items           []requestAcceptanceVectorItem `json:"items"`
	RequesterID     string                        `json:"requester_id"`
	RequesterDomain string                        `json:"requester_domain"`
	IdempotencyKey  string                        `json:"idempotency_key"`
	CanonicalJCS    string                        `json:"canonical_jcs"`
	SignatureHex    string                        `json:"signature_hex"`
	PubkeyB64       string                        `json:"pubkey_b64"`
	SeedHex         string                        `json:"seed_hex"`
}

func TestGenerateRequestAcceptanceVectors(t *testing.T) {
	seed, err := hex.DecodeString(acceptanceSeedHex)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	specs := []requestAcceptanceVector{
		{
			Name: "mixed_exchange_order",
			Items: []requestAcceptanceVectorItem{
				{OfferSig: "sig-a", Exchange: "one.example"},
				{OfferSig: "sig-b", Exchange: "two.example"},
				{OfferSig: "sig-c", Exchange: "one.example"},
			},
			RequesterID: "agent-1", RequesterDomain: "agent.example", IdempotencyKey: "idem-1",
		},
		// The one field the canonical form can still omit; see the offer
		// acceptance's empty_idempotency_key vector.
		{
			Name:        "empty_idempotency_key",
			Items:       []requestAcceptanceVectorItem{{OfferSig: "sig-y", Exchange: "one.example"}},
			RequesterID: "agent-3", RequesterDomain: "agent.example",
		},
	}
	for i := range specs {
		v := &specs[i]
		req := &forav1.TransactionRequest{
			IdempotencyKey: v.IdempotencyKey,
			Requester:      &forav1.Requester{Id: v.RequesterID, Domain: v.RequesterDomain},
		}
		for _, item := range v.Items {
			req.Items = append(req.Items, &forav1.TransactionItem{Offer: &forav1.Offer{
				Signature: item.OfferSig, Exchange: item.Exchange,
			}})
		}
		acceptance, err := SignRequestAcceptance(priv, req)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		canonical, err := CanonicalRequestAcceptanceBytes(acceptance.GetPayload())
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		v.CanonicalJCS = string(canonical)
		v.SignatureHex = acceptance.GetSignature()
		v.PubkeyB64 = base64.StdEncoding.EncodeToString(pub)
		v.SeedHex = acceptanceSeedHex
	}
	doc := map[string]any{
		"canonicalization": "jcs",
		"vectors":          specs,
		"refused":          buildRefusedRequestAcceptanceVectors(t, priv),
	}
	path := filepath.Join("testdata", "request-acceptance-vectors.json")
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeJSON(t, path, doc)
		return
	}
	assertMatches(t, path, doc)
}

// refusedRequestAcceptanceVector is a request acceptance whose payload names an
// empty requester. As for the offer acceptance, every SDK must refuse it at the
// canonical-bytes function, the signer and the verifier. CanonicalJCS and
// SignatureHex are rendered and signed below the refusal, so the verifier's
// refusal is proven against a signature that verifies over those bytes. Empty
// names the field left empty.
type refusedRequestAcceptanceVector struct {
	Name            string                        `json:"name"`
	Empty           string                        `json:"empty"`
	Items           []requestAcceptanceVectorItem `json:"items"`
	RequesterID     string                        `json:"requester_id"`
	RequesterDomain string                        `json:"requester_domain"`
	IdempotencyKey  string                        `json:"idempotency_key"`
	CanonicalJCS    string                        `json:"canonical_jcs"`
	SignatureHex    string                        `json:"signature_hex"`
	PubkeyB64       string                        `json:"pubkey_b64"`
	SeedHex         string                        `json:"seed_hex"`
}

func buildRefusedRequestAcceptanceVectors(t *testing.T, priv ed25519.PrivateKey) []refusedRequestAcceptanceVector {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	specs := []refusedRequestAcceptanceVector{
		{Name: "empty_requester_id", Empty: "requester_id",
			Items:           []requestAcceptanceVectorItem{{OfferSig: "sig-x", Exchange: "one.example"}},
			RequesterDomain: "agent.example", IdempotencyKey: "idem-4"},
		{Name: "empty_requester_domain", Empty: "requester_domain",
			Items:       []requestAcceptanceVectorItem{{OfferSig: "sig-z", Exchange: "one.example"}},
			RequesterID: "agent-2", IdempotencyKey: "idem-2"},
	}
	for i := range specs {
		v := &specs[i]
		req := &forav1.TransactionRequest{
			IdempotencyKey: v.IdempotencyKey,
			Requester:      &forav1.Requester{Id: v.RequesterID, Domain: v.RequesterDomain},
		}
		payload := &forav1.AgentRequestAcceptancePayload{
			RequesterId: v.RequesterID, RequesterDomain: v.RequesterDomain, IdempotencyKey: v.IdempotencyKey,
		}
		for _, item := range v.Items {
			req.Items = append(req.Items, &forav1.TransactionItem{Offer: &forav1.Offer{
				Signature: item.OfferSig, Exchange: item.Exchange,
			}})
			payload.Items = append(payload.Items, &forav1.AgentRequestAcceptanceItem{
				OfferSig: item.OfferSig, Exchange: item.Exchange,
			})
		}
		unchecked, err := canonicalSignPayload(payload)
		if err != nil {
			t.Fatalf("%s: unchecked render: %v", v.Name, err)
		}
		sig := ed25519.Sign(priv, unchecked)
		if _, err := CanonicalRequestAcceptanceBytes(payload); !errors.Is(err, ErrAcceptanceRequesterEmpty) {
			t.Fatalf("%s: CanonicalRequestAcceptanceBytes = %v, want ErrAcceptanceRequesterEmpty", v.Name, err)
		}
		if _, err := SignRequestAcceptance(priv, req); !errors.Is(err, ErrAcceptanceRequesterEmpty) {
			t.Fatalf("%s: SignRequestAcceptance = %v, want ErrAcceptanceRequesterEmpty", v.Name, err)
		}
		acceptance := &forav1.AgentRequestAcceptance{
			Payload: payload, Signature: hex.EncodeToString(sig), SignatureAlgorithm: AcceptanceSignatureAlgorithm,
		}
		if _, err := VerifyRequestAcceptance(req, acceptance, pub); !errors.Is(err, ErrAcceptanceRequesterEmpty) {
			t.Fatalf("%s: VerifyRequestAcceptance = %v, want ErrAcceptanceRequesterEmpty", v.Name, err)
		}
		v.CanonicalJCS = string(unchecked)
		v.SignatureHex = hex.EncodeToString(sig)
		v.PubkeyB64 = base64.StdEncoding.EncodeToString(pub)
		v.SeedHex = acceptanceSeedHex
	}
	return specs
}
