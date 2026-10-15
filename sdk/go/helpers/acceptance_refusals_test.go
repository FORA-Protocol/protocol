package helpers_test

// The refusals of the acceptance canonicalizers and signers, pinned: the exact text,
// the sentinel a caller matches, and which refusal wins when an input has several
// faults. The canonical renderer and the checks around it are shared with code that
// skips one of them, so the order and the wording are part of what must not move.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// refusal is one input that must be refused, the message it must be refused with, and
// the sentinel it must match (nil when it wraps none).
type refusal struct {
	name     string
	call     func() error
	message  string
	sentinel error
}

func assertRefusals(t *testing.T, cases []refusal) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			if err == nil {
				t.Fatal("accepted, want a refusal")
			}
			if err.Error() != c.message {
				t.Errorf("message = %q, want %q", err.Error(), c.message)
			}
			if c.sentinel != nil && !errors.Is(err, c.sentinel) {
				t.Errorf("%v does not match %v", err, c.sentinel)
			}
		})
	}
}

// offAlgSigner is a Signer offering an algorithm the acceptances do not accept.
type offAlgSigner struct{}

func (offAlgSigner) KeyID() string                                { return "k" }
func (offAlgSigner) Algorithm() string                            { return "ecdsa-p256-sha256" }
func (offAlgSigner) Sign(context.Context, []byte) ([]byte, error) { return nil, nil }

var (
	signedOffer   = &forav1.Offer{Signature: "sig", Exchange: "one.example"}
	unsignedOffer = &forav1.Offer{Exchange: "one.example"}
	named         = &forav1.Requester{Id: "agent-1", Domain: "agent.example"}
	noID          = &forav1.Requester{Domain: "agent.example"}
	noDomain      = &forav1.Requester{Id: "agent-1"}
)

const (
	msgOfferNil     = "helpers: offer is nil"
	msgRequesterNil = "helpers: requester is nil"
	msgUnsigned     = "helpers: cannot accept an unsigned offer (empty offer signature)"
	msgNoID         = "helpers: acceptance names an empty requester: requester id is empty"
	msgNoDomain     = "helpers: acceptance names an empty requester: requester domain is empty"
	msgShortKey     = "helpers: ed25519 private key must be 64 bytes, got 3"
)

func TestOfferAcceptanceRefusals(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer("k", priv)
	if err != nil {
		t.Fatal(err)
	}
	canonical := func(o *forav1.Offer, r *forav1.Requester) func() error {
		return func() error { _, err := helpers.CanonicalAcceptanceBytes(o, r, "idem"); return err }
	}
	sign := func(k ed25519.PrivateKey, o *forav1.Offer, r *forav1.Requester) func() error {
		return func() error { _, err := helpers.SignOfferAcceptance(k, o, r, "idem"); return err }
	}
	signWith := func(s helpers.Signer, o *forav1.Offer, r *forav1.Requester) func() error {
		return func() error {
			_, err := helpers.SignOfferAcceptanceWith(context.Background(), s, o, r, "idem")
			return err
		}
	}
	assertRefusals(t, []refusal{
		{"canonical: nil offer", canonical(nil, named), msgOfferNil, nil},
		{"canonical: nil requester", canonical(signedOffer, nil), msgRequesterNil, nil},
		{"canonical: unsigned offer", canonical(unsignedOffer, named), msgUnsigned, nil},
		{"canonical: no requester id", canonical(signedOffer, noID), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{"canonical: no requester domain", canonical(signedOffer, noDomain), msgNoDomain, helpers.ErrAcceptanceRequesterEmpty},
		{"canonical: nil offer before an empty requester", canonical(nil, noID), msgOfferNil, nil},
		{"canonical: unsigned offer before an empty requester", canonical(unsignedOffer, noID), msgUnsigned, nil},
		{"sign: short key before anything", sign(priv[:3], nil, noID), msgShortKey, nil},
		{"sign: unsigned offer", sign(priv, unsignedOffer, named), msgUnsigned, nil},
		{"sign: no requester id", sign(priv, signedOffer, noID), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{"sign with: nil signer", signWith(nil, signedOffer, named), "helpers: acceptance signer is nil", nil},
		{
			"sign with: an algorithm other than ed25519", signWith(offAlgSigner{}, signedOffer, noID),
			`helpers: unsupported alg (ed25519 only): offer acceptance requires "ed25519", signer offers "ecdsa-p256-sha256"`,
			helpers.ErrUnsupportedAlgorithm,
		},
		{"sign with: no requester domain", signWith(signer, signedOffer, noDomain), msgNoDomain, helpers.ErrAcceptanceRequesterEmpty},
	})
}

func TestRequestAcceptanceRefusals(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := helpers.NewEd25519Signer("k", priv)
	if err != nil {
		t.Fatal(err)
	}
	item := func(o *forav1.Offer) *forav1.TransactionItem { return &forav1.TransactionItem{Offer: o} }
	req := func(r *forav1.Requester, items ...*forav1.TransactionItem) *forav1.TransactionRequest {
		return &forav1.TransactionRequest{Requester: r, IdempotencyKey: "idem", Items: items}
	}
	payloadOf := func(q *forav1.TransactionRequest) func() error {
		return func() error { _, err := helpers.RequestAcceptancePayload(q); return err }
	}
	payload := func(id, domain string, items ...*forav1.AgentRequestAcceptanceItem) *forav1.AgentRequestAcceptancePayload {
		return &forav1.AgentRequestAcceptancePayload{
			Items: items, RequesterId: id, RequesterDomain: domain, IdempotencyKey: "idem",
		}
	}
	accepted := func(sig, exchange string) *forav1.AgentRequestAcceptanceItem {
		return &forav1.AgentRequestAcceptanceItem{OfferSig: sig, Exchange: exchange}
	}
	canonical := func(p *forav1.AgentRequestAcceptancePayload) func() error {
		return func() error { _, err := helpers.CanonicalRequestAcceptanceBytes(p); return err }
	}
	tooMany := make([]*forav1.AgentRequestAcceptanceItem, helpers.MaxRequestAcceptanceItemsForTest+1)
	for i := range tooMany {
		tooMany[i] = accepted("sig", "one.example")
	}
	sign := func(k ed25519.PrivateKey, q *forav1.TransactionRequest) func() error {
		return func() error { _, err := helpers.SignRequestAcceptance(k, q); return err }
	}
	signWith := func(s helpers.Signer, q *forav1.TransactionRequest) func() error {
		return func() error {
			_, err := helpers.SignRequestAcceptanceWith(context.Background(), s, q)
			return err
		}
	}
	assertRefusals(t, []refusal{
		{"payload: nil request", payloadOf(nil), "helpers: transaction request is nil", nil},
		{"payload: nil requester", payloadOf(req(nil, item(signedOffer))), msgRequesterNil, nil},
		{"payload: no requester id", payloadOf(req(noID, item(signedOffer))), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{"payload: no requester domain", payloadOf(req(noDomain, item(signedOffer))), msgNoDomain, helpers.ErrAcceptanceRequesterEmpty},
		{"payload: no items", payloadOf(req(named)), "helpers: transaction request has no items", nil},
		{"payload: an empty requester before no items", payloadOf(req(noID)), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{"payload: an item with no offer", payloadOf(req(named, item(nil))), "helpers: item 0 offer is nil", nil},
		{"payload: an unsigned item", payloadOf(req(named, item(unsignedOffer))), "helpers: item 0 offer is unsigned", nil},
		{
			"payload: an item naming no exchange", payloadOf(req(named, item(&forav1.Offer{Signature: "sig"}))),
			"helpers: item 0 offer exchange is empty", nil,
		},
		{"canonical: nil payload", canonical(nil), "helpers: request-acceptance payload is nil", nil},
		{"canonical: no requester id", canonical(payload("", "agent.example", accepted("sig", "one.example"))), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{"canonical: no requester domain", canonical(payload("agent-1", "", accepted("sig", "one.example"))), msgNoDomain, helpers.ErrAcceptanceRequesterEmpty},
		{"canonical: no items", canonical(payload("agent-1", "agent.example")), "helpers: request-acceptance payload has no items", nil},
		{"canonical: an empty requester before no items", canonical(payload("", "agent.example")), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{
			"canonical: too many items", canonical(payload("agent-1", "agent.example", tooMany...)),
			"helpers: request-acceptance payload has 257 items, the maximum is 256", nil,
		},
		{
			"canonical: an item with no offer signature", canonical(payload("agent-1", "agent.example", accepted("", "one.example"))),
			"helpers: request-acceptance item 0 offer signature is empty", nil,
		},
		{
			"canonical: an item naming no exchange", canonical(payload("agent-1", "agent.example", accepted("sig", ""))),
			"helpers: request-acceptance item 0 exchange is empty", nil,
		},
		{"sign: short key before anything", sign(priv[:3], nil), msgShortKey, nil},
		{"sign: no requester id", sign(priv, req(noID, item(signedOffer))), msgNoID, helpers.ErrAcceptanceRequesterEmpty},
		{"sign: no items", sign(priv, req(named)), "helpers: transaction request has no items", nil},
		{"sign with: nil signer", signWith(nil, req(named, item(signedOffer))), "helpers: request-acceptance signer is nil", nil},
		{
			"sign with: an algorithm other than ed25519", signWith(offAlgSigner{}, req(noID)),
			`helpers: unsupported alg (ed25519 only): request acceptance requires "ed25519", signer offers "ecdsa-p256-sha256"`,
			helpers.ErrUnsupportedAlgorithm,
		},
		{"sign with: no requester domain", signWith(signer, req(noDomain, item(signedOffer))), msgNoDomain, helpers.ErrAcceptanceRequesterEmpty},
	})
}
