// Package canonicalsign renders FORA's canonical signing form and holds the
// acceptance checks around it.
//
// Both kinds of signed FORA payload — an Offer's signature and an agent's
// acceptances — cover a canonical serialization of a protobuf message, defined once
// on Offer.signature in fora.proto (ADR-020 §4):
//
//	signed_payload = JCS( protojson(msg with sig/sig_algorithm cleared) )
//
// i.e. render the message to canonical proto-JSON with a PINNED option set, then
// apply the RFC 8785 JSON Canonicalization Scheme. Deterministic protobuf binary
// marshaling is explicitly NOT canonical across languages/versions (protobuf's own
// caveat), so it cannot be a cross-language signing primitive; JCS over proto-JSON
// CAN be reproduced by any language (Go/TS/Python) without a protobuf binary codec.
//
// PINNED proto-JSON option set (documented in proto/fora.proto):
//   - enums as NAME strings (protojson default; UseEnumNumbers=false)
//   - int64/uint64/fixed64 as strings (protojson default)
//   - bytes as std base64 (protojson default)
//   - google.protobuf.Timestamp / Duration per proto-JSON WKT rules
//   - OMIT unpopulated fields (EmitUnpopulated=false — protojson default)
//   - field naming: snake_case (UseProtoNames=true — the proto field name, matching
//     the wire, the generated Pydantic/Zod clients, and the committed corpus)
//   - google.protobuf.Struct ext → a plain JSON object; JCS then sorts its keys
//     recursively, so the Struct case needs no special handling.
//
// The Go-emitted golden vector is the arbiter: whatever these options render MUST
// be byte-identical across Go(protojson+jcs) / TS / Python, proven by the shared
// offer-verify and acceptance vectors.
//
// The acceptance functions take the requester check as a parameter and run it at
// the exact position the protocol's signer does, with every other check their own.
// helpers passes the check fora.proto requires of a signer; helperstest, whose test
// signers must produce what a verifier refuses, passes one that admits an empty
// requester. One renderer and one copy of every other check serve both, so neither
// can drift.
//
// The messages keep the helpers prefix: helpers' exported functions return them, and
// a caller reads them there. Internal on purpose: none of this is an API of its own.
package canonicalsign

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/gowebpki/jcs"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// JSONOptions is the single, pinned protojson marshal option set every
// canonical-signing site uses. Pinned here (not per call site) so the signed
// payloads cannot drift from each other.
var JSONOptions = protojson.MarshalOptions{
	UseProtoNames:   true,  // snake_case — the naming all three SDK targets share
	UseEnumNumbers:  false, // enums as NAME strings
	EmitUnpopulated: false, // omit unpopulated fields
}

// ErrUnknownFields refuses a message the canonical form cannot faithfully
// represent. helpers exports it as helpers.ErrUnknownFields, which documents it.
var ErrUnknownFields = errors.New("helpers: message carries unknown fields; canonical bytes cannot represent them")

// hasUnknownFields reports whether msg, or anything reachable from it, carries
// fields this build's schema does not define.
//
// The walk is explicit rather than delegated to a traversal helper: this is a
// signature-coverage guard, so its reachability rules are stated here where they
// can be audited against the message tree. Unknown-field sets are PER MESSAGE —
// a nested message and every element of a repeated or map field owns its own —
// so a top-level check alone would pass a payload whose tampering sits one level
// down.
func hasUnknownFields(msg proto.Message) bool {
	if msg == nil {
		return false
	}
	return messageHasUnknown(msg.ProtoReflect())
}

func messageHasUnknown(m protoreflect.Message) bool {
	if !m.IsValid() {
		return false // a typed nil carries nothing
	}
	if len(m.GetUnknown()) > 0 {
		return true
	}
	found := false
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			// Map KEYS are scalars; only a message-typed value can nest one. The
			// synthetic ENTRY messages are not visited: protobuf-go discards unknown
			// bytes planted on an entry at unmarshal, so they never reach here (nor
			// the wire again). helpers/offer_test.go pins that, and fails loudly if a
			// protobuf upgrade starts retaining them.
			if fd.MapValue().Kind() == protoreflect.MessageKind ||
				fd.MapValue().Kind() == protoreflect.GroupKind {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					if messageHasUnknown(mv.Message()) {
						found = true
					}
					return !found
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
				list := v.List()
				for i := 0; i < list.Len() && !found; i++ {
					if messageHasUnknown(list.Get(i).Message()) {
						found = true
					}
				}
			}
		case fd.Kind() == protoreflect.MessageKind, fd.Kind() == protoreflect.GroupKind:
			if messageHasUnknown(v.Message()) {
				found = true
			}
		}
		return !found // stop the range as soon as one is found
	})
	return found
}

// Render renders msg to canonical proto-JSON (pinned options) and applies RFC 8785
// JCS, returning the exact UTF-8 bytes an Ed25519 signature covers. Callers clear
// signature/signature_algorithm on a clone BEFORE calling.
//
// A message carrying unknown fields is refused rather than rendered — see
// ErrUnknownFields.
func Render(msg proto.Message) ([]byte, error) {
	if hasUnknownFields(msg) {
		return nil, ErrUnknownFields
	}
	pj, err := JSONOptions.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("helpers: canonical proto-JSON marshal: %w", err)
	}
	canon, err := jcs.Transform(pj)
	if err != nil {
		return nil, fmt.Errorf("helpers: JCS transform: %w", err)
	}
	return canon, nil
}

// RequesterCheck refuses a requester an acceptance may not name, given its id and
// domain. It runs after the anchor checks and before anything is rendered.
type RequesterCheck func(id, domain string) error

// MaxRequestAcceptanceItems mirrors the repeated.max_items rule on
// AgentRequestAcceptancePayload.items. It is enforced here, before any
// canonicalization work, because a verifier may run with wire validation off and
// rendering an unbounded caller-controlled list to canonical JSON is the expensive
// step. A test pins this constant to the wire rule.
const MaxRequestAcceptanceItems = 256

// AcceptanceBytes returns the canonical bytes of the AgentAcceptancePayload an
// offer acceptance covers, refusing in order: a nil offer, a nil requester, an
// unsigned offer, then whatever check refuses, before rendering.
func AcceptanceBytes(offer *forav1.Offer, requester *forav1.Requester, idempotencyKey string, check RequesterCheck) ([]byte, error) {
	if offer == nil {
		return nil, errors.New("helpers: offer is nil")
	}
	if requester == nil {
		return nil, errors.New("helpers: requester is nil")
	}
	if offer.GetSignature() == "" {
		return nil, errors.New("helpers: cannot accept an unsigned offer (empty offer signature)")
	}
	if err := check(requester.GetId(), requester.GetDomain()); err != nil {
		return nil, err
	}
	return Render(&forav1.AgentAcceptancePayload{
		OfferSig:        offer.GetSignature(),
		RequesterId:     requester.GetId(),
		RequesterDomain: requester.GetDomain(),
		IdempotencyKey:  idempotencyKey,
	})
}

// SignOfferAcceptance signs AcceptanceBytes with priv and returns the hex
// signature, refusing a key of the wrong size before anything else.
func SignOfferAcceptance(priv ed25519.PrivateKey, offer *forav1.Offer, requester *forav1.Requester, idempotencyKey string, check RequesterCheck) (string, error) {
	if err := checkKey(priv); err != nil {
		return "", err
	}
	payload, err := AcceptanceBytes(offer, requester, idempotencyKey, check)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(ed25519.Sign(priv, payload)), nil
}

// RequestAcceptancePayload builds the complete ordered request-set payload from
// req, refusing in order: a nil request, a nil requester, whatever check refuses,
// no items, then each item's missing offer, signature or exchange.
func RequestAcceptancePayload(req *forav1.TransactionRequest, check RequesterCheck) (*forav1.AgentRequestAcceptancePayload, error) {
	if req == nil {
		return nil, errors.New("helpers: transaction request is nil")
	}
	if req.GetRequester() == nil {
		return nil, errors.New("helpers: requester is nil")
	}
	if err := check(req.GetRequester().GetId(), req.GetRequester().GetDomain()); err != nil {
		return nil, err
	}
	if len(req.GetItems()) == 0 {
		return nil, errors.New("helpers: transaction request has no items")
	}
	items := make([]*forav1.AgentRequestAcceptanceItem, 0, len(req.GetItems()))
	for i, item := range req.GetItems() {
		offer := item.GetOffer()
		if offer == nil {
			return nil, fmt.Errorf("helpers: item %d offer is nil", i)
		}
		if offer.GetSignature() == "" {
			return nil, fmt.Errorf("helpers: item %d offer is unsigned", i)
		}
		if offer.GetExchange() == "" {
			return nil, fmt.Errorf("helpers: item %d offer exchange is empty", i)
		}
		items = append(items, &forav1.AgentRequestAcceptanceItem{
			OfferSig: offer.GetSignature(),
			Exchange: offer.GetExchange(),
		})
	}
	return &forav1.AgentRequestAcceptancePayload{
		Items:           items,
		RequesterId:     req.GetRequester().GetId(),
		RequesterDomain: req.GetRequester().GetDomain(),
		IdempotencyKey:  req.GetIdempotencyKey(),
	}, nil
}

// RequestAcceptanceBytes returns the canonical bytes a request acceptance covers,
// refusing in order: a nil payload, whatever check refuses, no items, more than
// MaxRequestAcceptanceItems, then each item's empty offer signature or exchange.
func RequestAcceptanceBytes(payload *forav1.AgentRequestAcceptancePayload, check RequesterCheck) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("helpers: request-acceptance payload is nil")
	}
	if err := check(payload.GetRequesterId(), payload.GetRequesterDomain()); err != nil {
		return nil, err
	}
	if len(payload.GetItems()) == 0 {
		return nil, errors.New("helpers: request-acceptance payload has no items")
	}
	if len(payload.GetItems()) > MaxRequestAcceptanceItems {
		return nil, fmt.Errorf("helpers: request-acceptance payload has %d items, the maximum is %d",
			len(payload.GetItems()), MaxRequestAcceptanceItems)
	}
	for i, item := range payload.GetItems() {
		if item.GetOfferSig() == "" {
			return nil, fmt.Errorf("helpers: request-acceptance item %d offer signature is empty", i)
		}
		if item.GetExchange() == "" {
			return nil, fmt.Errorf("helpers: request-acceptance item %d exchange is empty", i)
		}
	}
	return Render(payload)
}

// SignRequestAcceptance signs req's complete ordered request set with priv,
// refusing a key of the wrong size before anything else, and returns the
// acceptance carrying the payload, the hex signature and algorithm.
func SignRequestAcceptance(priv ed25519.PrivateKey, req *forav1.TransactionRequest, check RequesterCheck, algorithm string) (*forav1.AgentRequestAcceptance, error) {
	if err := checkKey(priv); err != nil {
		return nil, err
	}
	payload, err := RequestAcceptancePayload(req, check)
	if err != nil {
		return nil, err
	}
	canonical, err := RequestAcceptanceBytes(payload, check)
	if err != nil {
		return nil, err
	}
	return &forav1.AgentRequestAcceptance{
		Payload:            payload,
		Signature:          hex.EncodeToString(ed25519.Sign(priv, canonical)),
		SignatureAlgorithm: algorithm,
	}, nil
}

func checkKey(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return nil
}
