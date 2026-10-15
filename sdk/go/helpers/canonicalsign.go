package helpers

import "github.com/FORA-Protocol/protocol/sdk/go/internal/canonicalsign"

// The canonical signing form — RFC 8785 JCS over proto-JSON under one pinned option
// set, defined on Offer.signature in fora.proto — is rendered by
// internal/canonicalsign, whose package doc states the pinned options. This
// package's offer and acceptance functions render through it, and so do the test
// signers in helperstest.

// ErrUnknownFields refuses a message the canonical form cannot faithfully
// represent. proto-JSON renders only fields the schema defines, so a message
// carrying unknown ones canonicalizes to bytes that silently omit them. Both
// directions of that gap are wrong: a signer built against a newer schema
// covered more than this build can reconstruct, and an on-path party that
// appends unknown fields to an already-signed message would otherwise leave the
// signature verifying over bytes it never saw. Refusing the message is what
// makes the canonical form's coverage total rather than schema-relative.
//
// CanonicalOfferBytes and SignOffer return it directly, so a caller persisting
// evidence can tell this refusal apart from a marshal fault. VerifyOffer wraps it
// alongside ErrOfferSignatureInvalid — a message that arrived carrying extra bytes
// is a tampered offer — so errors.Is matches either sentinel there.
var ErrUnknownFields = canonicalsign.ErrUnknownFields
