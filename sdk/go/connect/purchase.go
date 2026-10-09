package connect

import (
	"context"
	"errors"
	"fmt"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// purchase is what every purchase verb builds a TransactionRequest from: the
// agent's identity and custody, the offers it accepts, and the key the action is
// identified by. The three verbs that buy — Client.Execute, Client.ExecuteBatch
// and BrokerClient.Execute — differ in which offers they admit and where the
// request goes, never in how the request is built, so the building lives here
// once.
type purchase struct {
	op        string
	signer    helpers.Signer
	requester *forav1.Requester
	offers    []core.VerifiedOffer
	opts      []CallOption
}

// buildTransaction assembles and signs the TransactionRequest for p.
//
// Each item reflects its signed Offer back exactly as received at discovery and
// carries the agent's detached acceptance of that one offer. The request-level
// AgentRequestAcceptance over the complete ordered item set is attached when
// every offer names its Exchange; an item without one cannot appear in that
// payload, which requires a recipient per item. ver comes from
// helpers.ProtocolVersion — the single owner of the protocol version across all
// three SDKs — never a literal.
//
// Every acceptance covers the offer, the requester and the idempotency key, so a
// retry that pins the same key reproduces byte-identical acceptance bytes. That
// is the deliberate-replay semantic, not an accident.
func buildTransaction(ctx context.Context, p purchase) (*forav1.TransactionRequest, error) {
	if p.requester == nil {
		return nil, malformed(p.op, errors.New(
			"no requester configured; the party that sells resolves who is buying (see WithRequester)"))
	}
	if err := requireNamedRequester(p.op, p.requester); err != nil {
		return nil, err
	}
	if p.signer == nil {
		// CallNotSignable, matching what Fetch answers for the same missing
		// holder: a caller branching on the kind sees one condition under one
		// class, whichever verb met it first.
		return nil, &CallError{Kind: CallNotSignable, Op: p.op, Err: errors.New(
			"no signer configured; a purchase carries a detached acceptance signed with the agent's own key (see WithSigner)")}
	}
	if len(p.offers) == 0 {
		return nil, malformed(p.op, errors.New("no offers to buy"))
	}
	allAddressed := true
	for i, offer := range p.offers {
		// An acceptance floating free of a concrete offer is meaningless, and an
		// unsigned offer is reachable here: WithVerification(Off) and
		// RejectedOffer.Unsafe() both mint a VerifiedOffer without a signature check.
		if offer.Offer().GetSignature() == "" {
			return nil, malformed(p.op, fmt.Errorf("cannot accept an unsigned offer (item %d)", i))
		}
		if offer.Offer().GetExchange() == "" {
			allAddressed = false
		}
	}
	key, err := idempotencyKeyFor(p.opts, "")
	if err != nil {
		return nil, malformed(p.op, err)
	}
	req := &forav1.TransactionRequest{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: key,
		Requester:      p.requester,
		Items:          make([]*forav1.TransactionItem, 0, len(p.offers)),
	}
	for _, offer := range p.offers {
		acceptance, signErr := helpers.SignOfferAcceptanceWith(ctx, p.signer, offer.Offer(), p.requester, key)
		if signErr != nil {
			return nil, &CallError{Kind: CallNotSignable, Op: p.op, Err: signErr}
		}
		req.Items = append(req.Items, &forav1.TransactionItem{
			Offer: offer.Offer(),
			AgentAcceptance: &forav1.AgentAcceptance{
				Signature:          acceptance,
				SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
			},
		})
	}
	if allAddressed {
		requestAcceptance, signErr := helpers.SignRequestAcceptanceWith(ctx, p.signer, req)
		if signErr != nil {
			return nil, &CallError{Kind: CallNotSignable, Op: p.op, Err: signErr}
		}
		req.AgentRequestAcceptance = requestAcceptance
	}
	return req, nil
}

// requireNamedRequester refuses a requester with an empty id or an empty domain.
// Every acceptance a purchase carries names the requester, and the protocol
// requires both fields, so the signer would refuse to sign anyway; refusing here
// reports the condition as CallMalformed, the configuration fault it is, rather
// than as a custody failure. The error wraps helpers.ErrAcceptanceRequesterEmpty.
func requireNamedRequester(op string, requester *forav1.Requester) error {
	var missing string
	switch {
	case requester.GetId() == "":
		missing = "requester.id"
	case requester.GetDomain() == "":
		missing = "requester.domain"
	default:
		return nil
	}
	return malformed(op, fmt.Errorf(
		"%w: %s is empty; a purchase's acceptances name the requester, and both requester.id "+
			"and requester.domain are required (see WithRequester)",
		helpers.ErrAcceptanceRequesterEmpty, missing))
}

// requireOneExchange refuses a direct purchase whose offers were issued by more
// than one Exchange. A direct purchase goes to one Exchange, and that Exchange
// refuses a request carrying an item addressed to anyone else, so the verdict is
// already known here. A purchase across Exchanges is what BrokerClient.Execute is
// for.
func requireOneExchange(op string, offers []core.VerifiedOffer) error {
	if len(offers) == 0 {
		return nil
	}
	first := offers[0].Offer().GetExchange()
	for i, offer := range offers[1:] {
		if offer.Offer().GetExchange() != first {
			return malformed(op, fmt.Errorf(
				"item %d is issued by %q and item 0 by %q; a direct purchase goes to one Exchange "+
					"(buy across Exchanges with BrokerClient.Execute)",
				i+1, offer.Offer().GetExchange(), first))
		}
	}
	return nil
}

// requireRoutable refuses a relayed purchase carrying an offer that names no
// Exchange. A Broker groups the items by each offer's exchange and dials that
// Exchange, so an offer without one has nowhere to go.
func requireRoutable(op string, offers []core.VerifiedOffer) error {
	for i, offer := range offers {
		if offer.Offer().GetExchange() == "" {
			return malformed(op, fmt.Errorf(
				"item %d names no exchange; a Broker routes each item to the Exchange its offer names", i))
		}
	}
	return nil
}

// requireRequesterIsSigner refuses a request whose requester.domain is not the
// host of the WBA directory this client signs as.
//
// A Broker verifies the agent's request signature against the key it resolves
// from the covered Signature-Agent directory, and then requires requester.domain
// to name that same directory: every Exchange the Broker relays to resolves the
// agent's acceptance keys from requester.domain, so a mismatch could only be
// refused there. The Broker refuses it first, with request_auth_failure
// SIGNATURE_INVALID, and so does this client, before anything is sent.
//
// The comparison is the recipient-identity rule: exact, case-folded, with an
// explicit :443 the same as no port. An unset Signature-Agent names no directory
// at all, so it fails the comparison too.
func requireRequesterIsSigner(op string, requester *forav1.Requester, signatureAgent string) error {
	if signatureAgent == "" {
		return malformed(op, errors.New(
			"no Signature-Agent configured; a Broker checks that requester.domain names the directory "+
				"the request is signed from (see WithSignatureAgent)"))
	}
	host, err := helpers.HostOf(signatureAgent)
	if err != nil {
		return malformed(op, fmt.Errorf("signature agent %q names no host: %w",
			helpers.RedactURL(signatureAgent), err))
	}
	verdict, err := helpers.CheckAudience(host, requester.GetDomain())
	if err != nil {
		return malformed(op, fmt.Errorf("signature agent host %q is not a bare domain: %w", host, err))
	}
	if verdict != helpers.AudienceAccepted {
		return malformed(op, fmt.Errorf(
			"requester.domain %q is not %q, the host of the directory this client signs as; "+
				"a Broker refuses the request (request_auth_failure SIGNATURE_INVALID)",
			requester.GetDomain(), host))
	}
	return nil
}
