// Code generated from website/src/content/docs/components/exchange/request-flows.mdx
// ("Handler Implementation"). DO NOT EDIT. Regenerate with
// FORA_UPDATE_VECTORS=1 go test ./conformance -run TestDocHandlerExampleCompiles

package requestflows

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/connectserver"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

func (h *ExchangeHandler) DiscoverResources(
	ctx context.Context,
	req *connect.Request[forav1.ResourceQuery],
) (*connect.Response[forav1.ResourceResponse], error) {
	// 1. Validate
	if err := validate(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// 1b. Respect deadline field from ResourceQuery.
	//     If req.Msg.Deadline is set, use it as the context timeout.
	//     If absent, use a 500ms default timeout for the entire handler.
	if req.Msg.Deadline != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Msg.Deadline.AsDuration())
		defer cancel()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
	}

	// 2. Requester identity. Verification already happened at the HTTP seam:
	//    the SDK's verify middleware checked the RFC 9421 signature of the
	//    party that sent the request — the agent, or a Broker that originated
	//    or re-packaged it (Authentication > Multi-hop forwarding) — resolving the signer's key
	//    by its signed keyid (an RFC 7638 thumbprint) in the key directory
	//    named by the `Signature-Agent` member that signature covers. The
	//    self-asserted Requester.domain field never drives request-signing key
	//    lookup.
	//    The handler consumes the proof from the context; it never re-fetches
	//    keys or re-verifies bytes, and it fails closed when the proof is
	//    absent (a route the middleware does not guard).
	requester := req.Msg.Requester
	verified := helpers.FromContext(ctx) // the first verified signature in header order; all of them via helpers.AllSignaturesFromContext
	if verified == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated,
			errors.New("request reached the handler without a verified signature"))
	}

	// 2b. Direct or Broker-led ("Direct and relayed requests" in the protocol).
	//     Requester.domain is the host of the agent's key directory, never a
	//     free label. When it names the directory the signature resolved from
	//     (the host of the covered Signature-Agent URL, compared by the
	//     request-recipient identity rule: case-folded, an absent port the same
	//     as :443), the query is DIRECT: the agent signed it. When it names
	//     another directory, the query is one a Broker originated, which this
	//     Exchange acts on only when it admits the signer as a Broker; there the
	//     domain is the Broker's statement of whom it queries for, and nothing
	//     on this leg authenticates the agent. Any other mismatch is a signature
	//     that verifies, but not for the requester the body names.
	host, err := helpers.HostOf(verified.SignatureAgent)
	verdict := helpers.AudienceMalformed
	if err == nil {
		verdict, err = helpers.CheckAudience(host, requester.GetDomain())
	}
	direct := err == nil && verdict == helpers.AudienceAccepted
	brokerLed := err == nil && verdict == helpers.AudienceMismatch &&
		h.brokers.Admits(verified.SignatureAgent)
	if !direct && !brokerLed {
		return nil, connectserver.AttachDetail(
			connect.NewError(connect.CodeUnauthenticated, errors.New("requester.domain is not the signing directory")),
			helpers.RequestAuthFailureDetail("fora.v1.ExchangeService", "requester.domain is not the signing directory",
				forav1.RequestAuthFailureReason_REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID))
	}

	// 2c. On a DIRECT query, resolve the agent's registered account from the
	//     directory the signature resolved from (verified.SignatureAgent; see
	//     "Accounts" on the authentication page). Every currently valid key that
	//     directory publishes acts for the account, so the key that verified
	//     does not select it, and neither does requester.id, a free label. A
	//     query a Broker originated authenticates no agent, so this Exchange
	//     consults no account for it (its own choice; the protocol leaves it
	//     open) and presents on the stated scopes alone.
	var account *Account
	if direct {
		account, err = h.accounts.ForDirectory(ctx, verified.SignatureAgent)
		if err != nil {
			return nil, connect.NewError(connect.CodePermissionDenied, err)
		}
	}

	// 3. Resolve tenant
	tenantCfg, err := h.tenants.ResolveFromURIs(req.Msg.Uris)
	if err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}

	// 3b. Verify the delegation (if present) on a DIRECT query, once per
	//     subscription record. Trust is per record: the SDK verifier is given
	//     the keys that record lists, so an issuer trusted for one subscription
	//     grants nothing on another. A record whose keys refuse the chain keeps
	//     its gated terms hidden; the refusal is journaled, never reported. The
	//     holder is the RFC 9421 signer's key from the HTTP proof of step 2,
	//     which stays separate from the delegation result. On a query a Broker
	//     originated the Broker signs alone, so nothing can pass the holder
	//     binding: the delegation is not honoured, and the query is answered
	//     as if none were present. A token over the size limit never gets
	//     here: step 1 refused the request.
	grants := map[string]*helpers.VerifiedDelegation{} // subscription record ID -> verified grant
	if direct && requester.GetDelegation() != nil {
		holder, err := helpers.Thumbprint(verified.PublicKey)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		for _, record := range h.subscriptions.RecordsForTenant(ctx, tenantCfg.ID) {
			grant, err := helpers.VerifyDelegation(helpers.DelegationInput{
				Token:          requester.GetDelegation().GetToken(),
				TrustedIssuers: record.TrustedIssuers,
				Audience:       tenantCfg.Identity,
				Holder:         holder,
				Now:            h.clock.Now(),
			})
			if err != nil {
				h.journal.DelegationRefused(ctx, record.ID, err)
				continue
			}
			grants[record.ID] = grant
		}
	}

	// 4. Application-level abuse check (optional — volumetric rate limiting is at infra layer)
	// The Exchange MAY return 429 for application-level abuse, e.g., query-to-transaction
	// ratio too low (agent discovering but never buying). Volumetric rate limiting (per-IP,
	// per-tenant RPS caps) belongs in HAProxy/Envoy/API Gateway in front of this service.

	// 5. Catalog lookup (lock-free read, scope-filtered)
	//    A non-gated term is filtered by requester.scopes, the requester's own
	//    statement — terms outside the stated scopes are not returned. A gated
	//    term (a subscription term) is presented only when the grant verified
	//    under the term's own subscription record covers the term's scopes, by
	//    the one matching rule on Requester.scopes; requester.scopes is ignored
	//    for it, and a record with no grant — every record on a query a Broker
	//    originated (3b) — keeps its gated terms hidden, as if they did not
	//    exist. The catalog bounds each gated offer's expires_at by its grant's
	//    ExpiresAt, so the offer never outlives the chain.
	offers, err := h.catalog.FindOffers(ctx, tenantCfg.ID, req.Msg.Uris, requester.Scopes, grants)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// 5b. Check for active subscription, on a DIRECT query (step 2d).
	//     If the requester has an active subscription with this tenant, include a
	//     subscription offer variant (rate=0) for each catalog offer with
	//     SubscriptionQuotaInfo attached. Quota enforcement is deferred to
	//     ExecuteTransaction time — DiscoverResources checks subscription status
	//     and populates quota visibility. Subscription/entitlement is resolved
	//     from the registered account of step 2d (plus any delegation) — never
	//     from the caller-written requester.id. A query a Broker originated has
	//     no account here, so it gets no subscription variant.
	var subStatus *SubscriptionStatus
	if account != nil {
		if sub, err := h.billing.CheckSubscription(ctx, account.BillingRef, tenantCfg.ID); err == nil && sub.Active {
			subStatus = sub
		}
	}

	// Build subscription offer variants per catalog offer (if subscription active).
	// Each subscription offer includes SubscriptionQuotaInfo so agents can see
	// remaining quota before committing to a transaction.
	if subStatus != nil {
		var subOffers []*forav1.Offer
		for _, offer := range offers {
			subOffer := proto.Clone(offer).(*forav1.Offer)
			// A subscription variant is a distinct offer, so it gets a fresh
			// opaque offer_id — never one derived from the base offer's id.
			subOffer.OfferId = "offer-" + newOpaqueID()
			subOffer.SubscriptionId = proto.String(subStatus.SubscriptionID)
			subOffer.Pricing = &forav1.Pricing{
				Model:             offer.Pricing.Model,
				Rate:              "0", // zero marginal cost under subscription; money is a decimal string
				Currency:          offer.Pricing.Currency,
				UnitCost:          proto.String("0"),
				EstimatedQuantity: offer.Pricing.EstimatedQuantity,
			}
			// Populate SubscriptionQuotaInfo for proactive quota signaling
			subOffer.SubscriptionQuota = h.billing.SubscriptionQuota(
				ctx, subStatus.SubscriptionID, tenantCfg.ID,
			)
			subOffers = append(subOffers, subOffer)
		}
		offers = append(offers, subOffers...)
	}

	// 6. Attach reporting obligations (per-tenant default, not per-offer lookup)
	//    Reporting obligation is set once in tenant config. All offers inherit the
	//    tenant's reporting obligation unless explicitly overridden (rare).
	tenantReporting := h.reporting.GetPolicy(tenantCfg.ID)
	for _, offer := range offers {
		offer.Reporting = tenantReporting
	}

	// 7. Ed25519-sign every offer (MANDATORY — enables stateless ExecuteTransaction)
	//    Ed25519 is the default for offers because agents and Brokers must
	//    verify signatures without holding the signing key. The Exchange signs
	//    with its Ed25519 private key; anyone verifies with the public key.
	for _, offer := range offers {
		sig, err := h.offerSigner.Sign(offer)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		offer.Signature = sig
		offer.SignatureAlgorithm = "EdDSA"
	}

	// 8. Build response — flat offers or OfferGroups depending on URI count.
	//    When the ResourceQuery contains multiple URIs, return OfferGroups
	//    (one per URI) so the caller knows which offers map to which resource.
	//    When a single URI is queried, use the flat offers field.
	uris := req.Msg.Uris
	if len(uris) > 1 {
		// Batch mode: group offers by requested URI.
		groups := make([]*forav1.OfferGroup, 0, len(uris))
		for _, uri := range uris {
			var uriOffers []*forav1.Offer
			for _, offer := range offers {
				if offerMatchesURI(offer, uri) {
					uriOffers = append(uriOffers, offer)
				}
			}
			groups = append(groups, &forav1.OfferGroup{
				Uri:    uri,
				Offers: uriOffers, // empty slice = resource not available for this URI
			})
		}
		return connect.NewResponse(&forav1.ResourceResponse{
			Ver:         helpers.ProtocolVersion,
			Exchange:    h.exchangeDomain,
			OfferGroups: groups,
		}), nil
		// Correlation is not echoed in the body: it rides the X-Request-ID
		// HTTP header, propagated across the request/response round-trip.
	}

	return connect.NewResponse(&forav1.ResourceResponse{
		Ver:      helpers.ProtocolVersion,
		Exchange: h.exchangeDomain,
		Offers:   offers,
	}), nil
}
