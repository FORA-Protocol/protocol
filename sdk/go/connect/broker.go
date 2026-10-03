package connect

import (
	"context"
	"errors"

	connectrpc "connectrpc.com/connect"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// BrokerClient is the Connect client for BrokerService.
//
// It is a SEPARATE constructor rather than a second surface on the exchange
// client because the two speak to different parties. A Broker is not an
// Exchange: it fans a query out across Exchanges it knows and relays back what
// they offered, so its address is the Broker's, not any Exchange's. Hanging both
// off one base URL would mean one of the two was always pointed at the wrong
// party.
//
// It shares the exchange client's plumbing — the same signing transport, the same
// cross-cutting interceptors, the same fail-closed offer Verifier — so the two
// faces cannot drift in how they sign, correlate, validate or verify.
type BrokerClient struct {
	rpc      forav1connect.BrokerServiceClient
	verifier core.Verifier
	// requester is the agent identity a Broker resolves the caller from. Held
	// here rather than demanded on every request for the same reason the exchange
	// client holds it: one client speaks for one agent.
	requester *forav1.Requester
	// signer signs the detached acceptances a relayed purchase carries — the same
	// key that signs the transport, because the protocol carries one agent identity.
	signer helpers.Signer
	// signatureAgent is the WBA directory this client signs as. A Broker requires
	// requester.domain to name it, so Execute checks the two agree before sending.
	signatureAgent string

	baseURL string
	raw     rawLeg
}

// NewBrokerClient builds a BrokerClient against a Broker's base URL. It accepts
// the same option type as NewClient, but only the options a discovery call has
// any use for actually do anything, and two of those need care:
//
//   - WithOfferKey pins a SINGLE offer-verifying key for every exchange, which is
//     the wrong shape here. Broker fan-out returns offers minted by different
//     Exchanges, so anything not signed by that one key lands in Rejected. Inject
//     WithKeyResolver instead — the resolvers tier ships one that resolves each
//     issuing Exchange's own key.
//   - WithRequester is REQUIRED, not optional: a Broker resolves the calling agent
//     from it and declines a request that names none, so Resolve and Execute refuse
//     locally rather than spending a round trip to be told.
//   - WithSigner and WithSignatureAgent are required by Execute: a relayed purchase
//     carries acceptances signed with the agent's key, and a Broker refuses a
//     requester.domain that does not name the directory the request is signed from.
//
// The options that do nothing here are the ones belonging to legs a Broker client
// does not have: WithAgentKey, WithProofWindow and WithContentTimeout /
// WithMaxContentBytes configure the delivery fetch; WithEndpointResolver and
// WithGuardedBaseTransport configure the offer-derived leg. Both legs live on the
// exchange client. Passing them here is silently inert rather than an error, so
// one shared option set can build both faces.
//
// BrokerService carries two methods, Resolve and ExecuteTransaction, and this type
// has one verb for each.
func NewBrokerClient(baseURL string, opts ...ClientOption) *BrokerClient {
	cfg := resolvedConfig(opts...)
	httpClient, connectOpts, verifier := plumbing(cfg)
	return &BrokerClient{
		rpc:            forav1connect.NewBrokerServiceClient(httpClient, baseURL, connectOpts...),
		verifier:       verifier,
		requester:      cfg.requester,
		signer:         cfg.signer,
		signatureAgent: cfg.signatureAgent,
		baseURL:        baseURL,
		raw:            newRawLeg(cfg, httpClient),
	}
}

// Resolve runs discovery through the Broker, which fans out to the Exchanges it
// knows and returns one group per requested URI.
//
// Every returned offer is verified through the SAME fail-closed Verifier
// Discover uses — not a second verification path. Broker-relayed offers are
// precisely the case that rule exists for: the Broker forwards offers it did not
// mint, and an unverified relay can steer an agent's selection with doctored
// terms that only fail later, at the purchase.
//
// A resolve that finds nothing is a SUCCESSFUL answer carrying a typed reason,
// not an error: the whole-call reason lands on DiscoveryResult.AbsenceReason and
// the per-URI ones on each group. Only a genuine fault returns an error.
//
// Resolve carries no idempotency key. Pure discovery buys nothing and changes
// nothing, so there is nothing for a server to deduplicate — the request message
// has no such field.
//
// The request is CLONED before ver and the requester are filled in, so the message
// the caller built stays untouched. Both are filled only when EMPTY: a value the
// caller set is theirs. A Broker resolves the calling agent from requester.id and
// refuses a request that names none, so leaving it to every caller to remember
// would make the identity the client already holds useless exactly where it is
// needed.
//
// WithRawBody sends caller bytes instead; the answer's offers are still verified.
func (b *BrokerClient) Resolve(ctx context.Context, req *forav1.DiscoveryRequest, opts ...CallOption) (core.DiscoveryResult, error) {
	const op = "resolve"
	if cc := resolveCall(opts); cc.rawSet {
		msg, err := rawCall[forav1.DiscoveryResponse](ctx, b.raw, op, b.baseURL,
			forav1connect.BrokerServiceResolveProcedure, cc.rawBody)
		if err != nil {
			return core.DiscoveryResult{}, err
		}
		return b.discoveryResult(ctx, msg), nil
	}
	if req == nil {
		return core.DiscoveryResult{}, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	stampDiscovery(&sent.Ver, &sent.Requester, b.requester)
	// Refused locally rather than sent: a Broker resolves the calling agent from
	// the requester and declines a request that names none, so this is a verdict
	// the client already knows, and naming the remedy beats relaying "requester
	// required" from a round trip away. Execute refuses the same way.
	if sent.Requester == nil {
		return core.DiscoveryResult{}, malformed(op, errors.New(
			"no requester configured; a Broker resolves who is asking (see WithRequester)"))
	}
	resp, err := b.rpc.Resolve(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return core.DiscoveryResult{}, sendError(op, err)
	}
	return b.discoveryResult(ctx, resp.Msg), nil
}

func (b *BrokerClient) discoveryResult(ctx context.Context, msg *forav1.DiscoveryResponse) core.DiscoveryResult {
	return core.DiscoveryResult{
		Groups: b.verifier.SortGroups(ctx, msg.GetOfferGroups()),
		// The raw field, not the getter: an absent optional enum and the
		// unspecified value are different answers, and a getter collapses them.
		AbsenceReason: msg.AbsenceReason,
		// A DiscoveryResponse names no single Exchange and carries no rate-limit
		// signal — each offer carries its own issuing domain instead.
	}
}

// Execute buys VERIFIED offers through the Broker in one call, however many
// Exchanges issued them (BrokerService.ExecuteTransaction).
//
// The client builds the same TransactionRequest a direct purchase sends — every
// item with the agent's detached AgentAcceptance, and one AgentRequestAcceptance
// over the complete ordered set — and stamps ver and the configured requester.
// The Broker re-packages it: it groups the items by each offer's exchange, sends
// one sub-request per Exchange signed with its own key, and combines the answers.
// The acceptances travel in each sub-request body, so every Exchange still
// verifies the agent's consent. The idempotency key is the action's, minted fresh
// unless WithIdempotencyKey pins one; the Broker forwards it unchanged to every
// Exchange, so a retry with the same key is answered from each Exchange's stored
// result.
//
// Refused locally, with nothing sent: no requester, or one with an empty id or
// domain (CallMalformed), no signer (CallNotSignable), no offers, an unsigned
// offer, an offer that names no exchange, and a requester.domain that is not the
// host of the directory this client signs as (all CallMalformed). The last mirrors the Broker's own check,
// which it refuses with request_auth_failure SIGNATURE_INVALID.
//
// An Exchange that refused the Broker's whole sub-request is NOT an error here:
// the call succeeds, and each affected item carries the refusal in
// TransactionResultItem.Refusal while the other Exchanges' items come back
// unchanged. Only the Broker's own refusals — a bad signature, a malformed
// request, an Exchange it cannot route to or does not approve — return an error,
// and then nothing was bought.
//
// Each item's retrieval_endpoint is returned exactly as the issuing Exchange
// signed it, as Client.Execute returns its own. Verifying it is the delivery
// edge's job.
func (b *BrokerClient) Execute(ctx context.Context, offers []core.VerifiedOffer, opts ...CallOption) (*forav1.BrokerTransactionResponse, error) {
	const op = "broker execute"
	cc := resolveCall(opts)
	if cc.rawSet {
		return rawCall[forav1.BrokerTransactionResponse](ctx, b.raw, op, b.baseURL,
			forav1connect.BrokerServiceExecuteTransactionProcedure, cc.rawBody)
	}
	if b.requester == nil {
		return nil, malformed(op, errors.New(
			"no requester configured; a Broker resolves who is buying (see WithRequester)"))
	}
	if err := requireNamedRequester(op, b.requester); err != nil {
		return nil, err
	}
	if err := requireRoutable(op, offers); err != nil {
		return nil, err
	}
	if err := requireRequesterIsSigner(op, b.requester, b.signatureAgent); err != nil {
		return nil, err
	}
	req, err := buildTransaction(ctx, purchase{
		op: op, signer: b.signer, requester: b.requester, offers: offers, opts: opts,
	})
	if err != nil {
		return nil, err
	}
	resp, err := b.rpc.ExecuteTransaction(ctx, connectrpc.NewRequest(req))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}
