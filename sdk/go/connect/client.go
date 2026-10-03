package connect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	connectrpc "connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/failure"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// Client is the L2 low-tier FORA Connect client: a configurable ExchangeService
// client with the sign face composed as a signing RoundTripper and the
// cross-cutting request-id / validate interceptors wired, plus the fail-closed
// offer Verifier that sorts every discovered offer into {verified, rejected}. It
// owns NO state — signer, keys, HTTP client, and verification policy are all
// injected (ADR-020 §2/§3).
type Client struct {
	rpc      forav1connect.ExchangeServiceClient
	verifier core.Verifier
	cfg      clientConfig

	// exchanges caches one client per OFFER-DERIVED Exchange origin. The home
	// client above is the configured one; a usage report or a dispute goes to
	// whichever Exchange issued the offer, which is discovered at runtime.
	exchanges *exchangePool
	// endpoints resolves an offer's exchange domain to that Exchange's own
	// advertised origin. Never configuration.
	endpoints EndpointResolver
	// requirements reads what an Exchange asks of a registration. It holds no
	// document cache, which the terms-digest rule depends on — see
	// WithRegistrationRequirements.
	requirements RegistrationRequirementsReader
	// fetcher is the content leg. It dials, so it lives one tier down.
	fetcher *resolvers.ContentFetcher

	// baseURL is the home Exchange's origin, which a raw call addresses directly.
	baseURL string
	// raw and rawPool are the home and offer-derived legs a raw call is sent over.
	raw, rawPool rawLeg
	// deliveries verifies the retrieval URLs a purchase answers with.
	deliveries deliveryVerifier
}

// resolvedConfig applies opts over the defaults every client shares.
func resolvedConfig(opts ...ClientOption) clientConfig {
	cfg := clientConfig{httpClient: &http.Client{}, mode: core.Strict}
	for _, o := range opts {
		o(&cfg)
	}
	return cfg
}

// DefaultMaxRPCReadBytes caps the response body a single FORA call will read.
// Connect
// treats an unset cap as "any size" and compresses every exchange, so without one
// a hostile or misconfigured peer can decompress an unbounded body into the
// caller's memory. A FORA response for a realistic batch is small; the bound is
// what stops a peer — including one an offer named — spending the caller's memory
// on its behalf. Override it per client with WithClientOptions.
const DefaultMaxRPCReadBytes = 1 << 20 // 1 MiB

// plumbing assembles what every client face is built from: the signing HTTP
// client, the Connect options, and the offer Verifier. Extracted so the exchange
// and broker faces cannot drift in how they sign, correlate, validate, verify, or
// bound what they read.
func plumbing(cfg clientConfig) (*http.Client, []connectrpc.ClientOption, core.Verifier) {
	// The caller's options come last so an application can tighten (or widen) a
	// default the SDK chose.
	opts := append([]connectrpc.ClientOption{
		connectrpc.WithInterceptors(clientInterceptors(cfg)...),
		connectrpc.WithReadMaxBytes(DefaultMaxRPCReadBytes),
	}, cfg.connectOpts...)
	return signedHTTPClient(cfg, cfg.httpClient.Transport),
		opts,
		core.NewVerifier(cfg.mode, cfg.resolveOfferResolver(), time.Now)
}

// NewClient builds a Client against baseURL — the agent's HOME Exchange, the one
// its account lives on. The sign face is composed onto the HTTP client's
// transport BEFORE the Connect client is built (Content-Digest needs the
// marshaled body bytes), then the cross-cutting interceptors are wired in the
// ADR order: sign(RoundTripper) · request-id · validate · (app extras). Offer
// verification is Strict by default.
//
// Discovery and purchase go to baseURL. A usage report or a dispute does NOT:
// those reach the Exchange that issued the offer, resolved per call from that
// Exchange's own manifest, over a separately guarded transport.
func NewClient(baseURL string, opts ...ClientOption) *Client {
	cfg := resolvedConfig(opts...)
	httpClient, connectOpts, verifier := plumbing(cfg)
	pooled := offerDerivedClient(cfg, resolvers.NewGuardedTransport(cfg.guardedBase))
	return &Client{
		rpc:        forav1connect.NewExchangeServiceClient(httpClient, baseURL, connectOpts...),
		verifier:   verifier,
		cfg:        cfg,
		baseURL:    baseURL,
		raw:        newRawLeg(cfg, httpClient),
		rawPool:    newRawLeg(cfg, pooled),
		deliveries: newDeliveryVerifier(cfg),
		// A SECOND signing client for the offer-derived leg, over the guarded
		// transport: the caller names a domain, the manifest it serves names an
		// endpoint, and a signed call then goes there. Without the guard one hop
		// down, that is a signed request aimed at an arbitrary internal address.
		// Redirects are refused outright — following one would re-sign the call for
		// a target the peer chose, after the endpoint check had already passed. And
		// it carries its own deadline, because an offer-named Exchange that accepts
		// a connection and then never answers would otherwise hold the call, a
		// goroutine and a socket open indefinitely.
		exchanges:    newExchangePool(pooled, connectOpts...),
		endpoints:    cfg.resolveEndpointResolver(),
		requirements: cfg.resolveRequirementsReader(),
		fetcher: resolvers.NewContentFetcher(resolvers.ContentFetchOptions{
			BaseTransport: cfg.guardedBase,
			Timeout:       cfg.fetchTimeout,
			MaxBytes:      cfg.fetchMaxByte,
			// The same mint the RPC legs read, so WithRequestIDFunc reaches all
			// three. Without it the delivery fetch is the one leg with no id, and
			// an edge that mints its own logs a refusal under a value nothing here
			// can join it to.
			RequestID: requestIDMint(cfg.requestID),
		}),
	}
}

// signedHTTPClient returns an *http.Client whose transport is the SDK signing
// RoundTripper wrapping base (preserving a custom proxy/mTLS transport
// underneath). Redirects are refused: a FORA RPC has no legitimate reason to be
// redirected, and following one would re-sign the caller's request for a target
// the peer chose — which would also move the destination after the endpoint check
// had run.
func signedHTTPClient(cfg clientConfig, base http.RoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	signed := *cfg.httpClient
	var transport http.RoundTripper = core.NewSigningTransport(cfg.signer, base, signingOptions(cfg)...)
	// The hook sits immediately in front of the signer, so the bytes it returns are
	// the bytes signed, and behind the answer recorder, which must see the response
	// whatever the hook did.
	if cfg.beforeSign != nil {
		transport = beforeSignTransport{hook: cfg.beforeSign, next: transport}
	}
	signed.Transport = answerRecorder{next: transport}
	signed.CheckRedirect = refuseRPCRedirect
	return &signed
}

// signingOptions renders the signing knobs the client models onto the transport's
// own option type. It is the ONE place they meet, so every face the SDK builds —
// the home Exchange, the Broker, and the offer-derived pool, which all reach the
// wire through signedHTTPClient — signs on identical terms.
// It ACCUMULATES rather than returning on the first knob it finds. Written as an
// early return for a single option, the second one to arrive is silently dropped
// whenever the first is unset — which is how a client came to sign an empty
// Signature-Agent while the option to fill it already existed a tier down.
func signingOptions(cfg clientConfig) []core.SigningOption {
	var opts []core.SigningOption
	if cfg.signWindow != nil {
		opts = append(opts, core.WithWindow(cfg.signWindow))
	}
	if cfg.signatureAgent != "" {
		opts = append(opts, core.WithSignatureAgent(cfg.signatureAgent))
	}
	return opts
}

// refuseRPCRedirect stops the client following any 3xx on an RPC leg. Following
// one would re-sign the caller's request for a target the peer chose, after the
// endpoint check had already passed.
var refuseRPCRedirect = failure.RefuseRedirect(
	"connect", "a FORA call is never redirected", helpers.RedactURL)

// DefaultCallTimeout bounds one call on the offer-derived leg. A FORA RPC is
// interactive — something is waiting on the other end — so a request that has not
// answered by now is more useful as an error than as a hang.
const DefaultCallTimeout = 30 * time.Second

// offerDerivedClient is signedHTTPClient plus a deadline. The home Exchange and
// the Broker are operator-configured, so their timeout is the caller's to set
// through WithHTTPClient; an Exchange an offer named is not, and a client with no
// deadline against a host chosen by another party is a hang waiting to happen.
// An explicit timeout on the injected client is respected.
func offerDerivedClient(cfg clientConfig, base http.RoundTripper) *http.Client {
	client := signedHTTPClient(cfg, base)
	if client.Timeout <= 0 {
		client.Timeout = DefaultCallTimeout
	}
	// The caller's cookie jar does not come along. This leg already drops the
	// caller's proxy, TLS dialer and redirect policy, and a jar is the same kind of
	// ambient state: http.CookieJar is an interface, so what an arbitrary
	// implementation sends to a host an offer named is not this package's to
	// assume. A FORA call carries its identity in the signature, never in a cookie.
	client.Jar = nil
	return client
}

// clientInterceptors assembles the cross-cutting interceptor stack (request-id ·
// validate · app extras). Sign is NOT here — it is the RoundTripper. Panics only
// if the shared validator fails to build, which is a programmer/config error, not
// a runtime condition.
func clientInterceptors(cfg clientConfig) []connectrpc.Interceptor {
	return interceptorStack(cfg, cfg.validation == ValidationStrict)
}

// interceptorStack is the stack every client is built with, optionally without
// the validate interceptor. A raw call leaves it out: its request is caller bytes,
// not a message to validate, and the answer still passes strict decoding.
//
// answerInterceptor is OUTERMOST so it observes the failure every inner layer
// produced; strictInterceptor sits inside it, so a refused OK answer is never
// mistaken for one the peer refused.
func interceptorStack(cfg clientConfig, validateRequests bool) []connectrpc.Interceptor {
	out := []connectrpc.Interceptor{answerInterceptor{}, newRequestIDInterceptor(cfg.requestID)}
	if cfg.strictDecoding {
		out = append(out, strictInterceptor{})
	}
	if validateRequests {
		if v, err := NewValidateInterceptor(); err == nil {
			out = append(out, v)
		}
	}
	out = append(out, cfg.extra...)
	return out
}

// Discover issues DiscoverResources and returns one group per requested URI,
// each carrying the fail-closed {verified, rejected} split: EVERY returned offer
// is verified against the exchange offer-signing key (resolved through the
// injected resolver) before it is handed back. Neither an unverifiable nor a
// doctored offer is silently dropped — it lands in Rejected with a reason. A URI
// that the responder GROUPED and left empty keeps its group, carrying the typed
// reason, so a refusal is an answer rather than an absence. (A response carrying
// no groups at all yields none — there is nothing to keep.) Round-trip: client
// sign → HTTP → server verify → origin → response, then the offer Verifier over
// the response.
//
// The query is CLONED before ver and the requester are filled in, so the message
// the caller built stays untouched — it crossed a package boundary as an
// argument, not as a buffer. Both fields are filled only when EMPTY: a value the
// caller set is theirs.
//
// `exchange` is NOT among them: the caller MUST set it to the bare host of the
// Exchange being queried, because the contract now requires every addressed
// request to name its recipient and a query without one is rejected on arrival.
// It is left to the caller rather than derived from the client's base URL on
// purpose — the point of the field is to state whom the SENDER meant, and a
// value the transport filled in from the address it was already dialling would
// restate the dial target instead of checking it.
//
// WithRawBody sends caller bytes instead; the answer's offers are still verified.
func (c *Client) Discover(ctx context.Context, query *forav1.ResourceQuery, opts ...CallOption) (core.DiscoveryResult, error) {
	const op = "discover"
	if cc := resolveCall(opts); cc.rawSet {
		msg, err := rawCall[forav1.ResourceResponse](ctx, c.raw, op, c.baseURL,
			forav1connect.ExchangeServiceDiscoverResourcesProcedure, cc.rawBody)
		if err != nil {
			return core.DiscoveryResult{}, err
		}
		// The flat fallback attributes its offers to the query's only URI, read off
		// the raw body when it decodes as a query.
		sent := &forav1.ResourceQuery{}
		_ = proto.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(cc.rawBody, sent)
		return c.discoveryResult(ctx, sent, msg), nil
	}
	if query == nil {
		return core.DiscoveryResult{}, malformed(op, errors.New("query is nil"))
	}
	sent, err := cloneRequest(query, op)
	if err != nil {
		return core.DiscoveryResult{}, err
	}
	stampDiscovery(&sent.Ver, &sent.Requester, c.cfg.requester)
	resp, err := c.rpc.DiscoverResources(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return core.DiscoveryResult{}, sendError(op, err)
	}
	return c.discoveryResult(ctx, sent, resp.Msg), nil
}

func (c *Client) discoveryResult(ctx context.Context, sent *forav1.ResourceQuery, msg *forav1.ResourceResponse) core.DiscoveryResult {
	return core.DiscoveryResult{
		Groups:    c.discoveredGroups(ctx, sent, msg),
		Exchange:  msg.GetExchange(),
		RateLimit: msg.GetRateLimit(),
	}
}

// discoveredGroups folds a ResourceResponse's two offer representations into the
// per-URI form.
//
// The message carries a grouped list AND a flat one, and the contract says a
// responder populating groups SHOULD leave the flat list empty "to avoid
// ambiguity" — but a real Exchange populates both, the flat list mirroring the
// grouped offers as a single-URI convenience. So the two are read as ALTERNATIVES,
// never concatenated: concatenating would double every offer against such a
// server, and deduplicating would silently accept a responder whose two lists
// disagree, which is precisely the ambiguity the contract forbids.
//
// Groups win when present. The flat fallback becomes a single group; it carries
// no URI of its own, so it takes the query's only URI when the query named
// exactly one, and none otherwise — the SDK does not invent an attribution the
// wire did not make.
func (c *Client) discoveredGroups(ctx context.Context, query *forav1.ResourceQuery, msg *forav1.ResourceResponse) []core.OfferGroupResult {
	if groups := msg.GetOfferGroups(); len(groups) > 0 {
		return c.verifier.SortGroups(ctx, groups)
	}
	flat := msg.GetOffers()
	if len(flat) == 0 {
		return nil
	}
	var uri string
	if uris := query.GetUris(); len(uris) == 1 {
		uri = uris[0]
	}
	return []core.OfferGroupResult{{URI: uri, Result: c.verifier.Sort(ctx, flat)}}
}

// CallOption tunes a single call: the idempotency key of a state-mutating call,
// raw mode, and the delivery options of a purchase or a fetch. Every verb takes
// them; an option that does not apply to a verb is inert there.
type CallOption func(*callConfig)

// ExecuteOption is the original name for CallOption, kept because the option set
// began as the one shared by execute, report and dispute — the three RPCs the
// protocol requires an idempotency key on.
type ExecuteOption = CallOption

type callConfig struct {
	idempotencyKey string
	// rawBody, when rawSet, replaces the request the verb would build (WithRawBody).
	rawBody []byte
	rawSet  bool
	// deliveries receives the verified retrieval URLs of a purchase (WithDeliveries).
	deliveries *[]Delivery
	// deliveryExchange names the Exchange a fetched URL is verified against
	// (WithDeliveryExchange).
	deliveryExchange string
}

// resolveCall applies a call's options.
func resolveCall(opts []CallOption) callConfig {
	var cc callConfig
	for _, o := range opts {
		o(&cc)
	}
	return cc
}

// WithIdempotencyKey pins the idempotency key for this call. Reusing a key makes
// the call a deliberate replay: the server dedupes on it (a fresh key is minted
// per call by default). The SDK never tracks keys — the server owns dedup
// (ADR-019 §4, ADR-020 §3).
//
// Hold the key and pass the same one back when retrying, on every verb that takes
// this option. The key identifies the ACTION, not the attempt: a fresh key on a
// retry reads to the server as a second purchase, a second report, a second
// dispute.
func WithIdempotencyKey(key string) CallOption {
	return func(e *callConfig) { e.idempotencyKey = key }
}

// idempotencyKeyFor resolves the key for one call, in precedence order: the key
// pinned for this call, then whatever the caller already put on the message, then
// a freshly minted one.
func idempotencyKeyFor(opts []CallOption, onMessage string) (string, error) {
	cc := resolveCall(opts)
	if cc.idempotencyKey != "" {
		return cc.idempotencyKey, nil
	}
	if onMessage != "" {
		return onMessage, nil
	}
	return helpers.NewIdempotencyKey()
}

// Execute commits to a VERIFIED offer and returns the transaction response. It
// accepts ONLY a core.VerifiedOffer — passing a RejectedOffer or a raw *forav1.Offer
// is a COMPILE error (the unforgeable-VerifiedOffer guard). A per-call idempotency
// key is minted fresh unless WithIdempotencyKey pins one. Execute builds the whole
// TransactionRequest, so it also stamps ver from helpers.ProtocolVersion — the
// caller neither supplies nor overrides it.
//
// Items-only wire shape: a single offer is the degenerate 1-element items list.
// ExecuteBatch buys several offers from the same Exchange in one request.
//
// Every retrieval_endpoint in the answer is verified before it is returned: its
// Ed25519 signature against the URL-signing key the issuing Exchange publishes in
// its WBA directory (the URL's kid names it), its agent_id binding against this
// agent's key and the answer's agent_identity_hash, and its expiry. A URL that does
// not verify fails the call as CallMalformed, with a retrieval_auth_failure detail
// naming the reason; the purchase itself was made, so the item's transaction id is
// in the error. WithDeliveries receives the verified bindings, and
// WithDeliveryVerification(core.Off) is the opt-out for URLs in a signing scheme a
// WBA directory cannot verify.
func (c *Client) Execute(ctx context.Context, offer core.VerifiedOffer, opts ...CallOption) (*forav1.TransactionResponse, error) {
	return c.executeDirect(ctx, "execute", []core.VerifiedOffer{offer}, opts)
}

// ExecuteBatch commits to several VERIFIED offers issued by ONE Exchange in a
// single request — the batch form of Execute, built by the same code. Each item
// carries its own detached acceptance, and the request carries one
// AgentRequestAcceptance over the complete ordered set.
//
// The offers must all name the same Exchange: a direct purchase goes to one
// Exchange, and an Exchange refuses a request carrying an item addressed to anyone
// else, so a mixed set is refused locally with CallMalformed. Buying across
// Exchanges in one call is BrokerClient.Execute.
func (c *Client) ExecuteBatch(ctx context.Context, offers []core.VerifiedOffer, opts ...CallOption) (*forav1.TransactionResponse, error) {
	return c.executeDirect(ctx, "execute", offers, opts)
}

func (c *Client) executeDirect(ctx context.Context, op string, offers []core.VerifiedOffer, opts []CallOption) (*forav1.TransactionResponse, error) {
	cc := resolveCall(opts)
	if cc.rawSet {
		return rawCall[forav1.TransactionResponse](ctx, c.raw, op, c.baseURL,
			forav1connect.ExchangeServiceExecuteTransactionProcedure, cc.rawBody)
	}
	if err := requireOneExchange(op, offers); err != nil {
		return nil, err
	}
	req, err := buildTransaction(ctx, purchase{
		op: op, signer: c.cfg.signer, requester: c.cfg.requester, offers: offers, opts: opts,
	})
	if err != nil {
		return nil, err
	}
	resp, err := c.rpc.ExecuteTransaction(ctx, connectrpc.NewRequest(req))
	if err != nil {
		return nil, sendError(op, err)
	}
	if err := c.deliveries.deliver(ctx, op, resp.Msg.GetItems(), offerExchange(offers),
		func(string) string { return resp.Msg.GetAgentIdentityHash() }, cc.deliveries); err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// stampEnvelope fills the two envelope fields the protocol requires on a
// state-mutating call, WITHOUT overwriting what the caller already set.
//
// Fill-when-empty is the whole rule. `ver` has a single owner, so the SDK supplies
// it rather than making every caller reach for the constant. The idempotency key
// is REQUIRED and identifies the action rather than the attempt, so a value the
// caller put there is theirs — discarding it would turn each of their retries into
// a fresh action, which is the double-counting the field exists to prevent.
// WithIdempotencyKey overrides both.
func stampEnvelope(ver, idempotencyKey *string, opts []CallOption) error {
	if *ver == "" {
		*ver = helpers.ProtocolVersion
	}
	key, err := idempotencyKeyFor(opts, *idempotencyKey)
	if err != nil {
		return err
	}
	*idempotencyKey = key
	return nil
}

// stampDiscovery fills the envelope a DISCOVERY call carries, which is the
// mutating envelope minus the idempotency key: pure discovery buys nothing and
// changes nothing, so there is no action for a key to identify.
//
// Both fills are only-when-empty. The caller's own value always wins — the
// message crossed a package boundary as an argument, not as a buffer to fill in —
// and the requester is filled because both reference services resolve the calling
// agent from it and refuse a request that names none, while the client already
// holds that identity.
func stampDiscovery(ver *string, requester **forav1.Requester, configured *forav1.Requester) {
	if *ver == "" {
		*ver = helpers.ProtocolVersion
	}
	if *requester == nil {
		*requester = configured
	}
}

// cloneRequest copies a caller's message so the SDK can stamp its envelope
// without touching what the caller still holds.
//
// The type assertion cannot fail for a concrete message — proto.Clone returns the
// same dynamic type it was given — but it is checked rather than asserted blind,
// because a silent nil would reach the wire as an empty request. One helper
// rather than four copies of the same three lines.
func cloneRequest[T proto.Message](msg T, op string) (T, error) {
	cloned, ok := proto.Clone(msg).(T)
	if !ok {
		var zero T
		return zero, malformed(op, fmt.Errorf(
			"cloned %T has the wrong type", msg))
	}
	return cloned, nil
}
