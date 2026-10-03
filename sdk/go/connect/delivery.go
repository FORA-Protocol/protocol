package connect

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/core"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// Delivery is a retrieval URL whose signature, agent binding and expiry this client
// verified: the URL, the Exchange whose URL-signing key verified it, and the
// verified binding — the agent thumbprint it is bound to ("" for a bearer URL), the
// key id, and the expiry.
type Delivery struct {
	URL      string
	Exchange string
	helpers.VerifiedURL
}

// WithDeliveryKeyResolver injects the resolver for an Exchange's URL-signing keys.
// A delivery URL names its key with the kid parameter, an RFC 7638 thumbprint, and
// the key is published in the issuing Exchange's WBA key directory; the resolver
// is called with the Exchange's domain as the context's Signature-Agent
// (helpers.WithSignatureAgent), which is how resolvers.WBAKeyResolver is told
// which directory to read. It defaults to an SSRF-guarded WBAKeyResolver.
func WithDeliveryKeyResolver(r helpers.KeyResolver) ClientOption {
	return func(c *clientConfig) { c.deliveryKeys = r }
}

// WithDeliveryVerification sets whether delivery URLs are verified. The default is
// core.Strict; core.Off is the single named opt-out, for a deployment whose
// delivery URLs use a signing scheme other than the protocol's Ed25519 URL
// signature (a CloudFront RSA signed URL, which a WBA directory cannot verify).
func WithDeliveryVerification(m core.Mode) ClientOption {
	return func(c *clientConfig) { c.deliveryMode = m }
}

// WithDeliveries receives the verified retrieval URLs of a purchase: on success,
// *out is set to one Delivery per result item, index-aligned with the response's
// items, with the zero Delivery for an item that carries no retrieval_endpoint (a
// denial, an upstream refusal, a delivery method that is not a signed URL). It is
// an out-parameter rather than a second return value so Execute keeps its
// signature; it is left untouched when the call fails or delivery verification is
// off.
func WithDeliveries(out *[]Delivery) CallOption {
	return func(c *callConfig) { c.deliveries = out }
}

// WithDeliveryExchange names the Exchange that issued the URL a Fetch retrieves, so
// the URL is verified against that Exchange's URL-signing key — and bound to this
// agent, and unexpired — before anything is sent, and the returned Content carries
// the verified binding. A Fetch without it sends the URL as given.
func WithDeliveryExchange(exchange string) CallOption {
	return func(c *callConfig) { c.deliveryExchange = exchange }
}

// deliveryVerifier holds what verifying a delivery URL takes.
type deliveryVerifier struct {
	keys  helpers.KeyResolver
	mode  core.Mode
	agent string // this agent's thumbprint
	now   func() time.Time
}

func newDeliveryVerifier(cfg clientConfig) deliveryVerifier {
	keys := cfg.deliveryKeys
	if keys == nil {
		keys = resolvers.NewWBAKeyResolver(resolvers.WBAKeyResolverOptions{})
	}
	return deliveryVerifier{keys: keys, mode: cfg.deliveryMode, agent: agentThumbprint(cfg), now: time.Now}
}

// agentThumbprint is the identity a delivery URL must be bound to: the thumbprint
// of the agent key when one is configured, else the signer's keyid, which the
// protocol defines as that same thumbprint.
func agentThumbprint(cfg clientConfig) string {
	if len(cfg.agentKey) == ed25519.PublicKeySize {
		if tp, err := helpers.Thumbprint(cfg.agentKey); err == nil {
			return tp
		}
	}
	if cfg.signer != nil {
		return cfg.signer.KeyID()
	}
	return ""
}

// deliveryRefusal is one verification failure, mapped onto the retrieval-auth
// reason an edge would answer for the same URL.
type deliveryRefusal struct {
	reason forav1.RetrievalAuthFailureReason
	err    error
}

// verify checks one delivery URL issued by exchange. stated is the
// agent_identity_hash the response claimed the URL is bound to ("" when none).
func (d deliveryVerifier) verify(ctx context.Context, rawURL, exchange, stated string) (Delivery, *deliveryRefusal, error) {
	q := deliveryParams(rawURL)
	if q.Get("sig") == "" {
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISSING,
			"the URL carries no signature"), nil
	}
	exp, err := strconv.ParseInt(q.Get("exp"), 10, 64)
	if err != nil {
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRY_MISSING,
			"the URL carries no usable expiry"), nil
	}
	// Expiry before the key is resolved: a dead URL is refused without a directory
	// fetch, and the reason a caller acts on is the same either way.
	if !time.Unix(exp, 0).After(d.now()) {
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED,
			"the URL has expired"), nil
	}
	kid := q.Get("kid")
	if kid == "" {
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH,
			"the URL names no key (kid)"), nil
	}
	pub, err := d.keys.Resolve(helpers.WithSignatureAgent(ctx, exchange), kid)
	if err != nil {
		if errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			return Delivery{}, nil, fmt.Errorf("read the key directory of %s: %w", exchange, err)
		}
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH,
			fmt.Sprintf("%s publishes no usable key %q: %v", exchange, kid, err)), nil
	}
	verified, err := helpers.VerifyURLEd25519(rawURL, pub, d.now())
	switch {
	case errors.Is(err, helpers.ErrURLExpired):
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_EXPIRED, err.Error()), nil
	case err != nil:
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_URL_SIGNATURE_MISMATCH,
			fmt.Sprintf("the URL signature does not verify under %s's key %q", exchange, kid)), nil
	}
	if verified.AgentID != "" && verified.AgentID != d.agent {
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH,
			fmt.Sprintf("the URL is bound to agent %q, not to this agent (%q)", verified.AgentID, d.agent)), nil
	}
	if stated != "" && verified.AgentID != stated {
		return Delivery{}, refuse(forav1.RetrievalAuthFailureReason_RETRIEVAL_AUTH_FAILURE_REASON_THUMBPRINT_MISMATCH,
			fmt.Sprintf("the answer binds its URLs to %q, and this URL to %q", stated, verified.AgentID)), nil
	}
	return Delivery{URL: rawURL, Exchange: exchange, VerifiedURL: verified}, nil, nil
}

func refuse(reason forav1.RetrievalAuthFailureReason, msg string) *deliveryRefusal {
	return &deliveryRefusal{reason: reason, err: errors.New(msg)}
}

// deliveryParams reads the query of a signed URL the way the signer wrote it: the
// bytes after the first '?', parsed as a query string. An unparseable query reads
// as empty, which refuses the URL as unsigned.
func deliveryParams(rawURL string) url.Values {
	_, rawQuery, _ := strings.Cut(rawURL, "?")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return url.Values{}
	}
	return q
}

// deliveryError turns a verification failure into the client's typed failure: a
// refusal is CallMalformed with a synthesized retrieval_auth_failure detail, a
// directory that could not be read is CallUnreachable. item names the result item.
func deliveryError(op, item string, refusal *deliveryRefusal, err error) error {
	if refusal == nil {
		return &CallError{Kind: CallUnreachable, Op: op, Err: fmt.Errorf("verify %s: %w", item, err)}
	}
	msg := fmt.Sprintf("delivery URL of %s does not verify: %v", item, refusal.err)
	return &CallError{
		Kind:   CallMalformed,
		Op:     op,
		Err:    errors.New(msg),
		Detail: helpers.RetrievalAuthFailureDetail(clientErrorDomain, msg, refusal.reason),
	}
}

// verifyItems verifies the retrieval URL of every result item. exchangeOf names
// the Exchange that issued item i, and statedOf the agent_identity_hash the answer
// claims for that Exchange.
func (d deliveryVerifier) verifyItems(
	ctx context.Context, op string, items []*forav1.TransactionResultItem,
	exchangeOf func(i int, item *forav1.TransactionResultItem) string, statedOf func(exchange string) string,
) ([]Delivery, error) {
	out := make([]Delivery, len(items))
	for i, item := range items {
		endpoint := item.GetRetrievalEndpoint()
		if endpoint == "" {
			continue
		}
		exchange := exchangeOf(i, item)
		got, refusal, err := d.verify(ctx, endpoint, exchange, statedOf(exchange))
		if refusal != nil || err != nil {
			label := fmt.Sprintf("item %d (transaction %q)", i, item.GetTransactionId())
			return nil, deliveryError(op, label, refusal, err)
		}
		out[i] = got
	}
	return out, nil
}

// offerExchange names the Exchange that issued result item i of a purchase of
// offers: the offer at the same index, or the offer with the same offer_id when
// the answer does not line up with the request.
func offerExchange(offers []core.VerifiedOffer) func(int, *forav1.TransactionResultItem) string {
	return func(i int, item *forav1.TransactionResultItem) string {
		if len(offers) == 0 {
			return ""
		}
		if len(offers) > i && offers[i].Offer().GetOfferId() == item.GetOfferId() {
			return offers[i].Offer().GetExchange()
		}
		for _, o := range offers {
			if o.Offer().GetOfferId() == item.GetOfferId() {
				return o.Offer().GetExchange()
			}
		}
		if len(offers) > i {
			return offers[i].Offer().GetExchange()
		}
		return offers[0].Offer().GetExchange()
	}
}

// deliver verifies a purchase's retrieval URLs unless verification is off, and
// hands them to the caller's WithDeliveries out-parameter.
func (d deliveryVerifier) deliver(
	ctx context.Context, op string, items []*forav1.TransactionResultItem,
	exchangeOf func(int, *forav1.TransactionResultItem) string, statedOf func(string) string,
	out *[]Delivery,
) error {
	if d.mode == core.Off {
		return nil
	}
	got, err := d.verifyItems(ctx, op, items, exchangeOf, statedOf)
	if err != nil {
		return err
	}
	if out != nil {
		*out = got
	}
	return nil
}
