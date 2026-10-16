package connect

import (
	"context"
	"errors"

	connectrpc "connectrpc.com/connect"

	foraadminv1 "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1/foraadminv1connect"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/gen/go/fora/v1/forav1connect"
)

// AdminClient is the operator's client: every RPC of fora.admin.v1.AdminService —
// the tenant fee rate and the tenant reporting policy — and the two
// domain-verification RPCs of fora.v1.ExchangeService a provider runs before its
// first catalog push.
//
// Both services are reached at the ONE base URL the client is built with, each at
// its own Connect path. The contract keeps AdminService off the public agent-facing
// listener, so a deployment that serves the admin listener and the Exchange endpoint
// at different addresses builds one AdminClient per address and calls each one's
// verbs there.
//
// The admin plane carries no RFC 9421 request signing, and its two setters are
// full-replace overwrites, so they carry no idempotency key. The client still signs
// when WithSigner is set — harmless to a peer that does not verify, and what a
// domain-verification request needs at an Exchange that does. Every verb fills an
// empty ver, so the caller's own value wins; the two domain-verification requests
// name their recipient in exchange and are refused before anything is sent when it
// is missing or not a bare domain, as the catalog verbs are. Every verb takes the
// per-call options: WithRawBody sends caller bytes instead.
type AdminClient struct {
	admin    foraadminv1connect.AdminServiceClient
	exchange forav1connect.ExchangeServiceClient
	baseURL  string
	raw      rawLeg
}

// NewAdminClient builds an AdminClient against baseURL. It takes the client options
// every face takes; the agent-only ones (the requester, the offer key, the delivery
// and endpoint resolvers) are inert here.
func NewAdminClient(baseURL string, opts ...ClientOption) *AdminClient {
	cfg := resolvedConfig(opts...)
	httpClient, connectOpts, _ := plumbing(cfg)
	return &AdminClient{
		admin:    foraadminv1connect.NewAdminServiceClient(httpClient, baseURL, connectOpts...),
		exchange: forav1connect.NewExchangeServiceClient(httpClient, baseURL, connectOpts...),
		baseURL:  baseURL,
		raw:      newRawLeg(cfg, httpClient),
	}
}

// SetTenantFeeRate replaces the tenant's fee rate and operator note
// (AdminService.SetTenantFeeRate) and returns the rate as persisted.
func (a *AdminClient) SetTenantFeeRate(
	ctx context.Context, req *foraadminv1.SetTenantFeeRateRequest, opts ...CallOption,
) (*foraadminv1.SetTenantFeeRateResponse, error) {
	const op = "set tenant fee rate"
	if cc := resolveCall(opts); cc.rawSet {
		return rawCall[foraadminv1.SetTenantFeeRateResponse](ctx, a.raw, op, a.baseURL,
			foraadminv1connect.AdminServiceSetTenantFeeRateProcedure, cc.rawBody)
	}
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	resp, err := a.admin.SetTenantFeeRate(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// SetReportingPolicy replaces the tenant's reporting policy
// (AdminService.SetReportingPolicy) and returns the policy as persisted.
func (a *AdminClient) SetReportingPolicy(
	ctx context.Context, req *foraadminv1.SetReportingPolicyRequest, opts ...CallOption,
) (*foraadminv1.SetReportingPolicyResponse, error) {
	const op = "set reporting policy"
	if cc := resolveCall(opts); cc.rawSet {
		return rawCall[foraadminv1.SetReportingPolicyResponse](ctx, a.raw, op, a.baseURL,
			foraadminv1connect.AdminServiceSetReportingPolicyProcedure, cc.rawBody)
	}
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	resp, err := a.admin.SetReportingPolicy(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// RequestDomainVerification asks the Exchange for a domain-verification challenge
// (ExchangeService.RequestDomainVerification): a token the provider serves at its
// domain before confirming.
func (a *AdminClient) RequestDomainVerification(
	ctx context.Context, req *forav1.DomainVerificationRequest, opts ...CallOption,
) (*forav1.DomainVerificationChallenge, error) {
	const op = "request domain verification"
	if cc := resolveCall(opts); cc.rawSet {
		return rawCall[forav1.DomainVerificationChallenge](ctx, a.raw, op, a.baseURL,
			forav1connect.ExchangeServiceRequestDomainVerificationProcedure, cc.rawBody)
	}
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	resp, err := a.exchange.RequestDomainVerification(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}

// ConfirmDomainVerification tells the Exchange the challenge is in place and,
// optionally, registers the delivery endpoint's verification key
// (ExchangeService.ConfirmDomainVerification).
func (a *AdminClient) ConfirmDomainVerification(
	ctx context.Context, req *forav1.DomainVerificationConfirmation, opts ...CallOption,
) (*forav1.DomainVerificationResult, error) {
	const op = "confirm domain verification"
	if cc := resolveCall(opts); cc.rawSet {
		return rawCall[forav1.DomainVerificationResult](ctx, a.raw, op, a.baseURL,
			forav1connect.ExchangeServiceConfirmDomainVerificationProcedure, cc.rawBody)
	}
	if req == nil {
		return nil, malformed(op, errors.New("request is nil"))
	}
	sent, err := cloneRequest(req, op)
	if err != nil {
		return nil, err
	}
	stampVer(&sent.Ver)
	if err := requireRecipient(op, sent.GetExchange()); err != nil {
		return nil, err
	}
	resp, err := a.exchange.ConfirmDomainVerification(ctx, connectrpc.NewRequest(sent))
	if err != nil {
		return nil, sendError(op, err)
	}
	return resp.Msg, nil
}
