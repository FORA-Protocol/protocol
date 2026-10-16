"""The operator verbs: AdminService, and the two domain-verification RPCs.

``fora.admin.v1.AdminService`` sets a tenant's fee rate and reporting policy. The two
domain-verification RPCs live on ``fora.v1.ExchangeService`` but serve the same audience:
the tooling that onboards a publisher, not an agent. Both faces of :class:`AdminClient`
share these plans, the way every other client shares :mod:`._verbs`.

Every call goes to the configured base URL over the plain transport. The operator chose
that address, as a publisher chooses its catalog endpoint, so nothing here is routed by
a manifest. The contract keeps AdminService off the public agent-facing listener, so a
deployment that serves it apart from the Exchange endpoint builds one client per address.

The admin plane carries no request signing in the contract, and these plans sign anyway
when a signer is configured: a signature the peer does not check costs nothing, and the
domain-verification RPCs share an endpoint with signed traffic. No message here carries
an idempotency key — both admin setters are full-replace overwrites.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from wire.models import (
    DomainVerificationChallenge,
    DomainVerificationConfirmation,
    DomainVerificationRequest,
    DomainVerificationResult,
    SetReportingPolicyRequest,
    SetReportingPolicyResponse,
    SetTenantFeeRateRequest,
    SetTenantFeeRateResponse,
)

from ._call import RawBody, decode, validate_request
from ._verbs import (
    EXCHANGE_SERVICE,
    ClientConfig,
    Plan,
    RequestMessage,
    _plan,
    _require_recipient,
    _Route,
    _stamp_ver,
    _str_field,
)

if TYPE_CHECKING:
    from pydantic import BaseModel

ADMIN_SERVICE = "fora.admin.v1.AdminService"


def plan_set_tenant_fee_rate(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble AdminService.SetTenantFeeRate."""
    return _plan_admin(
        cfg, "set tenant fee rate", "SetTenantFeeRate", SetTenantFeeRateRequest, request
    )


def finish_set_tenant_fee_rate(plan: Plan, status: int, body: str) -> SetTenantFeeRateResponse:
    return decode(plan.op, status, body, SetTenantFeeRateResponse, strict=plan.strict)  # type: ignore[no-any-return]


def plan_set_reporting_policy(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble AdminService.SetReportingPolicy."""
    return _plan_admin(
        cfg, "set reporting policy", "SetReportingPolicy", SetReportingPolicyRequest, request
    )


def finish_set_reporting_policy(plan: Plan, status: int, body: str) -> SetReportingPolicyResponse:
    return decode(plan.op, status, body, SetReportingPolicyResponse, strict=plan.strict)  # type: ignore[no-any-return]


def plan_request_domain_verification(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble ExchangeService.RequestDomainVerification. See :func:`_plan_domain`."""
    return _plan_domain(
        cfg,
        "request domain verification",
        "RequestDomainVerification",
        DomainVerificationRequest,
        request,
    )


def finish_request_domain_verification(
    plan: Plan, status: int, body: str
) -> DomainVerificationChallenge:
    return decode(plan.op, status, body, DomainVerificationChallenge, strict=plan.strict)  # type: ignore[no-any-return]


def plan_confirm_domain_verification(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble ExchangeService.ConfirmDomainVerification. See :func:`_plan_domain`."""
    return _plan_domain(
        cfg,
        "confirm domain verification",
        "ConfirmDomainVerification",
        DomainVerificationConfirmation,
        request,
    )


def finish_confirm_domain_verification(
    plan: Plan, status: int, body: str
) -> DomainVerificationResult:
    return decode(plan.op, status, body, DomainVerificationResult, strict=plan.strict)  # type: ignore[no-any-return]


def _plan_admin(
    cfg: ClientConfig, op: str, method: str, model: type[BaseModel], request: RequestMessage
) -> Plan:
    """The admin setters: ``ver`` filled when empty, the message checked, nothing else.

    The admin messages name no recipient — the plane is reached on an internal listener,
    not addressed by domain — so there is no recipient to require.
    """
    route = _Route(op, cfg.base_url, ADMIN_SERVICE, method)
    if isinstance(request, RawBody):
        return _plan(cfg, route, request)
    sent = _stamp_ver(op, request)
    validate_request(op, sent, model, cfg.validation)
    return _plan(cfg, route, sent)


def _plan_domain(
    cfg: ClientConfig, op: str, method: str, model: type[BaseModel], request: RequestMessage
) -> Plan:
    """The domain-verification requests, which DO name a recipient.

    ``exchange`` is the bare domain of the Exchange the request is meant for, distinct
    from ``domain``, the publisher domain being verified. A request naming none, or a
    value that is not a bare domain, is refused before anything is signed or sent — the
    rule every other addressed request follows.
    """
    route = _Route(op, cfg.base_url, EXCHANGE_SERVICE, method)
    if isinstance(request, RawBody):
        return _plan(cfg, route, request)
    sent: dict[str, Any] = _stamp_ver(op, request)
    _require_recipient(op, _str_field(sent, "exchange"))
    validate_request(op, sent, model, cfg.validation)
    return _plan(cfg, route, sent)
