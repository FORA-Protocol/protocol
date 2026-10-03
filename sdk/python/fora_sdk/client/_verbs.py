"""The six verbs, split into the part that has no IO and the part that reads an answer.

Both faces — the async client and the sync facade — share every line here. What differs
between them is which httpx client carries the bytes, and nothing else; keeping the
protocol in one place is what stops the two drifting into two dialects of the same client.

Each verb is a ``plan_*`` (stamp, check, route, sign — everything up to the send) and a
``finish_*`` (read the answer). The plan is what a face awaits around; the finish is what
it hands back.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel
from wire.models import (
    DiscoveryRequest,
    DiscoveryResponse,
    DisputeRequest,
    DisputeResponse,
    GetAccountStatusRequest,
    GetAccountStatusResponse,
    PushResourcesRequest,
    PushResourcesResponse,
    RefreshCatalogRequest,
    RefreshCatalogResponse,
    RegisterRequest,
    RegisterResponse,
    RegistrationFailureReason,
    RemoveResourcesRequest,
    RemoveResourcesResponse,
    ResourceQuery,
    ResourceResponse,
    TransactionRequest,
    UsageReport,
    UsageReportResponse,
)

from fora_sdk.core import (
    ACCEPTANCE_SIGNATURE_ALGORITHM,
    DiscoveryResult,
    Mode,
    OfferGroupResult,
    VerifiedOffer,
    Verifier,
)
from fora_sdk.errordetail import registration_failure_detail
from fora_sdk.idempotency import generate_idempotency_key
from fora_sdk.regschema import check_registration_data
from fora_sdk._hostref import _is_invalid_host_refusal
from fora_sdk.resolvers import (
    ExchangeNotPermittedError,
    ManifestNotExchangeError,
    ManifestUnusableError,
    WBAKeyResolver,
    WellKnownRequirementsReader,
    guarded_client,
)
from fora_sdk.window import Window
from fora_sdk.wire import ProtocolVersion, to_wire
from fora_sdk.wire_canon import from_wire_offer

from ._call import (
    BeforeSign,
    DEFAULT_CALL_TIMEOUT_SEC,
    DEFAULT_MAX_RPC_READ_BYTES,
    RawBody,
    Validation,
    decode,
    decode_with_raw,
    prepare,
    rpc_url,
    validate_request,
)
from .._hostref import _redact_userinfo as redact_userinfo
from .delivery import (
    BrokerExecuteResult,
    DeliveryKeyResolver,
    ExecuteResult,
    Expected,
    verify_items,
)
from ..hosts import check_audience, host_of, is_bare_domain
from .errors import CallError, CallErrorKind, malformed, not_sent
from .route import (
    EndpointResolver,
    RegistrationRequirementsReader,
    vet_exchange_endpoint,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    import httpx

    from fora_sdk.signing_transport import SigningTransport
    from fora_sdk.window import Window

EXCHANGE_SERVICE = "fora.v1.ExchangeService"
BROKER_SERVICE = "fora.v1.BrokerService"
CATALOG_SERVICE = "fora.v1.CatalogService"


#: A request a verb accepts: the generated wire model, the equivalent dict, or a
#: :class:`RawBody` sent exactly as given.
RequestMessage = dict[str, Any] | BaseModel | RawBody


@dataclass
class ClientConfig:
    """Everything a client is built from. Every field is injected; the client owns none."""

    base_url: str
    #: The RFC 9421 request signer. Custody stays with the application.
    signer: SigningTransport | None = None
    #: The agent's own identity, forwarded on discovery and required on a purchase: both
    #: reference services resolve the calling agent from it and refuse a request that
    #: names none.
    requester: dict[str, Any] | None = None
    #: The fail-closed offer Verifier. Defaults to STRICT with nothing resolvable, so an
    #: unconfigured client rejects every offer rather than surfacing it unchecked.
    verifier: Verifier | None = None
    #: Whether an outbound request is checked against its generated model first.
    #: Orthogonal to offer verification: this one is about the message going out.
    validation: Validation = "strict"
    #: Turns an offer's exchange domain into that Exchange's own advertised origin. Never
    #: configuration — a usage report and a dispute go where the signed offer says.
    endpoint_resolver: EndpointResolver | None = None
    #: Reports what one Exchange asks of a registration — the terms revision submitting
    #: one accepts, and the schema its registration_data must match. The reader it takes
    #: holds no document cache, and that is the point rather than an implementation
    #: detail: the contract requires a registering client to read the terms digest from a
    #: FRESHLY fetched manifest, so an implementation serving it from a cache breaks the
    #: rule the field exists to record. There is deliberately no slot for a digest or a
    #: schema directly — a caller managing its own requirements sets ``terms_digest`` on
    #: the request, which suppresses the read and says so on the message the signature
    #: covers.
    registration_requirements: RegistrationRequirementsReader | None = None
    #: The RFC 9421 freshness window stamped on every outbound REQUEST signature.
    #:
    #: Named here as well as on the signer so the knob sits at the same tier it does in
    #: Go and TypeScript. A deployment with its own freshness policy sets it. It is not
    #: needed for uniqueness: every request signature carries a fresh RFC 9421 nonce, so
    #: two identical requests inside one second still sign to different bytes.
    sign_window: Window | None = None
    #: Mints the X-Request-ID correlation value. ``None`` sends no header.
    request_id: Callable[[], str] | None = None
    #: Called with every request just before it is signed, as an ``httpx.Request``; the
    #: request it returns is what gets signed and sent, and the reply is decoded as usual.
    #: For a test that must send a deliberately altered message through the SDK's own
    #: signer and decoder. The method and URL cannot change, and a header the signer
    #: emits cannot be set: either refuses the call as malformed.
    before_sign: BeforeSign | None = None
    #: Refuse an answer the contract does not describe: an unknown field at any depth, a
    #: field-level rule broken, or a cross-field rule broken. The shape is the published
    #: strict JSON Schema of the response message and the SDK's cross-field rules, so it
    #: is defined once, by the proto. Off by default, because the models accept fields a
    #: newer minor version may add. Error envelopes are read the same either way.
    strict: bool = False
    #: Resolves the key an Exchange signs delivery URLs with: ``resolve(kid, exchange)``,
    #: against that Exchange's Web Bot Auth key directory. Defaults to the SSRF-guarded
    #: :class:`~fora_sdk.resolvers.wba.WBAKeyResolver`, built once with the client.
    delivery_keys: DeliveryKeyResolver | None = None
    #: Whether ``execute`` and ``fetch`` verify a delivery URL — its signature against the
    #: issuing Exchange's key, its binding to this agent, its expiry — before handing it
    #: back or dialling it. ``Mode.OFF`` is the named opt-out, for a deployment whose URLs
    #: are signed in a scheme other than the protocol's Ed25519 one.
    delivery_verification: Mode = Mode.STRICT
    #: The freshness window stamped on a delivery-fetch proof.
    proof_window: Window | None = None
    max_rpc_read_bytes: int = DEFAULT_MAX_RPC_READ_BYTES
    call_timeout_sec: float = DEFAULT_CALL_TIMEOUT_SEC
    content_timeout_sec: float | None = None
    max_content_bytes: int | None = None

    def resolved_verifier(self) -> Verifier:
        if self.verifier is not None:
            return self.verifier
        return _NULL_VERIFIER


@dataclass(frozen=True)
class _Owned:
    """The transports a client built for the defaults it filled in, and so must close."""

    requirements: httpx.Client | None = None
    delivery: httpx.Client | None = None

    def close(self) -> None:
        for http in (self.requirements, self.delivery):
            if http is not None:
                http.close()


def _with_defaults(config: ClientConfig) -> tuple[ClientConfig, _Owned]:
    """Fill in the default requirements reader and delivery-key resolver ONCE, and report
    the transports that came with them.

    Both client facades call this from their constructor, which is the tier Go resolves
    the same defaults at. Per CALL it would build an SSRF-guarded httpx client for every
    registration and every purchase and close none of them; per CLIENT it is one pooled
    transport each, with an owner that can close it.

    The caller's config is never mutated — a caller may hold it, reuse it across
    clients, or read it back — so the filled-in defaults ride on a copy. The second
    return is the transports this client OWNS: none for a seam the caller injected,
    because then the transport inside it is theirs.
    """
    requirements: httpx.Client | None = None
    delivery: httpx.Client | None = None
    if config.registration_requirements is None:
        requirements = guarded_client()
        config = replace(
            config, registration_requirements=WellKnownRequirementsReader(http=requirements)
        )
    if config.delivery_keys is None:
        delivery = guarded_client()
        config = replace(config, delivery_keys=WBAKeyResolver(http=delivery))
    return config, _Owned(requirements=requirements, delivery=delivery)


class _NullOfferKeyResolver:
    """Resolves nothing. Under STRICT that rejects every offer, with a reason — the
    fail-closed default for a client given no key source."""

    def resolve(self, exchange: str) -> bytes | None:  # noqa: ARG002
        return None


_NULL_VERIFIER = Verifier(mode=Mode.STRICT, resolver=_NullOfferKeyResolver(), now=lambda: 0)


@dataclass(frozen=True)
class Plan:
    """One request, ready to send."""

    op: str
    url: str
    body: bytes
    headers: dict[str, str]
    timeout: float
    max_bytes: int
    #: Whether this leg dials a host another party named — an offer-derived Exchange —
    #: and so goes over the address-guarded transport. Mirrors the Go client, which keeps
    #: a second guarded client for exactly these two verbs.
    guarded: bool = False
    #: The caller's message, before any ``before_sign`` hook altered it. Kept so the
    #: finish step can read the query back: the flat fallback's attribution needs the
    #: URIs the caller asked about.
    sent: dict[str, Any] = field(default_factory=dict)
    #: Whether the answer is decoded strictly (``ClientConfig.strict``).
    strict: bool = False
    #: Whether the body is a caller's :class:`RawBody`. The answer is decoded as usual,
    #: and nothing that ties it to a request the SDK built — delivery verification — runs.
    raw: bool = False
    #: ``(offer_id, exchange)`` of each item a purchase sent, in order: what a result
    #: item's retrieval URL is verified against.
    items: tuple[tuple[str, str], ...] = ()


# ---------------------------------------------------------------------------
# discover
# ---------------------------------------------------------------------------


def plan_discover(cfg: ClientConfig, query: RequestMessage) -> Plan:
    """Assemble DiscoverResources.

    The query is CLONED before ``ver`` and the requester are filled in, so the message the
    caller built stays untouched — it crossed a module boundary as an argument, not as a
    buffer. Both are filled only when EMPTY: a value the caller set is theirs.

    ``exchange`` is NOT among them: the caller MUST set it to the bare host of the
    Exchange being queried, because the contract requires every addressed request to name
    its recipient. It is left to the caller rather than derived from the base URL on
    purpose — the point of the field is to state whom the SENDER meant, and a value the
    transport filled in from the address it was already dialling would restate the dial
    target instead of checking it.
    """
    op = "discover"
    route = _Route(op, cfg.base_url, EXCHANGE_SERVICE, "DiscoverResources")
    if isinstance(query, RawBody):
        return _plan(cfg, route, query)
    sent = _stamp_discovery(op, query, cfg.requester)
    validate_request(op, sent, ResourceQuery, cfg.validation)
    return _plan(cfg, route, sent)


def finish_discover(cfg: ClientConfig, plan: Plan, status: int, body: str) -> DiscoveryResult:
    msg, raw = decode_with_raw(plan.op, status, body, ResourceResponse, strict=plan.strict)
    return DiscoveryResult(
        # The offers are read from the RAW answer, not the parsed one. A model parse is
        # the GATE — it proves the answer well formed and its field names canonical — but
        # it also NORMALIZES: Pydantic fills every declared default, which adds keys the
        # signer never covered and would make a genuine offer fail verification. A
        # signature covers what the responder sent.
        groups=_discovered_groups(cfg.resolved_verifier(), plan.sent, raw),
        exchange=msg.exchange or "",
        # From the PARSED answer, unlike the offers above, with one member excepted.
        #
        # Nothing here is signed, so the reason the offers are read raw does not reach this
        # field, and the oracle settles what should: Go hands back the decoded message, so a
        # string-spelled int32 arrives as a number and a member the schema does not declare
        # is gone. TypeScript's parse does the same two things. A Python that answered from
        # the wire was the odd one of the three — it handed back "300" where the other two
        # said 300, and kept a vendor key they both dropped.
        #
        # reset_at is the exception because it is the one member the parse cannot return
        # unchanged: Pydantic reads it into a datetime and re-renders it, and that round trip
        # is not the identity — ".123Z" comes back ".123000Z", nanosecond precision is
        # truncated, "+00:00" becomes "Z". TypeScript validates it as a plain string and
        # hands back what it was given, so the peer's own spelling is what the two agree on.
        rate_limit=_rate_limit(msg.rate_limit, raw.get("rate_limit")),
    )


def _discovered_groups(
    verifier: Verifier, query: dict[str, Any], raw: dict[str, Any]
) -> list[OfferGroupResult]:
    """Fold a ResourceResponse's two offer representations into the per-URI form.

    The message carries a grouped list AND a flat one, and the contract says a responder
    populating groups SHOULD leave the flat list empty "to avoid ambiguity" — but a real
    Exchange populates both, the flat list mirroring the grouped offers as a single-URI
    convenience. So the two are read as ALTERNATIVES, never concatenated: concatenating
    would double every offer against such a server, and deduplicating would silently
    accept a responder whose two lists disagree, which is precisely the ambiguity the
    contract forbids.

    Groups win when present. The flat fallback becomes a single group; it carries no URI
    of its own, so it takes the query's only URI when the query named exactly one, and
    none otherwise — the SDK does not invent an attribution the wire did not make.
    """
    groups = raw.get("offer_groups")
    if isinstance(groups, list) and groups:
        return verifier.sort_groups([_canonicalize_group(g) for g in groups])
    flat = raw.get("offers")
    if not isinstance(flat, list) or not flat:
        return []
    uris = query.get("uris")
    uri = uris[0] if isinstance(uris, list) and len(uris) == 1 and isinstance(uris[0], str) else ""
    return [OfferGroupResult(uri=uri, result=verifier.sort(_canonicalize(flat)))]


def _canonicalize(offers: list[Any]) -> list[Any]:
    """Invert the wire emission of each offer before it is verified.

    A FORA Exchange serves proto-JSON with EmitUnpopulated, so a wire offer carries
    zero-valued scalars, empty repeateds, null messages and ``*_UNSPECIFIED`` enums that
    the SIGNED form does not — the signature covers the omit-unpopulated rendering.
    Verifying the wire object as-is would fail every genuine offer, which is a fail-closed
    direction but the wrong answer. ``from_wire_offer`` is the schema-aware inversion,
    byte-parity-pinned against the Go oracle; a field newer than its pinned model is kept
    verbatim, so an offer this SDK cannot reconstruct still verifies FALSE rather than
    being waved through.

    The verified value is therefore the CANONICAL offer, which is what execute reflects
    back: the Exchange verifies the presented bytes and re-renders them canonically either
    way, so reflecting the canonical form is the same statement with none of the wire
    emission's noise.
    """
    return [from_wire_offer(o) if isinstance(o, dict) else o for o in offers]


def _canonicalize_group(group: Any) -> Any:
    """Apply the inversion to one group's offers, leaving its URI and typed reasons
    untouched."""
    if not isinstance(group, dict):
        return group
    offers = group.get("offers")
    if not isinstance(offers, list):
        return group
    return {**group, "offers": _canonicalize(offers)}


# ---------------------------------------------------------------------------
# resolve (Broker)
# ---------------------------------------------------------------------------


def plan_resolve(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble the Broker's Resolve.

    It carries no idempotency key. Pure discovery buys nothing and changes nothing, so
    there is nothing for a server to deduplicate — the request message has no such field.
    """
    op = "resolve"
    if isinstance(request, RawBody):
        return _plan(cfg, _Route(op, cfg.base_url, BROKER_SERVICE, "Resolve"), request)
    sent = _stamp_discovery(op, request, cfg.requester)
    # Refused locally rather than sent: a Broker resolves the calling agent from the
    # requester and declines a request that names none, so this is a verdict the client
    # already knows, and naming the remedy beats relaying "requester required" from a
    # round trip away. execute refuses the same way.
    if sent.get("requester") is None:
        raise malformed(op, "no requester configured; a Broker resolves who is asking")
    validate_request(op, sent, DiscoveryRequest, cfg.validation)
    return _plan(cfg, _Route(op, cfg.base_url, BROKER_SERVICE, "Resolve"), sent)


def finish_resolve(cfg: ClientConfig, plan: Plan, status: int, body: str) -> DiscoveryResult:
    """Read the Broker's answer.

    Every returned offer is verified through the SAME fail-closed Verifier discover uses —
    not a second verification path. Broker-relayed offers are precisely the case that rule
    exists for: the Broker forwards offers it did not mint, and an unverified relay can
    steer an agent's selection with doctored terms that only fail later, at the purchase.

    A resolve that finds nothing is a SUCCESSFUL answer carrying a typed reason, not a
    failure.
    """
    msg, raw = decode_with_raw(plan.op, status, body, DiscoveryResponse, strict=plan.strict)
    groups = raw.get("offer_groups")
    return DiscoveryResult(
        groups=cfg.resolved_verifier().sort_groups(
            [_canonicalize_group(g) for g in groups] if isinstance(groups, list) else []
        ),
        absence_reason=msg.absence_reason.value if msg.absence_reason is not None else None,
        # A DiscoveryResponse names no single Exchange and carries no rate-limit signal —
        # each offer carries its own issuing domain instead.
        exchange="",
    )


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------


def plan_execute(
    cfg: ClientConfig,
    offer: VerifiedOffer | Sequence[VerifiedOffer] | RawBody,
    idempotency_key: str | None,
) -> Plan:
    """Assemble ExecuteTransaction for one VERIFIED offer, or several issued by ONE Exchange.

    It accepts ONLY VerifiedOffers — the construction token is module-private to the core,
    so a rejected offer or a raw parsed one cannot be passed. A per-call idempotency key is
    minted fresh unless one is pinned. It builds the whole TransactionRequest, so it also
    stamps ``ver`` from ProtocolVersion — the caller neither supplies nor overrides it.

    Several offers must all name the same Exchange: a direct purchase goes to one Exchange,
    and an Exchange refuses a request carrying an item addressed to anyone else, so a mixed
    set is refused here. Buying across Exchanges in one call is ``BrokerClient.execute``.
    """
    op = "execute"
    if isinstance(offer, RawBody):
        return _plan(cfg, _Route(op, cfg.base_url, EXCHANGE_SERVICE, "ExecuteTransaction"), offer)
    offers = [offer] if isinstance(offer, VerifiedOffer) else list(offer)
    _require_one_exchange(op, offers)
    sent = _build_transaction(cfg, op, offers, idempotency_key)
    validate_request(op, sent, TransactionRequest, cfg.validation)
    plan = _plan(cfg, _Route(op, cfg.base_url, EXCHANGE_SERVICE, "ExecuteTransaction"), sent)
    return replace(plan, items=_purchase_items(offers))


def plan_broker_execute(
    cfg: ClientConfig, offers: Sequence[VerifiedOffer] | RawBody, idempotency_key: str | None
) -> Plan:
    """Assemble the Broker's ExecuteTransaction: one purchase across any number of Exchanges.

    The request is the one a direct purchase sends — every item with the agent's detached
    acceptance, one request acceptance over the complete ordered set — and the Broker
    re-packages it into one sub-request per Exchange, signed with its own key, carrying the
    agent's acceptances unchanged.

    Refused here, with nothing sent: no requester, no signer, no offers, an unsigned offer,
    an offer that names no exchange, and a ``requester.domain`` that is not the host of the
    directory the signer signs as. The last mirrors the Broker's own check, which it refuses
    with ``request_auth_failure`` SIGNATURE_INVALID.
    """
    op = "broker execute"
    if isinstance(offers, RawBody):
        return _plan(cfg, _Route(op, cfg.base_url, BROKER_SERVICE, "ExecuteTransaction"), offers)
    if cfg.requester is None:
        raise malformed(op, "no requester configured; a Broker resolves who is buying")
    offers = list(offers)
    for i, item in enumerate(offers):
        if _str_field(_offer_wire(item), "exchange") == "":
            raise malformed(
                op,
                f"item {i} names no exchange; a Broker routes each item to the Exchange its "
                "offer names",
            )
    if cfg.signer is not None:
        _require_requester_is_signer(op, cfg.requester, cfg.signer.signature_agent)
    sent = _build_transaction(cfg, op, offers, idempotency_key)
    validate_request(op, sent, TransactionRequest, cfg.validation)
    plan = _plan(cfg, _Route(op, cfg.base_url, BROKER_SERVICE, "ExecuteTransaction"), sent)
    return replace(plan, items=_purchase_items(offers))


def finish_broker_execute(
    cfg: ClientConfig, plan: Plan, status: int, body: str
) -> BrokerExecuteResult:
    """Read the Broker's combined answer and verify every retrieval URL in it.

    An Exchange that refused the Broker's whole sub-request is NOT a failure here: the call
    succeeds, and each affected item carries the refusal in ``refusal`` while the other
    Exchanges' items come back unchanged. Only the Broker's own refusals raise.

    The one signed value in a result item is its retrieval URL, signed by the Exchange
    that issued the item's offer — the Broker cannot forge or alter one, and this is
    where that is checked. Each URL is verified against its own Exchange's key and the
    agent_identity_hash that Exchange's outcome states.
    """
    result: BrokerExecuteResult = decode(
        plan.op, status, body, BrokerExecuteResult, strict=plan.strict
    )
    if _verifies_deliveries(cfg, plan):
        outcomes = {o.exchange.lower(): o.agent_identity_hash or "" for o in result.exchanges or []}
        items = list(result.items or [])
        agent = _agent_thumbprint(cfg)

        def expected_of(index: int, item: Any) -> Expected:
            exchange = _issuing_exchange(plan, index, item, len(items))
            return Expected(exchange, agent, outcomes.get(exchange.lower(), ""))

        result._deliveries = verify_items(plan.op, items, expected_of, _delivery_keys(cfg))
    return result


def _offer_wire(offer: VerifiedOffer) -> dict[str, Any]:
    return offer.offer if isinstance(offer.offer, dict) else {}


def _build_transaction(
    cfg: ClientConfig, op: str, offers: list[VerifiedOffer], idempotency_key: str | None
) -> dict[str, Any]:
    """Build and sign the TransactionRequest every purchase verb sends.

    Each item reflects its signed Offer back exactly as received at discovery and carries the
    agent's detached acceptance of that one offer. The request acceptance over the complete
    ordered set is attached when every offer names its Exchange; an item without one cannot
    appear in that payload, which requires a recipient per item. Every acceptance covers the
    offer, the requester and the idempotency key, so a retry that pins the same key
    reproduces byte-identical acceptance bytes. That is the deliberate-replay semantic, not
    an accident.
    """
    if cfg.requester is None:
        raise malformed(op, "no requester configured; the party that sells resolves who is buying")
    if cfg.signer is None:
        # NOT_SIGNABLE, matching what fetch answers for the same missing holder: a caller
        # branching on the kind sees one condition under one class, whichever verb met it
        # first.
        raise CallError(
            CallErrorKind.NOT_SIGNABLE,
            op,
            cause=(
                "no signer configured; a purchase carries a detached acceptance signed "
                "with the agent's own key — the same key the request is signed with"
            ),
        )
    if not offers:
        raise malformed(op, "no offers to buy")
    wires = [_offer_wire(o) for o in offers]
    offer_sigs: list[str] = []
    for wire in wires:
        offer_sig = wire.get("signature")
        # An acceptance floating free of a concrete offer is meaningless, and an unsigned
        # offer is reachable here: Mode.OFF and RejectedOffer.unsafe() both mint a
        # VerifiedOffer without a signature check.
        if not isinstance(offer_sig, str) or offer_sig == "":
            raise malformed(op, "cannot accept an unsigned offer")
        offer_sigs.append(offer_sig)
    key = idempotency_key or generate_idempotency_key()
    requester_id = _str_field(cfg.requester, "id")
    requester_domain = _str_field(cfg.requester, "domain")
    request_items = [
        (sig, _str_field(w, "exchange")) for sig, w in zip(offer_sigs, wires, strict=True)
    ]
    items: list[dict[str, Any]] = []
    request_acceptance: dict[str, Any] | None = None
    try:
        for wire, offer_sig in zip(wires, offer_sigs, strict=True):
            signature, _algorithm = cfg.signer.sign_offer_acceptance(
                offer_sig=offer_sig,
                requester_id=requester_id,
                requester_domain=requester_domain,
                idempotency_key=key,
            )
            items.append(
                {
                    "offer": wire,
                    "agent_acceptance": {
                        "signature": signature,
                        "signature_algorithm": ACCEPTANCE_SIGNATURE_ALGORITHM,
                    },
                }
            )
        if all(exchange != "" for _sig, exchange in request_items):
            request_signature, _request_algorithm = cfg.signer.sign_request_acceptance(
                items=request_items,
                requester_id=requester_id,
                requester_domain=requester_domain,
                idempotency_key=key,
            )
            request_acceptance = {
                "payload": {
                    "items": [
                        {"offer_sig": sig, "exchange": exchange} for sig, exchange in request_items
                    ],
                    "requester_id": requester_id,
                    "requester_domain": requester_domain,
                    "idempotency_key": key,
                },
                "signature": request_signature,
                "signature_algorithm": ACCEPTANCE_SIGNATURE_ALGORITHM,
            }
    except Exception as exc:  # custody can fail any way it likes
        raise CallError(CallErrorKind.NOT_SIGNABLE, op, cause=exc) from exc
    # Items-only wire shape: a single offer is the degenerate 1-element items list. The
    # authoritative identity is the reflected offer; the optional top-level offer_id
    # correlation scalar is left unset.
    sent: dict[str, Any] = {
        "ver": ProtocolVersion,
        "idempotency_key": key,
        "requester": cfg.requester,
        "items": items,
    }
    if request_acceptance is not None:
        sent["agent_request_acceptance"] = request_acceptance
    return sent


def _require_one_exchange(op: str, offers: list[VerifiedOffer]) -> None:
    """Refuse a direct purchase whose offers were issued by more than one Exchange."""
    if not offers:
        return
    first = _str_field(_offer_wire(offers[0]), "exchange")
    for i, item in enumerate(offers[1:], start=1):
        other = _str_field(_offer_wire(item), "exchange")
        if other != first:
            raise malformed(
                op,
                f"item {i} is issued by {other!r} and item 0 by {first!r}; a direct purchase "
                "goes to one Exchange (buy across Exchanges with BrokerClient.execute)",
            )


def _require_requester_is_signer(op: str, requester: dict[str, Any], signature_agent: str) -> None:
    """Refuse a request whose ``requester.domain`` is not the host of the WBA directory the
    signer signs as.

    A Broker verifies the request signature against the key it resolves from the covered
    Signature-Agent directory and requires ``requester.domain`` to name that directory:
    every Exchange it relays to resolves the agent's acceptance keys from requester.domain.
    The comparison is the recipient-identity rule — exact, case-folded, an explicit :443
    the same as no port. An empty Signature-Agent names no directory, so it fails too.
    """
    if signature_agent == "":
        raise malformed(
            op,
            "no Signature-Agent configured; a Broker checks that requester.domain names the "
            "directory the request is signed from (set signature_agent on the signer)",
        )
    try:
        host = host_of(signature_agent)
        verdict = check_audience(host, _str_field(requester, "domain"))
    except ValueError as exc:
        raise malformed(
            op, f"signature agent {redact_userinfo(signature_agent)!r} names no usable host"
        ) from exc
    if verdict != "accepted":
        raise malformed(
            op,
            f"requester.domain {_str_field(requester, 'domain')!r} is not {host!r}, the host "
            "of the directory this client signs as; a Broker refuses the request "
            "(request_auth_failure SIGNATURE_INVALID)",
        )


def finish_execute(cfg: ClientConfig, plan: Plan, status: int, body: str) -> ExecuteResult:
    """Read the Exchange's answer and verify every retrieval URL in it.

    Each URL is verified against the key the Exchange that issued the offers publishes in
    its Web Bot Auth directory, and must be bound to this agent and to the
    agent_identity_hash the answer states. One that does not verify refuses the whole
    answer, as malformed, with the reason on a synthesized ``retrieval_auth_failure``
    detail and the item named in the message. The purchase itself happened; the
    transaction id in the message is what a dispute or a support request names.
    """
    result: ExecuteResult = decode(plan.op, status, body, ExecuteResult, strict=plan.strict)
    if _verifies_deliveries(cfg, plan):
        items = list(result.items or [])
        agent, stated = _agent_thumbprint(cfg), result.agent_identity_hash or ""

        def expected_of(index: int, item: Any) -> Expected:
            return Expected(_issuing_exchange(plan, index, item, len(items)), agent, stated)

        result._deliveries = verify_items(plan.op, items, expected_of, _delivery_keys(cfg))
    return result


def _purchase_items(offers: list[VerifiedOffer]) -> tuple[tuple[str, str], ...]:
    return tuple(
        (_str_field(_offer_wire(o), "offer_id"), _str_field(_offer_wire(o), "exchange"))
        for o in offers
    )


def _verifies_deliveries(cfg: ClientConfig, plan: Plan) -> bool:
    return not plan.raw and cfg.delivery_verification is Mode.STRICT


def _issuing_exchange(plan: Plan, index: int, item: Any, count: int) -> str:
    """The Exchange that issued the offer a result item answers.

    The answer carries one item per request item, in request order, so the index is the
    match; an answer of another length is matched by offer_id instead. An item neither
    places is attributed to the one Exchange a direct purchase went to, and to nobody on a
    relayed one — which then fails verification rather than borrowing another key.
    """
    if count == len(plan.items):
        return plan.items[index][1]
    offer_id = getattr(item, "offer_id", "") or ""
    for item_offer, exchange in plan.items:
        if offer_id and item_offer == offer_id:
            return exchange
    exchanges = {exchange for _offer, exchange in plan.items}
    return exchanges.pop() if len(exchanges) == 1 else ""


def _agent_thumbprint(cfg: ClientConfig) -> str:
    # A purchase that reached here was signed, so the signer is configured.
    return cfg.signer.thumbprint if cfg.signer is not None else ""


def _delivery_keys(cfg: ClientConfig) -> DeliveryKeyResolver:
    # Both facades fill this in at construction; the fallback serves a caller driving
    # the plan functions directly, at the cost of a transport per call.
    return cfg.delivery_keys if cfg.delivery_keys is not None else WBAKeyResolver()


# ---------------------------------------------------------------------------
# reportUsage and dispute — the offer-derived leg
# ---------------------------------------------------------------------------


def plan_report_usage(
    cfg: ClientConfig, report: RequestMessage, idempotency_key: str | None
) -> Plan:
    """Assemble a usage report for the Exchange that ISSUED the offer — never through a
    Broker, and never to an address from configuration.

    The destination comes off the report itself: ``exchange`` carries the offer's signed
    exchange domain, and the endpoint is then resolved from that Exchange's own well-known
    manifest. Reading it off the message rather than taking it as an argument is what
    makes the rule structural — there is no parameter a configured origin could be passed
    as, so it cannot become the default by anyone's convenience.

    The report is CLONED before ``ver`` and the idempotency key are stamped. The key
    identifies the REPORT, not the attempt: a fresh one is minted only when the caller
    supplied none, because an application that mints its own key for its own dedup would
    otherwise have it silently discarded and see every retry counted as a second report.
    """
    return _plan_offer_derived(
        cfg,
        _OfferDerived("report usage", UsageReport, "ReportUsage"),
        report,
        idempotency_key,
    )


def finish_report_usage(plan: Plan, status: int, body: str) -> UsageReportResponse:
    return decode(plan.op, status, body, UsageReportResponse, strict=plan.strict)  # type: ignore[no-any-return]


def plan_dispute(cfg: ClientConfig, request: RequestMessage, idempotency_key: str | None) -> Plan:
    """Assemble a dispute for the issuing Exchange, over the same vetted routing a usage
    report takes.

    The dispute chain is a structural invariant: an agent must have filed a usage report
    and received a report_id before it can dispute, so ``report_id`` and
    ``transaction_id`` both name links the Exchange already holds.
    """
    return _plan_offer_derived(
        cfg,
        _OfferDerived("dispute", DisputeRequest, "DisputeTransaction"),
        request,
        idempotency_key,
    )


def finish_dispute(plan: Plan, status: int, body: str) -> DisputeResponse:
    return decode(plan.op, status, body, DisputeResponse, strict=plan.strict)  # type: ignore[no-any-return]


@dataclass(frozen=True)
class _OfferDerived:
    """One offer-derived verb: its name, its request model, and its RPC method."""

    op: str
    model: Any
    method: str


def _plan_offer_derived(
    cfg: ClientConfig,
    verb: _OfferDerived,
    message: RequestMessage,
    idempotency_key: str | None,
) -> Plan:
    # Discovery and execute keep the plain transport, because their address is the
    # operator's own configuration. The same split the Go client makes.
    if isinstance(message, RawBody):
        return _plan_raw_routed(cfg, verb.op, verb.method, message)
    sent = _stamp_envelope(verb.op, message, idempotency_key)
    return _plan_routed_keyless(cfg, _Routed(verb.op, verb.model, verb.method), sent)


# ---------------------------------------------------------------------------
# account setup: register / get account status
#
# They route like a usage report, not like discovery. An account is per-Exchange,
# and which Exchange is the agent's choice PER CALL: a target routinely arrives at
# runtime — a denial names where to register — rather than from configuration.
#
# Neither message carries an idempotency key, so neither verb takes one.
# ---------------------------------------------------------------------------

#: The ErrorDetail domain for a refusal THIS CLIENT computed, before anything was sent.
#: It names the failing surface, which here is the client's own tier: the Exchange never
#: saw the request, so naming it would attribute a local verdict to a party that reached
#: none. The naming rule the value follows — a Service suffix for an RPC service that
#: exists in the contract, a bare noun for a tier that does not — is recorded on the Go
#: oracle's ``edgeErrorDomain``, beside ``_EDGE_ERROR_DOMAIN``'s twin.
_CLIENT_ERROR_DOMAIN = "fora.v1.Client"


def plan_register(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble a registration for the Exchange the request names.

    The caller's identity is the request SIGNATURE. Nothing in the message says who is
    registering, and the business payload is not an identity claim.

    Four bounds on ``registration_data`` are checked before anything is signed, in the
    order the contract fixes, because a limit that exists to stop work belongs before the
    work it would stop — including before the manifest read.

    ``terms_digest`` is filled only when the caller left it ABSENT, from a freshly fetched
    manifest, and the payload is pre-checked against the schema that manifest publishes. A
    caller that sets the field is managing its own requirements and gets neither.

    A schema this SDK refuses never becomes a local veto: refusing locally and declining
    to send would turn a rule about reading a third party's document into a denial of
    service against the caller's own user, so an unusable schema is skipped and the
    Exchange decides.
    """
    op = "register"
    if isinstance(request, RawBody):
        return _plan_raw_routed(cfg, op, "Register", request)
    sent = _stamp_ver(op, request)
    _require_recipient(op, _str_field(sent, "exchange"))
    data = sent.get("registration_data")
    verdict = check_registration_data(data if isinstance(data, dict) else None)
    if verdict != "accepted":
        raise malformed(op, f"registration_data: {verdict}")
    if sent.get("terms_digest") is None:
        _apply_registration_requirements(cfg, op, sent)
    return _plan_routed_keyless(cfg, _Routed(op, RegisterRequest, "Register"), sent)


def finish_register(plan: Plan, status: int, body: str) -> RegisterResponse:
    return decode(plan.op, status, body, RegisterResponse, strict=plan.strict)  # type: ignore[no-any-return]


def plan_get_account_status(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble a status read for the Exchange the request names.

    The request carries no field identifying the caller — the Exchange resolves the
    account from the verified signature — so ``exchange`` is the only thing that says
    which account is being asked about.

    Safe to call in a loop. The request has no varying field, but every request
    signature carries a fresh RFC 9421 nonce, so two calls to the same Exchange inside
    one wall-clock second still sign different bytes and a peer screening replays on
    (key id, signature) accepts both.
    """
    op = "get account status"
    if isinstance(request, RawBody):
        return _plan_raw_routed(cfg, op, "GetAccountStatus", request)
    sent = _stamp_ver(op, request)
    _require_recipient(op, _str_field(sent, "exchange"))
    return _plan_routed_keyless(cfg, _Routed(op, GetAccountStatusRequest, "GetAccountStatus"), sent)


def finish_get_account_status(plan: Plan, status: int, body: str) -> GetAccountStatusResponse:
    return decode(plan.op, status, body, GetAccountStatusResponse, strict=plan.strict)  # type: ignore[no-any-return]


def _apply_registration_requirements(cfg: ClientConfig, op: str, sent: dict[str, Any]) -> None:
    """Read what the Exchange asks of a registration and apply it to the request.

    A failed READ refuses the registration rather than sending without a digest. Guessing
    here is not the cautious option: an Exchange that publishes a digest refuses a
    registration that omits one, so sending anyway trades a local failure the caller can
    act on for a remote one it cannot.
    """
    # Both client facades fill this in at construction, so the fallback is only for a
    # caller driving the plan functions directly. It builds a transport per call, which
    # is why the clients do not go through it.
    reader = cfg.registration_requirements
    if reader is None:
        reader = WellKnownRequirementsReader()
    exchange = _str_field(sent, "exchange")
    try:
        reqs = reader.resolve_registration_requirements(exchange)
    # Every verdict this seam admits. The SDK's own reader raises all three itself —
    # the middle two for the document it was handed, and ManifestUnusableError for a
    # version it cannot classify — and an INJECTED reader stricter than it reaches the
    # same three. Only the invalid-host refusal is normally out of reach here, because
    # the verb's own recipient check runs that rule first. Calling any of them
    # retryable would have a caller retry a verdict.
    except (
        ExchangeNotPermittedError,
        ManifestNotExchangeError,
        ManifestUnusableError,
    ) as exc:
        # A value this deployment or the Exchange refused is FINAL; anything else is a
        # transport failure worth retrying. The same split the routing tier makes, so a
        # caller branches on one taxonomy whichever check declined.
        raise not_sent(op, str(exc)) from exc
    except CallError:
        raise
    except Exception as exc:  # noqa: BLE001 - classified, then re-raised as one shape
        if _is_invalid_host_refusal(exc):
            raise not_sent(op, str(exc)) from exc
        raise CallError(kind=CallErrorKind.UNREACHABLE, op=op, cause=exc) from exc
    if reqs.terms_digest is not None:
        sent["terms_digest"] = reqs.terms_digest
    # A None validator means "nothing to enforce", which is the behaviour the contract
    # requires both when the Exchange publishes no schema and when it publishes one this
    # SDK refused. One branch, deliberately.
    data = sent.get("registration_data")
    fails = reqs.schema.validate(data if isinstance(data, dict) else None) if reqs.schema else []
    if fails:
        # An empty path addresses the whole object, which is how a missing required
        # member and every other whole-object failure is reported. Rendering a bare
        # ": ..." there would read as a member with no name.
        named = "; ".join(
            f"{p}: {f.get('error', '')}" if (p := f.get("path", "")) else f.get("error", "")
            for f in fails
        )
        # The failures travel as a typed detail, not only as prose. An Exchange attaches
        # this same list when it refuses the same payload, so a consumer that renders one
        # refusal renders both, and nothing has to parse the members back out of a
        # sentence.
        raise CallError(
            kind=CallErrorKind.MALFORMED,
            op=op,
            cause=f"registration_data does not match the schema {exchange} publishes: {named}",
            detail=registration_failure_detail(
                _CLIENT_ERROR_DOMAIN,
                "registration_data does not match the published data_schema",
                RegistrationFailureReason.REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
                fails,
            ),
        )


@dataclass(frozen=True)
class _Routed:
    """One manifest-routed verb that carries no idempotency key: its name, its request
    model, and its RPC method."""

    op: str
    model: Any
    method: str


def _plan_routed_keyless(cfg: ClientConfig, verb: _Routed, sent: dict[str, Any]) -> Plan:
    """The routing half every manifest-addressed verb shares, with the envelope already
    stamped by the caller.

    It exists so the order — address, then schema, then the guarded leg — is written
    once. The address is vetted BEFORE the schema: an unroutable recipient is a refusal to
    send, which is a different verdict from a message the server would reject, and the
    caller acts on them differently.
    """
    op = verb.op
    endpoint = vet_exchange_endpoint(cfg.endpoint_resolver, _str_field(sent, "exchange"), op)
    validate_request(op, sent, verb.model, cfg.validation)
    # The manifest-derived leg, so the guarded transport: the caller named a domain, the
    # manifest it serves named this endpoint, and a signed call now goes there.
    return _plan(cfg, _Route(op, endpoint, EXCHANGE_SERVICE, verb.method), sent, guarded=True)


# ---------------------------------------------------------------------------
# catalog: push / remove / refresh
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CatalogVerb:
    """One catalog verb: its name, its request model, and its RPC method."""

    op: str
    model: Any
    method: str


_PUSH_RESOURCES = _CatalogVerb("push resources", PushResourcesRequest, "PushResources")
_REMOVE_RESOURCES = _CatalogVerb("remove resources", RemoveResourcesRequest, "RemoveResources")
_REFRESH_CATALOG = _CatalogVerb("refresh catalog", RefreshCatalogRequest, "RefreshCatalog")


def plan_push_resources(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble PushResources. See :func:`_plan_catalog` for the envelope rule."""
    return _plan_catalog(cfg, _PUSH_RESOURCES, request)


def finish_push_resources(plan: Plan, status: int, body: str) -> PushResourcesResponse:
    return decode(plan.op, status, body, PushResourcesResponse, strict=plan.strict)


def plan_remove_resources(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble RemoveResources. See :func:`_plan_catalog` for the envelope rule."""
    return _plan_catalog(cfg, _REMOVE_RESOURCES, request)


def finish_remove_resources(plan: Plan, status: int, body: str) -> RemoveResourcesResponse:
    return decode(plan.op, status, body, RemoveResourcesResponse, strict=plan.strict)


def plan_refresh_catalog(cfg: ClientConfig, request: RequestMessage) -> Plan:
    """Assemble RefreshCatalog. See :func:`_plan_catalog` for the envelope rule."""
    return _plan_catalog(cfg, _REFRESH_CATALOG, request)


def finish_refresh_catalog(plan: Plan, status: int, body: str) -> RefreshCatalogResponse:
    return decode(plan.op, status, body, RefreshCatalogResponse, strict=plan.strict)


def _plan_catalog(cfg: ClientConfig, verb: _CatalogVerb, message: RequestMessage) -> Plan:
    """The one shape all three catalog verbs share.

    The request is CLONED before ``ver`` is stamped (fill-when-empty; the caller's value
    is theirs); no idempotency key is stamped, because the messages carry none — a catalog
    push is an upsert and naturally idempotent, so a key there would be ceremony.
    ``exchange`` is the caller's to set, the bare domain of the Exchange the call is meant
    for; a request that names none, or names something that is not a bare domain, is refused
    before anything is signed or sent — a refusal to send, the verdict a report with no
    routable recipient gets, not a malformed message.

    The publisher chose the Exchange, so the origin is configuration and the leg runs on
    the plain transport — the posture of the home Exchange, not of the offer-derived leg.
    """
    op = verb.op
    route = _Route(op, cfg.base_url, CATALOG_SERVICE, verb.method)
    if isinstance(message, RawBody):
        return _plan(cfg, route, message)
    sent = _stamp_ver(op, message)
    _require_recipient(op, _str_field(sent, "exchange"))
    validate_request(op, sent, verb.model, cfg.validation)
    return _plan(cfg, route, sent)


def _stamp_ver(op: str, message: dict[str, Any] | BaseModel) -> dict[str, Any]:
    sent = _clone(op, message)
    if _str_field(sent, "ver") == "":
        sent["ver"] = ProtocolVersion
    return sent


def _require_recipient(op: str, exchange: str) -> None:
    """Refuse a request whose recipient is missing or not a bare domain.

    Serves the catalog verbs and the two account verbs, and asks only the SHAPE question.

    The predicate is :func:`is_bare_domain`, the SHAPE rule, not the routing rule
    :func:`is_bare_host`. The only question it answers is whether the value is the form
    the contract admits, which is the protovalidate pattern ``exchange`` carries and the
    same rule the Exchange's own audience check applies on arrival. Whether the value can
    be DIALLED is a separate question with a separate answer: a catalog client is built
    against an address the publisher configured and never asks it, while the account verbs
    resolve this domain through its own manifest and ask it there, under the routing
    predicate. The
    routing predicate is deliberately wider: an underscore, a trailing root dot and a
    bracketed IPv6 literal are all usable hosts and none of them is a value this field may
    hold, so vetting with it would sign and send a request the recipient can only refuse.

    The refused value is redacted before it is named. A reference carrying userinfo is a
    verdict rather than a parse failure, so it would otherwise reach the message below
    verbatim; the routing check next door redacts for the same reason, and a tier that
    echoes is the drift ``_redact_userinfo`` exists to prevent.
    """
    if exchange == "":
        raise not_sent(op, "request names no recipient; set exchange to the Exchange's bare domain")
    if not is_bare_domain(exchange):
        raise not_sent(op, f"exchange {redact_userinfo(exchange)!r} is not a bare domain")


# ---------------------------------------------------------------------------
# Envelope stamping
# ---------------------------------------------------------------------------


def _stamp_discovery(
    op: str, message: dict[str, Any] | BaseModel, requester: dict[str, Any] | None
) -> dict[str, Any]:
    """Fill the envelope a DISCOVERY call carries, which is the mutating envelope minus
    the idempotency key: pure discovery buys nothing and changes nothing, so there is no
    action for a key to identify.

    Both fills are only-when-empty. The caller's own value always wins — the message
    crossed a module boundary as an argument, not as a buffer to fill in — and the
    requester is filled because both reference services resolve the calling agent from it
    and refuse a request that names none, while the client already holds that identity.
    """
    sent = _clone(op, message)
    if not sent.get("ver"):
        sent["ver"] = ProtocolVersion
    if sent.get("requester") is None and requester is not None:
        sent["requester"] = requester
    return sent


def _stamp_envelope(
    op: str, message: dict[str, Any] | BaseModel, idempotency_key: str | None
) -> dict[str, Any]:
    """Fill the two envelope fields the protocol requires on a state-mutating call,
    WITHOUT overwriting what the caller already set.

    Fill-when-empty is the whole rule. ``ver`` has a single owner, so the SDK supplies it
    rather than making every caller reach for the constant. The idempotency key is
    REQUIRED and identifies the action rather than the attempt, so a value the caller put
    there is theirs — discarding it would turn each of their retries into a fresh action,
    which is the double-counting the field exists to prevent. A pinned key overrides both.
    """
    sent = _clone(op, message)
    if not sent.get("ver"):
        sent["ver"] = ProtocolVersion
    on_message = sent.get("idempotency_key")
    sent["idempotency_key"] = (
        idempotency_key
        or (on_message if isinstance(on_message, str) and on_message else None)
        or generate_idempotency_key()
    )
    return sent


def _rate_limit(parsed: Any, wire: Any) -> dict[str, Any] | None:
    """The decoded rate-limit standing, spelling reset_at the way the peer did.

    Every other member comes from the parse, which is what the other two SDKs answer with:
    an int32 the peer spelled as a string arrives as a number, and a member the schema does
    not declare is gone. reset_at is taken from the wire because it is the only one the
    parse cannot hand back unchanged.

    The wire value is only used when it is a string, which the parse has already proved
    well formed — a shape that disagrees with its own parsed twin does not get to decide
    what this field says.
    """
    if parsed is None:
        return None
    standing: dict[str, Any] = parsed.model_dump(mode="json")
    sent = wire.get("reset_at") if isinstance(wire, dict) else None
    if isinstance(sent, str):
        standing["reset_at"] = sent
    return standing


def _clone(op: str, message: dict[str, Any] | BaseModel) -> dict[str, Any]:
    """Copy a caller's message so the SDK can stamp its envelope without touching what the
    caller still holds. A deep copy, because the envelope fields are top-level but a
    caller re-using a nested object across calls must not see it change either.

    A generated model is rendered through :func:`to_wire` instead, which already returns
    a fresh object. This is the one point every dict-taking verb passes through, so a
    model and the equivalent dict are serialized the same way exactly once."""
    if isinstance(message, BaseModel):
        return to_wire(message)
    try:
        return copy.deepcopy(dict(message))
    except Exception as exc:  # a message that cannot be copied cannot be sent
        raise malformed(op, exc) from exc


@dataclass(frozen=True)
class _Route:
    """Where one call goes, and what it is called in a failure."""

    op: str
    base_url: str
    service: str
    method: str


def _plan(
    cfg: ClientConfig,
    route: _Route,
    sent: dict[str, Any] | RawBody,
    *,
    guarded: bool = False,
) -> Plan:
    op = route.op
    url = rpc_url(route.base_url, route.service, route.method)
    body, headers = prepare(op, url, sent, cfg)
    return Plan(
        op=op,
        url=url,
        body=body,
        headers=headers,
        timeout=cfg.call_timeout_sec,
        max_bytes=cfg.max_rpc_read_bytes,
        guarded=guarded,
        sent=sent.parsed() if isinstance(sent, RawBody) else sent,
        strict=cfg.strict,
        raw=isinstance(sent, RawBody),
    )


def _plan_raw_routed(cfg: ClientConfig, op: str, method: str, raw: RawBody) -> Plan:
    """A raw call to a manifest-routed verb: the destination is the body's ``exchange``.

    The address a signed call goes to is vetted whatever the message says, so the
    resolution and its address checks run as for any routed call; a body that names no
    usable Exchange has nothing to dial and is refused as not sent.
    """
    endpoint = vet_exchange_endpoint(
        cfg.endpoint_resolver, _str_field(raw.parsed(), "exchange"), op
    )
    return _plan(cfg, _Route(op, endpoint, EXCHANGE_SERVICE, method), raw, guarded=True)


def _str_field(record: dict[str, Any] | None, key: str) -> str:
    if record is None:
        return ""
    value = record.get(key)
    return value if isinstance(value, str) else ""
