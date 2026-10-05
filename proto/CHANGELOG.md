# FORA Protocol Changelog

## Unreleased

**Discovery has no side effects; usage-report and relayed-acceptance refusals are
stated (comments only).** Five rules the contract implied but did not state:

- `DiscoverResources` creates no transaction, no billing authorization and no reporting
  obligation; an agent commits to an offer only on the execute path.
- Discovery is therefore safe to retry. A transport failure, such as an unreachable
  Exchange or a timeout, is the client's concern, and the protocol defines no
  transient-failure code for it.
- A usage report whose `billing_id` is not the transaction's is malformed:
  `invalid_argument` with `USAGE_REPORT_REJECTION_REASON_MALFORMED`.
- A usage report for a transaction recorded under a different agent is answered exactly as
  for an unknown transaction, `not_found` with
  `USAGE_REPORT_REJECTION_REASON_TRANSACTION_NOT_FOUND`, so the answer does not reveal that
  the transaction exists.
- On a purchase a Broker relayed, an item whose `AgentAcceptance` does not verify under the
  keys the directory `requester.domain` names publishes is denied in the body with
  `DENIAL_REASON_SIGNATURE_INVALID`, as for the `AgentRequestAcceptance`; the whole request
  is not refused.

The `DiscoverResources` RPC, the `UsageReport` message and `DENIAL_REASON_SIGNATURE_INVALID`
state them, and the transaction-flow and Exchange request-flow pages follow.

**`GetAccountStatus` answers an agent with no account `NOT_FOUND` (comments only).**
The RPC comment now states the answer for an agent the Exchange knows, its request
signature verified, but that holds no account at that Exchange: the Connect code
`NOT_FOUND`. `GetAccountStatusResponse.billing_ref` is therefore set on every OK answer,
and a receiver reads an empty handle, which an Exchange built before the rule may send,
as the same answer. The reference and AI-agent pages and the SDK doc comments of
`GetAccountStatus` / `get_account_status` / `getAccountStatus` say the same; the SDKs
return the refusal as their call error with the code `not_found`.

**The hop cap counts every signature and is refused with `resource_exhausted` (comments
only).** `WellKnownManifest.max_intermediary_hops` is the maximum number of RFC 9421
signatures an Exchange accepts on a request, every signature counted whether or not it
covers another. An Exchange refuses a request carrying more before it verifies any
signature, with the Connect code `resource_exhausted` (HTTP 429) and no typed reason; the
field comment states it once. Go's `connectserver.WithMaxSignatures` and
`helpers.VerifyOptions.MaxSignatures` no longer say to set the cap to
`max_intermediary_hops + 1`: they take `max_intermediary_hops` itself, as the Python and
TypeScript verifiers already did.

**An MCP tool error carries `{"refusal": UpstreamRefusal}`; `UpstreamRefusal.exchange`
is renamed `party` (field rename; no released message changes).** `UpstreamRefusal` is the
one shape for "a peer refused a call made on the caller's behalf". Its field 1 was named
`exchange`, which fit only a Broker purchase. It is now `party`, the bare host of the party
that refused, with the same number and host rule. On a Broker purchase item the party is
the Exchange, equal to the refused items' signed `offer.exchange`. `UpstreamRefusal` was
added in this release, so no released message changes and `buf breaking` passes against
v1.0.8 and v1.0.0; the proto-JSON name is now `party`.

The Identity Service and AI-agent pages specify an MCP tool error: an error result whose
`structuredContent` is `{"refusal": UpstreamRefusal}`, the party being the Broker or
Exchange that refused the call, or the Identity Service itself when it refused the tool
call; `detail` is the FORA `ErrorDetail` that party attached, unchanged. Each tool's
`outputSchema` declares two branches, its success shape or `{refusal}`.

**Revocation is scoped to the signer, and revocation-list and manifest fetches may
follow up to five redirects (comments and docs only).** Each signature is verified against its own signer's
key directory and the revocation list that directory names, and against no other party's.
A Broker's list covers only the Broker's keys, and an agent's list covers only that
agent's keys, so no party's list can revoke another party's key. A request that carries
several request signatures is refused if any one of them fails, and a request signed only
by the agent never depends on the Broker's directory being reachable. A party fetching a
revocation list or a `/.well-known/fora.json` manifest MAY follow up to five redirects,
re-pinning the address and re-vetting the scheme at each hop. A key directory is never
fetched through a redirect: it answers `200` itself, as the Web Bot Auth profile below
requires. The file header, `WBAFile.revocation_url`, `KeyRevocationList` and the
Well-Known Discovery block state both rules, and the authentication page gains "Whose
list revokes whose key" and "Fetching directories, revocation lists and manifests".

**`PushResourcesRequest.caller_id` is deprecated (comments only).** It was never needed:
each entry's domain names whose resource it is, and the caller is the party that signs
the request; the Exchange checks that the verified signer may push for each entry's
domain, and a receiver does not rely on it. The field is retained for the v1 wire
contract; it does not yet carry the `deprecated` field option, which follows once
implementations no longer read it. The SDK docs, test fixtures and the catalog pages (reference,
multi-tenant, request flows, content sources, verification vendors, publisher onboarding,
deployment models, threat model) no longer set or rely on it.

**Docs: CoMP keys, self-push and custodied signing (docs only).** The licensing-terms page
no longer cites a CoMP `revshare` key: canonical CoMP V1 has none, and `fora-comp-v1`
keys are flat dotted keys in `ext` like every other profile's, as the CoMP page says. Its
revenue-share example gates the term on the scope the agent states in its signed request.
The for-providers page says a publisher may always push for its own domain, and only
listed contributors besides. The identity overview says the service signs an acceptance
with the agent's own custodied key.

**Term scopes are matched against the scopes in the requester's signed request
(comments only).** `LicenseTerm.scopes` said the Exchange returns a term when the agent's
delegation grant covers its scopes, and the Restriction header said term visibility is
gated by delegation scope coverage. The Exchange returns an offer for a term when the
scopes in the requester's signed request (`Requester.scopes`) cover the term's scopes.
The threat model's scope-pollution and scope-gating entries say the same.

**Restrictions are declared terms, never enforced by the Exchange;
`DENIAL_REASON_RESTRICTION_NOT_SATISFIED` and `TransactionResultItem.restriction_mismatches`
are deprecated (comments only).** The licensing-core header, the ENUMERATED and
REFERENCE_ONLY comments and the Quota comment said restrictions and quotas are enforced
or gate a term's validity. They are declared terms the parties agree to when the agent
accepts the offer, and the Exchange never enforces a restriction, so a purchase is never
denied for one. `DENIAL_REASON_RESTRICTION_NOT_SATISFIED` is never sent and
`TransactionResultItem.restriction_mismatches` is never set; their numbers are retained
and not reused. The licensing-terms, transaction-flow, reference, C2PA and medical-imaging
pages follow: the medical-imaging walkthrough records the agent's DUA instead of denying
the purchase with a restriction reason.

**RemoveResources names each resource by domain and path (additive field and message;
`RemoveResourcesRequest.paths` deprecated).** A bare path names no domain, so the Exchange
could not tell whose resource it was or whether the signer may remove it. The new
`RemoveResourcesRequest.resources` (field 5, 1 to 256 items) carries `ResourceRef`
items, each a `domain` and a `path` under `ResourceEntry`'s rules. For each item the
Exchange resolves `/.well-known/fora.json` from its domain and checks that the request's
signer is authorized to push for that domain, exactly as for a push; the caller is the
party that signs. `paths` is deprecated and ignored, and loses its `min_items` rule, so a
request carrying only `paths` is refused by the `min_items` rule on `resources`. The Go
SDK's client comment and tests, the TypeScript raw-body test and the conformance cases
use `resources`; the reference and multi-tenant pages say the same.

**A mis-addressed request is refused before processing, for every RPC (comments only).**
"Request recipient" says the recipient applies the `exchange` check to every RPC that
carries it, before processing the request, and never answers it with an RPC's own reason
family. `PushResourcesResponse` limits its "a push that could not be applied carries
`catalog_rejection`" to pushes the Exchange processed: a mis-addressed or malformed push
is `invalid_argument` with no typed reason, and one whose signature fails is
`unauthenticated` with `request_auth_failure`. The reference page says the same.

**Catalog push refusals: wire bounds, the contributor reason and
`CATALOG_REJECTION_REASON_EXCHANGE_NOT_LISTED` (one additive enum value).** A push with no
entries or more than 256 is a malformed request: the existing `min_items` and `max_items`
rules refuse it at wire validation, `invalid_argument` with no `catalog_rejection`. An
entry naming a resource owner the signer may not push for is
`CATALOG_REJECTION_REASON_NOT_CATALOG_CONTRIBUTOR`, whose comment now says who may push.
The new `CATALOG_REJECTION_REASON_EXCHANGE_NOT_LISTED` (11) refuses a push for a domain
whose manifest does not list the recipient Exchange. The SDK error-detail decoders in
Python and TypeScript know the new value; the reference and Exchange request-flow pages
state the same.

**A Broker forwards the agent's `supported_profiles` and does not route by them
(comments only).** `DiscoveryRequest.supported_profiles` said the Broker routes queries to
Exchanges that support the agent's profiles. The Broker MUST forward the list unchanged in
`ResourceQuery.supported_profiles` on every query, and an absent list as absent; it does
not choose Exchanges by profile, and each Exchange answers for its own profiles. The
Broker overview, the extension-profile pages and the getting-started pages say the same.

**A request's critical extensions are for its receiver, and an entry's are for the agent:
`UNKNOWN_CRITICAL_EXTENSION` is added to three reason enums (additive enum values).** The
file header gains "Critical extensions", the one statement of the rule. A request's
`ext_critical` is for the party that receives that request; a receiver that does not
understand a listed key answers with its RPC's reason: OK with no offers and
`OFFER_ABSENCE_REASON_UNKNOWN_CRITICAL_EXTENSION` on discovery and `Resolve`, OK with
every item denied as the new `DENIAL_REASON_UNKNOWN_CRITICAL_EXTENSION` (20) on a
purchase, the new `CATALOG_REJECTION_REASON_UNKNOWN_CRITICAL_EXTENSION` (10) on a catalog
push, and the new `USAGE_REPORT_REJECTION_REASON_UNKNOWN_CRITICAL_EXTENSION` (6,
`invalid_argument`) on a usage report. `ResourceEntry.ext_critical` is for the agent: the
Exchange carries it onto `Offer.ext_critical` and does not consume it, so it never
refuses a push. The SDK error-detail decoders in Python and TypeScript know the new
values, and the extension-profiles, academic walkthrough and what-is-FORA pages state
the rule.

**A catalog call whose signature fails is refused with `request_auth_failure`;
`CATALOG_REJECTION_REASON_SIGNATURE_INVALID` is deprecated (comments only).** A signed
`CatalogService` call is refused like every other signed request when its signature is
missing, does not verify or is stale: `unauthenticated` with
`ErrorDetail.request_auth_failure` (`SIGNATURE_MISSING`, `SIGNATURE_INVALID` or
`SIGNATURE_STALE`). `CATALOG_REJECTION_REASON_SIGNATURE_INVALID` is never sent; its number
is retained and is not reused. The Exchange request-flow page no longer lists it.

**An offer carries its price once: `Offer.pricing` (two validation rules added;
`LicenseTerm.pricing` loses its field-level rule; no field removed).** An offer carried its
price twice, in `Offer.pricing` and in the pricing of the one term it sells, and the
comment called the term's copy authoritative. The two could disagree inside one signed
offer, nothing said which one execute charges, and the metered rule read either copy.

- `Offer.pricing` is the offer's only price: the price execute charges, a Broker ranks and
  a metered purchase is charged at. The term inside `Offer.terms` MUST carry no pricing (rule
  `offer.terms.pricing_unset`, on `Offer`). Each offer derives from exactly one catalog
  term, so the price is stated once and cannot disagree with itself.
- `offer.metered.estimate_positive` reads `Offer.pricing` only: an offer is metered when
  its pricing is `PER_UNIT`.
- Catalog terms still carry pricing. `LicenseTerm.pricing` loses its field-level `required`
  rule, because the requirement depends on the message that holds the term, and
  `ResourceEntry` gains `resource_entry.terms.pricing_required`: every catalog term carries
  its price, whatever its semantics. A standalone `LicenseTerm` without pricing is no
  longer refused on its own.
- `buf breaking` against v1.0.0 passes. A validating peer now refuses an offer whose term
  carries pricing, including inside a `TransactionRequest`.
- The field-level corpus drops `LicenseTerm/pricing/missing`. The cross-field corpus gains
  two priced-term offers and a `ResourceEntry` term without pricing, replacing the metered
  term-only case, and the license-term entry vectors report a catalog term without pricing
  as that cross-field rule.

SDKs, in all three languages: `IsMeteredOffer` / `is_metered_offer` / `isMeteredOffer` read
the offer's pricing only. New `CheckOfferTermsUnpriced` / `check_offer_terms_unpriced` /
`checkOfferTermsUnpriced` apply `offer.terms.pricing_unset` without wire validation (Go
returns `helpers.ErrOfferTermPriced`, new; Python raises `ValueError`; TypeScript throws).
The offer signers (`helpers.SignOffer`, `sign_offer_jcs`, `signOffer`) refuse an offer whose
term carries pricing, and the offer verifiers reject one after the signature and expiry
checks. The Python and TypeScript cross-field layers gain both rules, with a composed
`ResourceEntry` model, and `validate_resource_entry` / `validateResourceEntry` check the
entry itself. The offer-verify vectors gain a term repeating the offer's price, which is
rejected, and an unpriced term under a `FLAT` price, which verifies.

**A per-item purchase denial is always answered in the body (comments and two
deprecations; no wire change).** A denied one-item purchase was described as a non-OK
error carrying `ErrorDetail.transaction_denial`, while the same denial in a batch rode in
the body, so a caller handled one decision in two shapes.

- `ExecuteTransaction`, `TransactionResponse` and `TransactionResultItem.denial_reason`
  state that every per-item denial is answered in the body, whatever the item count.
  `TransactionDenial` is used only when the Exchange refuses the whole request and decides
  no item, for a reason about the caller that would deny every item alike (for example
  `ACCOUNT_NOT_REGISTERED`, `ACCOUNT_INACTIVE`, `REPORTING_OVERDUE`, `RATE_LIMITED`).
  `TransactionDenial.restriction_mismatches` and `TransactionDenial.offer_id` are
  deprecated and never set.
- `DENIAL_REASON_RELAY_NOT_ACCEPTED` is decided per item by each offer's provider, the
  provider that sells that resource, and answered in the body. It is never a refusal of the whole
  sub-request, and an Exchange never sends it as `transaction_denial`.
- A sub-request whose items are not exactly the agent's `AgentRequestAcceptance` projected
  onto the Exchange (an item dropped, added or reordered) has every item denied with
  `DENIAL_REASON_SIGNATURE_INVALID`, in the body: the agent's signature does not cover
  what arrived. It is not `invalid_argument`, nothing is purchased, and no request-level
  idempotency state is claimed.

**A usage report is refused for time, never for quantity (comments; one admin field
deprecated).** `UsageReportRejectionReason` states that the reported quantity is
unrestricted: no reason refuses a report because its `consumed_quantity` differs from the
estimate, above or below. Monitoring how far reports fall from estimates is the Exchange
operator's own business, not part of the protocol.
The existing `USAGE_REPORT_REJECTION_REASON_WINDOW_EXPIRED` is the time cause, refused with
`failed_precondition`; `USAGE_REPORT_REJECTION_REASON_MALFORMED` is a malformed report,
refused with `invalid_argument`.
`fora.admin.v1.ReportingPolicy.quantity_tolerance` is deprecated and ignored: an Exchange
must not refuse a report on it.

**Idempotency keys are scoped per caller, and a reused key with a different request is
refused (comments only).** The file header gains "Idempotency", the one statement of the
rule for `TransactionRequest`, `UsageReport` and `DisputeRequest`. A key is scoped to the
authenticated agent, and to the pair (Broker, requester) on a purchase relayed through
`BrokerService.ExecuteTransaction`; a key another agent or tenant used is never a
collision. The same key with the same request is a replay answered from the stored result.
The same key with a different request (for a purchase, different items or another order)
is refused with the Connect code `already_exists` and an `ErrorDetail` with no typed reason.

**`BrokerService.Resolve` reports a budget as `BUDGET_EXCEEDED` (comments only).**
`Resolve` may apply the agent's budget (`RequestConstraints`) as a filter over the offers it
returns. How the budget is computed is the Broker's own behaviour, and the protocol does
not specify it: which price an offer is compared at, and how spend is counted, are left to
the party that applies the budget. What the protocol fixes is the report: a URI left with
no offer is answered with `OFFER_ABSENCE_REASON_BUDGET_EXCEEDED`, never `NOT_AUTHORIZED`
and never an error such as `RESOURCE_EXHAUSTED`, and `Resolve` never charges. The
`RequestConstraints` budget fields keep plain meanings, and `period_budget` no longer says
transactions are denied.

**`TransactionResponse.total_cost` is unset when the items span currencies (comments
only).** It is the exact sum of the purchased items' costs in their one shared currency,
and unset when they span more than one. Currency conversion is out of scope for this
version, which `BrokerTransactionResponse.totals` states too.

**`DisputeTransaction` states its refusal reasons (comments only).** Every Exchange
implements the RPC. Each `DisputeFailureReason` now names its check: no transaction for the
caller, no accepted report for this transaction, the dispute window closed, a dispute
already filed (a retry under the same key is a replay), and a transaction whose state
admits no dispute.

Docs: the transaction-flow page gains "Denials are in the body" and "Idempotency", states
the report refusals and the dispute refusal reasons, and drops "no refunds in the
protocol". The Exchange request flow answers every per-item denial in the body, scopes the
idempotency key per caller, leaves `total_cost` unset across currencies and stops
checking a minimum billable quantity. The Broker pages describe the budget as a filter at
`Resolve` and drop the currency converter and the generated idempotency key. The money-flow
page divides `unit_cost` by the resource's size rather than by `estimated_quantity`, and
every walkthrough and example that paired a per-access unit with a token-count estimate now
states the estimate in the price's own unit. The medical-imaging walkthrough answers its
DUA failure in the body. Offer examples drop their terms' pricing, and the licensing-terms,
reference and threat-model pages state the same rules.

**A metered purchase charges estimate × rate, or one unit's rate without an estimate, and
the charge is final (comments and one validation rule; no wire change).** A `PER_UNIT`
price is charged per unit, but the protocol did not say what a metered purchase charges.

- The publisher states the rate and the unit. An offer may state a rate with or without
  `pricing.estimated_quantity`; whether to state one is the publisher's decision, and
  nothing requires it, on the pushed term or on the offer. An estimate an offer states is
  positive (rule `offer.metered.estimate_positive`, on `Offer`). An estimate the publisher
  states, on the term's own pricing or once on `ResourceEntry.estimated_quantity`, is
  carried onto `Offer.pricing`, the term's own taking precedence.
- Stated once, on `Pricing`: a metered purchase charges E × R, or one unit, 1 × R, when
  the offer states no estimate. That is what `TransactionResultItem.cost` carries, and the
  charge is final. A disagreement about the quantity consumed is a dispute, which this
  version does not define further. A price whose metering is `NONE` is no different.
- A usage report is a record of the quantity consumed. `UsageReport`,
  `Usage.consumed_quantity`, `ReportingObligation` and `UsageReportRejectionReason` state
  that a report whose quantity differs from the estimate is never refused for it.
- `buf breaking` against v1.0.0 passes. The rule is new validation: a validating peer
  refuses a `PER_UNIT` offer that states a zero or negative estimate, including inside a
  `TransactionRequest`. A `PER_UNIT` offer with no estimate is valid. The cross-field
  corpus gains the zero and negative cases, and the conformance cases accept a metered
  offer with no estimate, alone and inside a `TransactionRequest`.

SDKs, in all three languages: the offer verifiers reject a metered offer whose stated
estimate is not positive, after the signature and expiry checks (Go: `core.Verifier`,
reason `helpers.ErrMeteredEstimateNotPositive`), and verify a metered offer that states
none. New checks `IsMeteredOffer` / `is_metered_offer` / `isMeteredOffer` and
`CheckMeteredEstimate` / `check_metered_estimate` / `checkMeteredEstimate` apply the rule
without wire validation. The offer-verify vectors gain the metered cases, among them a
metered offer with no estimate that verifies.

Docs: the transaction-flow page gains "Charging a metered purchase", and its list of
report checks drops the ±20% quantity tolerance that refused honest reports, as do the
Exchange storage model and the scenario walkthrough. The licensing-terms page gains
"Metered pricing: rate, unit and estimate", and the money-flow page, the reference page
and the walkthroughs describe the charge.

**An acceptance names its requester: `Requester.id` and `Requester.domain` are required
(validation rules added; no wire change).** An agent's offer acceptance signs canonical
bytes built from the offer, the request's `Requester` and the idempotency key. The proto
let `Requester.id` be empty, and the SDKs signed an empty `requester_domain` as well, so
those bytes could name no requester. On a purchase relayed through
`BrokerService.ExecuteTransaction`, that acceptance is the only agent signature the
Exchange sees: the request signature there is the Broker's, which says only that the call
comes from the Broker and never signs the purchase.

- `Requester.id` is REQUIRED, 1 to 255 characters. It is a free label the agent chooses
  for attribution, for example to tell apart sub-agents or end customers behind one key
  directory. It is never identity, never used to find keys, and never trusted.
- `Requester.domain` is REQUIRED, a non-empty bare host under the same pattern every other
  domain field uses. The pattern already refused an empty value; the comment now says so.
  The field is the host of the agent's key directory, and never a free label.
- The `Requester.domain` comment said verification never uses the field, which
  contradicted the relayed purchase. It now states the rule per path. On a direct request
  (the agent's own signature arrives), a verifier resolves the agent's keys from the
  covered `Signature-Agent` and MUST require `Requester.domain` to name that same
  directory, compared by the request-recipient identity rule; a mismatch is refused as
  `unauthenticated` with `request_auth_failure` `SIGNATURE_INVALID`. An Exchange applies
  this to every request the agent signed, as a Broker already did on
  `ExecuteTransaction`. On a purchase relayed through a Broker, the Exchange MUST verify
  the agent's acceptances against the key directory `Requester.domain` names. On a
  Broker's discovery fan-out, which carries no agent signature, the field is the Broker's
  statement of whom it queries for.
- `AgentAcceptance`, `AgentAcceptancePayload`, `AgentRequestAcceptance` and
  `AgentRequestAcceptancePayload` state that an acceptance names a non-empty requester. A
  signer refuses to sign bytes that name an empty requester, and a verifier refuses an
  acceptance whose canonical bytes name one, even when the signature over them verifies.
- `buf breaking` against v1.0.0 passes: adding validation rules is not a wire break. A
  peer that sent an empty `Requester.id` is now refused by a validating receiver.
- The validation corpus gains `Requester/id/too_short` and `Requester/id/too_long`, and
  its `Requester` baseline now carries an `id`.

SDKs, in all three languages: the acceptance canonicalizers and signers refuse an empty
requester id or domain, for the offer acceptance and the request acceptance alike, and
the verifiers refuse such an acceptance. Go returns `helpers.ErrAcceptanceRequesterEmpty`
(new, match it with `errors.Is`) from `CanonicalAcceptanceBytes`, `SignOfferAcceptance`,
`SignOfferAcceptanceWith`, `VerifyOfferAcceptance`, `RequestAcceptancePayload`,
`CanonicalRequestAcceptanceBytes`, the request-acceptance signers and
`VerifyRequestAcceptance`. Python raises `ValueError` from the `*_jcs` canonicalizers and
signers and from `verify_offer_acceptance_jcs`, and `verify_request_acceptance_jcs`
returns `False`. TypeScript throws from `acceptancePayload`, `requestAcceptancePayload`
and the signers, and the verifiers return `false`. The purchase verbs of every client
(direct and through a Broker) refuse a configured requester with an empty `id` or
`domain` locally, as a malformed call, before signing or sending anything. The shared
acceptance vectors move their empty-requester cases into a new `refused` list, which
records the bytes and raw signature a signer without the check would produce, so each
language proves it refuses them even though that signature verifies.

Docs: the authentication page's Requester table and a new "Requester domain and the key
directory" section, the projected-execute section, the transaction-flow page, the
reference page and the Exchange request-flow example state the same rules.

**A scope shortfall is never disclosed: `OFFER_ABSENCE_REASON_SCOPE_INSUFFICIENT` and
`DENIAL_REASON_SCOPE_INSUFFICIENT` are deprecated and never sent (no wire change).**
Their comments described an Exchange sending them, which contradicted `Requester.scopes`:
a requester never learns about a resource outside its scopes. `Requester.scopes` now
states the existence-hiding rule once, and the related comments point at it.

- At discovery, when the requester's scopes leave no presentable offer for a resource,
  the Exchange answers with no offers and no absence reason, exactly as for any resource
  with nothing to offer. A Broker relaying that answer adds no reason of its own.
  `OfferGroup.absence_reason` is no longer described as present whenever `offers` is
  empty.
- At purchase, an offer the Exchange presented is honoured until it expires, so a scope
  refusal cannot arise.
- Both values are marked `[deprecated = true]`. Their numbers are retained, because
  removing them would break the v1 wire contract, and must not be reused. A receiver
  treats either value as unknown. The SDK readers still decode them, and the generated
  models still accept them.
- The guides no longer tell an Exchange to send either value, or an agent how to react
  to one: the authentication page's disclosure-policy section became "Existence hiding",
  and the Exchange-operator, enterprise, AI-agent, discovery-paths and threat-model pages
  and the reference page follow it. The doc-conformance check now fails if either value
  is named in the guides.

**Edge discovery headers: `X-Content-Rules` and `X-FORA-Exchange` (HTTP convention
specified; no message change).** When a publisher's edge refuses an unlicensed AI agent
with 403, it answers with two discovery headers, and they are now part of the protocol.
Neither was defined before. The documentation presented `X-Content-Rules` as a FORA
extension pointing at the Exchange, which was wrong: it points at the publisher's
manifest. The normative text is the new "Edge discovery headers" section of the
`fora.proto` file header.

- `X-Content-Rules` is the absolute URL of the publisher's manifest, exactly
  `https://{domain}/.well-known/fora.json` with the publisher's bare domain (a port
  allowed) and no userinfo, query, fragment, trailing slash or other path. An edge
  SHOULD send it on every 403 to a request for licensed content that carries no valid
  signed URL.
- `X-FORA-Exchange` is the bare domain of one Exchange that sells the content directly,
  in the same form as `Offer.exchange`. An edge MAY send it, only together with
  `X-Content-Rules`, and only for an Exchange its manifest lists. It is an optimisation
  over `X-Content-Rules`, not a replacement.
- An agent reads the headers only from a 403, and ignores a value of the wrong shape as
  if it were absent. With `X-FORA-Exchange` it MAY start discovery at the named
  Exchange without fetching the publisher's manifest first. It resolves that
  Exchange's endpoint from the Exchange's own `fora.json`, never from the header, under
  the request-recipient rule.
- An agent MUST NOT treat `X-FORA-Exchange` as authorization. Offers are verified by
  their signatures, and the publisher's manifest stays the authority on which Exchanges
  sell the content. When the header names an Exchange the manifest does not list, the
  manifest wins: the agent discards the header, does not transact on an offer from that
  Exchange, and discovers at the Exchanges the manifest lists.

SDKs, in all three languages: `parse_discovery_hint(status, headers)` (Python, from
`fora_sdk`), `parseDiscoveryHint(status, headers)` (TypeScript, export path
`./discovery-hint`) and `helpers.ParseDiscoveryHint(status, header)` (Go) read a
response's discovery headers into a `DiscoveryHint`: each value with a state of
`absent`, `valid` or `malformed`. Any status other than 403 reads as absent, and a header
sent twice is malformed. `reconcile_discovery_hint`, `reconcileDiscoveryHint` and
`helpers.ReconcileDiscoveryHint` check the hinted Exchange against the domains the
publisher manifest's `exchanges` lists, with the recipient identity match, and answer
`listed`, `unlisted` or `no_exchange`. The header names are exported as
`ContentRulesHeader` and `ExchangeHeader` in all three languages and join
`wire-constants-vectors.json`. New corpus: `discovery-hint-vectors.json`, replayed by all
three SDKs.

**Published JSON Schemas, with a strict variant (no wire change).** The SDK build
already generated a JSON Schema per message from `fora.proto` and discarded it after
generating the Pydantic and Zod models. Those schemas are now release artifacts under
`gen/jsonschema/`: one self-contained draft 2020-12 file per message of `fora.v1` and
`fora.admin.v1`, named by the fully-qualified message name, in two variants.
`fora.v1.ResourceResponse.schema.json` accepts unknown fields;
`fora.v1.ResourceResponse.schema.strict.json` sets `additionalProperties: false` on every
message object at every depth, so a conformance check fails on an unknown or misspelled
field.

- Shipped in all three packages: the Go module as the `gen/jsonschema/` directory, with
  `jsonschema.Load(name, strict)` and `jsonschema.FS` in package
  `github.com/FORA-Protocol/protocol/gen/jsonschema`; `fora-protocol` on PyPI as package
  data, read with `wire.schemas.load(name, strict=False)` and listed by
  `wire.schemas.names()`; `@fora-protocol/sdk` on npm under the export path
  `./jsonschema/*`.
- The schemas describe canonical proto-JSON. Field names are the snake_case proto names,
  and the lowerCamel aliases the generator emits are dropped, so a camelCase key is an
  unknown field. `google.protobuf.Struct` (every `ext`) stays open in the strict variant.
  A 64-bit integer accepts a decimal string or a JSON integer, with its bound applied to
  both forms; other numbers are JSON numbers only, so a string cannot carry a value past
  a numeric bound.
- They carry the per-field `buf.validate` constraints, and mark `required` every field
  whose zero value its own rule rejects. Cross-field rules and oneof exclusivity are not
  expressible per field and are not in the schemas.
- The drift gate regenerates and compares them like the generated code. A Go conformance
  test checks them against the descriptors, and both variants must match Go
  protovalidate on every case of the conformance corpus, in Python and in TypeScript.

**The Broker buys: `BrokerService.ExecuteTransaction` (additive wire change).**
A purchase of offers from several Exchanges is now one call to the Broker. Before
this change `BrokerService` had only `Resolve`, and the contract described the
agent buying at each Exchange directly, with a Broker on the path forwarding the
request byte-for-byte under a stack of hop signatures. Implementations relayed
purchases through the Broker anyway, by re-packaging them outside the contract.
The contract now defines that relay.

- `rpc ExecuteTransaction(TransactionRequest) returns (BrokerTransactionResponse)`
  on `BrokerService`. The agent sends the same `TransactionRequest` it would send
  an Exchange: every item with its `AgentAcceptance`, and one
  `AgentRequestAcceptance` over all items. The Broker verifies the agent's request,
  groups the items by each signed offer's `exchange`, and sends one
  `ExchangeService.ExecuteTransaction` per Exchange, signed with its own key. The
  acceptances travel in each sub-request body, so every Exchange still verifies
  the agent's consent. The Broker forwards the agent's `idempotency_key` unchanged
  to every Exchange.
- New messages: `BrokerTransactionResponse` (`items` in request order,
  `exchanges`, per-currency `totals`), `ExchangeOutcome` (one per Exchange
  contacted: `exchange`, `offer_ids`, `agent_identity_hash`, `subscription_quota`)
  and `UpstreamRefusal` (`party`, the refusing party's bare host; the Connect
  `code`; the party's `ErrorDetail`). It is the one shape for "a peer refused": the
  Identity Service's MCP tool errors carry it too.
- `TransactionResultItem.refusal = 14`. An Exchange's refusal of a whole
  sub-request is never turned into a Broker error: it rides on each affected item,
  and the other Exchanges' results come back unchanged.
- `DenialReason.DENIAL_REASON_RELAY_NOT_ACCEPTED = 19`: the provider at this
  Exchange does not accept purchases relayed by a Broker. Buy the offer directly.
- The Broker's own refusals are non-OK errors: `unauthenticated` with
  `request_auth_failure` for an invalid agent signature, and `SIGNATURE_INVALID`
  when `requester.domain` is not the agent's verified signing directory;
  `invalid_argument` for a malformed request; `failed_precondition` for an
  Exchange it cannot route to or does not approve.
- `DENIAL_REASON_CONTENT_UNAVAILABLE` is documented as not a catch-all for
  upstream failures.
- Re-packaging is safe because each item is atomic and its integrity is per
  resource: each offer carries its Exchange's signature, each acceptance binds the
  agent to that one offer, and each result comes from the Exchange that owns the
  resource. In a result item the one signed value is `retrieval_endpoint`; the
  combined response is otherwise the Broker's unsigned report.
- Updated rules: a purchase through a Broker is always re-packaged, and the Broker
  signs each sub-request alone (see the Web Bot Auth profile entry below). On a
  re-packaged purchase the delegation holder binding (`cnf.jkt`)
  and `agent_identity_hash` use the key the item's `AgentAcceptance` verifies
  under, not the request signer, which is the Broker. An Exchange scopes a relayed
  request's idempotency key per Broker, authenticated requester and key.

SDKs, in all three languages:

- `BrokerClient.Execute` (Go), `BrokerClient.execute` (Python, async and sync) and
  `BrokerClient.execute` (TypeScript) buy verified offers through a Broker in one
  call and return the `BrokerTransactionResponse`. The client builds each item's
  acceptance and the request acceptance from its signer, stamps `ver` and the
  requester, and refuses locally, as malformed, a `requester.domain` that is not the
  host of the directory it signs as (Signature-Agent).
- The exchange client buys several offers from one Exchange in one request:
  `Client.ExecuteBatch` in Go, and `execute` given a sequence (Python) or an array
  (TypeScript). Offers from more than one Exchange are refused locally.
- The client-request corpus gains the `brokerExecute` verb.

**SDK capabilities for conformance and e2e harnesses, in all three languages (no wire
change).** A harness can now drive FORA services through the SDK, build a malformed
request only where it means to, and check every answer through the SDK's own decoder.

- **Pre-signing hook.** A function that receives each RPC request just before it is
  signed; the request it returns is signed and sent, and the answer decoded as usual.
  `ClientConfig.before_sign` (Python, an `httpx.Request`), `beforeSign` in
  `ClientOptions` (TypeScript, a Fetch API `Request`), `connect.WithBeforeSign`
  (Go, an `*http.Request`). A hook that changes the method or URL, sets a header the
  signer writes, or fails is refused locally as malformed, and nothing is sent.
- **Raw mode.** A per-call body sent exactly as given: no `ver`, `idempotency_key` or
  `requester` is filled in and nothing about the message is refused locally, while the
  body is still signed and the answer still decoded. `RawBody(body)` in place of a
  verb's request in Python and TypeScript, `connect.WithRawBody(body)` in Go (binary
  protobuf; every Go verb now takes call options). A verb that routes by the message
  still reads its destination from the body's `exchange`.
- **Strict response decoding.** `ClientConfig(strict=True)` (Python), `strict: true`
  (TypeScript) and `connect.WithStrictDecoding()` (Go) refuse an answer carrying an
  unknown field at any depth, or breaking a field-level or cross-field rule. Python and
  TypeScript check the published strict JSON Schema of the response message and the
  SDK's cross-field rules, reading a `null` member as absent; Go checks the descriptor's
  unknown fields and runs protovalidate. An error answer is checked too. The Connect
  error envelope may carry only `code`, `message` and `details`, must name one of the
  sixteen Connect codes, and its details must be well formed: each entry carries only
  `type`, `value` and `debug`, a non-empty `type`, a base64 `value` and at least one of
  the two. Every `ErrorDetail` in it is checked against the strict `ErrorDetail` schema
  and its rules, both the decoded binary `value` (an unknown field in the binary
  encoding included) and the `debug` projection. A refused envelope is malformed, keeps
  the Connect code on `code`/`Code` and carries no detail; an empty or non-JSON error
  body is a gateway's answer and is still classified by its status. Without strict
  decoding an error answer is read as before. `connect-error-vectors.json` gains a
  `strict_malformed` column on every row and three rows for it: an envelope with an
  unknown top-level member, a `debug` projection with an unknown field, and a
  `registration_failure` whose `field_errors` break the RegistrationFailure message
  rule. All three SDKs replay every row strict and non-strict.
- **Error decoding.** The JSON SDKs read a Connect error's `ErrorDetail` from the binary
  `details[].value`, with a table-driven decoder and no protobuf dependency, and fall
  back to the `debug` projection only when `value` is absent. A value that does not
  decode is not replaced by its `debug`. The Connect code of a peer's answer has its own
  field: `CallError.code` (Python), `ForaCallError.code` (TypeScript), `CallError.Code`
  (Go). `connect-error-vectors.json` now pins the code and the whole detail, including
  rows carrying only `value`, and the new `error-detail-wire-vectors.json` pins the
  binary decoding of every field of the ErrorDetail subtree against the descriptor.
- **Delivery URLs pass through unchanged.** Execute, the Broker purchase and fetch hand
  back each retrieval URL as the Exchange issued it, and fetch presents the agent's proof
  of possession. The delivery edge verifies the URL signature and, where it can, the agent
  binding against that proof; an edge that cannot check the binding (CloudFront with its
  pre-arranged RSA key pair) checks its own signature and treats the URL as a bearer
  token. New tests in all three SDKs pin the pass-through.
- **Admin client.** `AdminClient` covers `fora.admin.v1.AdminService`
  (`SetTenantFeeRate`, `SetReportingPolicy`) and the two domain-verification RPCs,
  `RequestDomainVerification` and `ConfirmDomainVerification`: `AdminClient` in Python
  (async and sync), `createAdminClient` in TypeScript, `connect.NewAdminClient` in Go.
  Python has no separate factory: as for every other client, the Go factory folds into
  the `AdminClient` constructor. The SDK parity matrix records it with that reason, as
  its 17th documented divergence (16 at v1.0.8).
- **Identity helpers.** Mint a fresh agent: a key and its thumbprint, the Web Bot Auth
  directory document for a key set, and a signer that signs as it.
  `generate_key`, `directory_document`, `signing_transport_for` (Python, in
  `fora_sdk.identity`); `generateKey`, `directoryDocument`, `signingTransportFor`
  (TypeScript, export path `./identity`); `helpers.GenerateKey`,
  `helpers.DirectoryDocument`, `core.SigningTransportFor` (Go).
- **Document readers.** Read and check the documents a party publishes over HTTPS:
  `read_manifest`, `read_wba_directory`, `read_revocation_list` and
  `read_license_document` (Python, `fora_sdk.resolvers`); `readManifest`,
  `readWBADirectory`, `readRevocationList` and `readLicenseDocument` (TypeScript,
  `./resolvers`); `resolvers.ReadManifest`, `ReadWBADirectory`, `ReadRevocationList` and
  `ReadLicenseDocument` (Go). Each fetches through the SDK's guarded client, with the
  SSRF and https-only scheme guards, and returns the parsed generated message with the
  URL, the bytes and the media type (`Document`), or fails with a typed error; none
  returns nothing. The manifest must be served as `application/json` and the WBA
  directory as `application/http-message-signatures-directory+json`
  (`MediaTypeRefusedError`, `MediaTypeRefused`, `ErrMediaTypeRefused`), fetched with no
  redirect and signed by every key it lists (see the Web Bot Auth profile entry below). The manifest's `ver` is read first. Every document must pass
  the strict check below. The license reader checks the `License`, fetches its `uri` and
  verifies the bytes against `uri_digest` (`LicenseDocument`, or `DigestMismatchError`,
  `DigestMismatch`, `ErrDigestMismatch`). A failed fetch, a non-200 answer, a body that
  is not JSON and a body over 1 MiB are an unavailable document; a body over the cap is
  now refused rather than truncated, in the resolvers as well. Go's
  `ErrDirectoryUnavailable` reads `resolvers: document unavailable`, and a manifest
  fetch failure in the Go endpoint resolver and requirements reader now wraps it. The
  endpoint resolver, the registration-requirements reader, the WBA key resolver and the
  offer-directory fetch read the same documents through the same fetch and decode,
  without the strict check; the WBA key resolver and the offer-directory fetch still
  check a directory's media type and response signatures. The Python and TypeScript readers return the
  generated model, which names an enum by its value name, so they refuse a document that
  writes an enum as its number; the Go reader accepts it. New corpora:
  `document-check-vectors.json`, the verdict for a document's bytes and Content-Type, and
  `license-digest-vectors.json`, both replayed by all three SDKs.
- **Public strict check.** `check_strict(message_name, payload)` (Python, from
  `fora_sdk` and `fora_sdk.client`, raising `StrictViolationError`), `checkStrict(message,
  payload, schema?)` (TypeScript, `./client`, throwing `StrictViolation`) and
  `helpers.CheckStrict(name, payload)` (Go, wrapping `helpers.ErrStrictViolation`). The
  client's strict decoding of a success answer and of an error envelope, and the document
  readers, call this one check in each language. Python and TypeScript check the
  published strict JSON Schema and the cross-field rules; TypeScript takes the strict
  schema of a message it does not bundle as the third argument. Go decodes the proto-JSON,
  refuses unknown fields, a lowerCamelCase member and a 32-bit number or bool written as
  a string, and runs protovalidate; `helpers.CheckStrictMessage` is the same check on a
  decoded message, which the Go client applies to binary answers. The Python client's
  `proof_headers` stays internal: a harness signs a delivery fetch with the public
  `sign_agent_binding`, as Go does with `helpers.SignAgentBinding` and TypeScript with
  `signInbound`.
- **Typed request inputs.** Python verbs accept the generated request models as well as
  dicts, and `to_wire(model)` renders a model as the JSON object the SDK sends.
  TypeScript exports the request input types its verbs are typed with. Go verbs already
  take the generated messages.

**A request-signature refusal carries a typed reason (additive wire change).**
An RPC request whose RFC 9421 HTTP message signature failed verification was
refused as Connect `unauthenticated` with only a message, such as
`helpers: missing Signature-Input header`. The contract tells clients to branch on
a typed reason and never on the message, and `ErrorDetail` had no reason for this
failure. It now has one: a new `reason` oneof member,
`RequestAuthFailure request_auth_failure = 17`, whose `RequestAuthFailureReason` is
one of three values:

- `SIGNATURE_MISSING`: no signature, or none that parses. Sign the request.
- `SIGNATURE_INVALID`: the signature does not verify, for example a bad
  signature, a key that cannot be resolved, a content-digest mismatch or a
  required covered component that is missing.
- `SIGNATURE_STALE`: the signature is outside its `created`/`expires` window, or
  was already used. Sign the request again, now.

The values are deliberately coarse: each names what the caller does next, never
which validation step failed, so a refusal tells a forger nothing about how far
its request got.

The Go server binding attaches the detail. `connectserver.WriteReject`, which the
verify seam of `NewExchangeServiceHandler`, `NewBrokerServiceHandler` and
`NewCatalogServiceHandler` answers with, now adds one `fora.v1.ErrorDetail` to the
`details` of every `unauthenticated` refusal. The reason comes from the
verification error: a missing or malformed `Signature-Input` or `Signature` is
`SIGNATURE_MISSING`; an expired signature, one created in the future, or a replay
(`connectserver.ErrReplayed`) is `SIGNATURE_STALE`; every other error, including
one the mapping does not know, is `SIGNATURE_INVALID`. The detail's `domain` is
empty, because the writer is not given the request and cannot name the service.
The envelope's `code` and `message` are unchanged, and a `resource_exhausted`
refusal still carries no detail.

The detail builders gain `helpers.RequestAuthFailureDetail` (Go),
`request_auth_failure_detail` (Python) and `requestAuthFailureDetail`
(TypeScript), and the readers (`helpers.Reason`, `reason`) return the new enum.
The Python and TypeScript SDKs have no RPC refusal writer, so they read this
detail but do not emit it.
**Request signatures and key directories follow the Web Bot Auth profile (SDK and wire
change; a hard cut).** The Authentication page said FORA was "automatically compatible"
with Web Bot Auth and that "no changes to FORA's authentication are required". That was
not true: a Web Bot Auth verifier refused a FORA signature, and a FORA verifier refused a
signature from a Web Bot Auth library. The pages also disagreed with each other:
Transaction Flow and the Exchange request flows said each hop covers `@method`,
`@authority`, `@path` and `Content-Digest`, while Authentication required `@method`,
`@target-uri`, `content-digest`, `authorization` and `signature-agent`.

The target is draft-ietf-webbotauth-httpsig-protocol-00 (1 September 2026), the only
document the IETF webbotauth working group has adopted. Authentication specifies the
profile in one place, the other pages and the proto comments refer to it, and the three
SDKs implement it:

- Every FORA request signature is a conformant Web Bot Auth signature.
  `Signature-Agent` is a structured-field dictionary with one member per signature,
  `<label>="https://<origin>"`, covered as `"signature-agent";key="<label>"`. The
  signature covers `@target-uri` or `@authority`, and carries `created`, `expires`,
  `keyid` (the RFC 7638 thumbprint), `alg="ed25519"`, `tag="web-bot-auth"` and a fresh
  64-byte `nonce`. Its lifetime is at most five minutes.
- A FORA RPC signature also covers `@method`, `@target-uri`, `content-digest` and
  `authorization`. This is FORA policy on top of Web Bot Auth, advertised through
  `Accept-Signature`. A bodiless request at the publisher edge needs only the Web Bot
  Auth base.
- Signers use a `Signature-Agent` member key equal to the signature label. Verifiers
  also accept a member key that differs from the label, a signature without a nonce, and
  a member with `type=directory`. The legacy sf-string `Signature-Agent` is accepted on a
  request carrying one signature only. Verifiers refuse a signature with no `tag`, a
  `Signature-Agent` member that is not an https origin, and the bare unquoted value the
  v1.0.8 SDKs sent, and answer a missing component, a refused form or a member that is
  not an https origin with `Accept-Signature` listing what they require. `Signature-Agent` is never empty; an
  empty `Authorization` stays valid.
- Several signatures: each is verified on its own, against the key its `keyid` names in
  the directory its own covered member names; a signature that covers several members
  (because it covers an earlier signature) follows the one keyed to its label. Covering
  an earlier signature is optional (WG-00 §5.2.2), and a signature that covers
  `"signature";key=X` must also cover `"signature-input";key=X` and every component X
  lists, and X must appear before it. Labels carry no meaning; the `sig1` to `sigN`
  requirement is gone. The hop caps count every signature. FORA's Broker never forwards
  an agent's request unchanged, so it never covers an agent's signature: discovery
  through the Broker is Broker-led, the Broker choosing the Exchanges and originating its
  own queries, and execute is re-packaged per Exchange; in both cases the Broker signs
  alone, covering its own request and only its own member. How an agent proves a
  holder-of-key entitlement at discovery time through a Broker is an open protocol
  question, tracked separately. On a relayed purchase the agent's identity and consent
  come from `AgentAcceptance`, verified against the agent's registered key resolved from
  `Requester.domain`. That key gives the delivery-URL binding, and a delegation's
  `cnf.jkt` is checked against it; a Broker is never delegated to. The Exchange resolves
  each signer's key in the directory that signer names, not in a configured key set.
- The retrieval proof of possession at the publisher edge is a full Web Bot Auth
  signature plus `@method` and `@target-uri`. That covered set is a minimum: a proof that
  also covers `@authority`, or a header, verifies. The edge keeps verifying offline with the
  key in `X-FORA-Agent-Key`, which it accepts only when its thumbprint equals both the
  signature `keyid` and the delivery URL's `agent_id`. A generic WBA verifier accepts
  the same signature by resolving the agent's directory.
- Key directories are served over https at
  `/.well-known/http-message-signatures-directory`, answer `200` without a redirect, use
  the media type `application/http-message-signatures-directory+json`, and carry a
  response signature per listed key with `tag="http-message-signatures-directory"`,
  covering `"@authority";req` and `content-digest`. A revocation list and the `fora.json`
  manifest may still follow up to five redirects. Each key's JWK `alg` stays `EdDSA`, the
  JOSE name RFC 7517 §4.4 defines. This is a known, deliberate deviation from WG-00
  §5.5.1, which restricts that member to HTTP Message Signatures names (`ed25519`); FORA
  follows RFC 7517 and Cloudflare's reference library. It is the only deviation from
  WG-00.

Authentication includes a complete signed request, a query a Broker originated and
signed alone, and a signed directory response, all with real values the SDKs reproduce
byte for byte.

SDKs, in all three languages:

- Signing: `helpers.SignRequest` / `sign_request` / `signRequest` and
  `helpers.AppendSignature` / `append_signature` / `appendSignature` take the signer's
  directory origin and emit the dictionary member, the tag and the profile's parameter
  order (created, expires, keyid, alg, nonce, tag). They refuse a missing or non-origin
  directory (`helpers.CheckHTTPSOrigin` / `check_https_origin` / `checkHttpsOrigin`), a
  window over five minutes (`MaxSignatureLifetime` / `MAX_SIGNATURE_LIFETIME`), an
  unusable label, and appending to a legacy `Signature-Agent`. An appended signature
  covers only its own request and member unless asked to cover the previous one
  (`SignOptions.CoverPrevious`, `cover_previous`, `coverPrevious`). Go's `SignOptions`
  gains `SignatureAgent`, `Label` and `CoverPrevious`.
- Verifying: the verifiers apply the rules above, resolve each signature's key with the
  directory its member names, and carry that directory on the result. A refusal for a
  missing component, a refused form or a member that is not an https origin carries the
  `Accept-Signature` value
  (`helpers.AcceptSignature` / `accept_signature` / `acceptSignature`): Go's
  `connectserver` writes it on the 401, and the Python and TypeScript server verdicts carry
  it. The key resolver receives the directory of the signature it resolves: Go threads it
  through `helpers.SignatureAgentFromContext`, while Python's `KeyResolver.resolve` and
  TypeScript's `RequestKeyResolver.resolve` take it as a second argument (a breaking change
  for a custom resolver). `helpers.ErrBrokenSignatureChain` now means an incomplete or
  dangling coverage of an earlier signature. `helpers.BrokerKeyIDPrefix` is deprecated.
  The TypeScript helpers that served the old chain (`COVERED_COMPONENTS`,
  `buildRequestSignatureBase`, `maxSigLabelN`, `signatureBytesByLabel`,
  `parseMultisigSignatureInput` and the regex-based proof parsers) are removed.
- Signing transports: 64-byte nonces; a directory is required (`WithSignatureAgent`,
  `signature_agent`, `signatureAgent`), and a client without one refuses a signed call
  locally as malformed. A per-request signer source (`core.WithSignerSource` /
  `SignerSource`) signs each request as the identity a callback picks. Append mode
  (`core.WithAppendSigner`, `appendOnly`) is joined by Python's `append_only`, which
  Python lacked. `core.MonotonicWindow` / `monotonic_window` / `monotonicWindow` used to
  move `created` forward by one second per request, stamping signatures in the future
  above one request per second; it now signs at the clock's current time, exactly as the
  clock window, and is deprecated.
- Delivery proof: `helpers.SignAgentBinding` / `sign_agent_binding` / `signInbound`
  take the agent's directory, a nonce and the HTTP method, and emit the
  `Signature-Agent` header. Python's `sign_agent_binding` now returns an `AgentBinding`
  with the four header values instead of a tuple. Go gains the verify face,
  `helpers.VerifyAgentBinding`, which refuses with a `PoPError` (`PoPFailure` token and
  `PoPAcceptSignature`). The three verifiers accept a proof covering at least the
  profile's components, parse it with a structured-field parser, and refuse with the same
  tokens; a refusal the fetcher can fix carries `PoPAcceptSignature` /
  `POP_ACCEPT_SIGNATURE`, and the Hono middleware answers it with 401 and that header.
- Directories: `helpers.SignDirectoryResponse` / `sign_directory_response` /
  `signDirectoryResponse` sign a directory response and
  `helpers.VerifyDirectoryResponse` / `verify_directory_response` /
  `verifyDirectoryResponse` check one. The WBA key resolvers and the offer-directory
  fetch refuse redirects, check the media type and hand out only keys that signed the
  response; `ReadWBADirectory` / `read_wba_directory` / `readWBADirectory` require every
  listed key to have signed, and refuse `application/jwk-set+json`. The key resolver's
  scheme option, which let a configuration fetch an https origin's directory in
  plaintext, is removed from all three SDKs (Go `WBAKeyResolverOptions.Scheme`, Python
  `WBAKeyResolver(scheme=...)`, TypeScript `WBAKeyResolverOptions.scheme`): a directory
  is always fetched over https. The
  constants `WBATag`, `DirectoryResponseTag` and `AcceptSignatureHeader` join the wire
  constants.
- TypeScript on edge runtimes: the SDK typechecks under `@cloudflare/workers-types`, and
  `npm test` runs that check. `@fora-protocol/sdk/resolvers/edge` is a new entry for an
  edge runtime: the resolvers with an injected `fetch` and no Node import. The existing
  `@fora-protocol/sdk/resolvers` entry keeps its guarded Node default. A guard test fails
  on any `undici` or `node:` import, and any Node global, reachable from the edge entry,
  `src/`, `core/` or `hono/`. `verifyDirectoryResponse`, `readWBADirectory`,
  `createWBAKeyResolver` and `createWBAOfferDirectoryFetch` take the injectable
  `verifyEd25519` primitive `verifyAgentBinding` already took, so a runtime without
  WebCrypto Ed25519, such as Fastly Compute, no longer reads every directory key as
  unsigned.
- TypeScript strict check: the strict schemas of the messages the SDK checks by name are
  compiled at build time with ajv's standalone output, into the generated, drift-gated
  `gen/ts/strict/`, so the strict readers and the client's strict decoding generate no code
  at run time. On Cloudflare Workers, which refuses code built from strings, every strict
  reader used to fail with an `EvalError`. A schema passed to `checkStrict` as its third
  argument is still compiled at run time. A test runs the edge readers where code
  generation from strings is refused.
- TypeScript bundle size: the packages are marked `"sideEffects": false` and each generated
  Zod schema is built in a call marked pure (`gen/ts/wire/schemas.ts` is regenerated), so a
  bundler keeps only what a program imports. Importing one constant from the edge entry
  carried about 0.9 MB and now carries a few bytes; a strict reader carries its own
  message's validator and Zod schema. A guard test bundles the edge entry and checks it.
- Shared vectors, regenerated by the Go oracle and replayed by all three SDKs:
  `sign-request-vectors.json`, `verify-request-neg-vectors.json` (now with the expected
  `Accept-Signature`), the new `verify-request-accept-vectors.json` (the forms a verifier
  must accept), `multisig-chain-vectors.json` (each signer with its own directory, so a
  verifier that resolves through the wrong member fails), `pop-vectors.json` (now with
  each vector's expected refusal token and `Accept-Signature`, and superset proofs),
  `wire-constants-vectors.json`, `document-check-vectors.json` and the new
  `directory-response-vectors.json`. The Go suite also checks the draft's Appendix E.2
  Ed25519 vectors against its signature base builder.

The change is a hard cut with no transition window: verifiers refuse the bare unquoted
`Signature-Agent` that v1.0.8 sends and a directory served as `application/jwk-set+json`
or unsigned, so v1.0.8 clients and directories must upgrade. The reference
implementation's directories are still served as `application/jwk-set+json` and unsigned,
and change when it adopts this release.

## v1.0.8

**Request signatures carry an RFC 9421 `nonce` (SDK fix; no wire change for
verifiers).** Ed25519 signatures are deterministic, and `created` and `expires`
are whole seconds. Two identical requests signed in the same second therefore got
the same signature, and a verifier with a replay store refused the second one as
a replay (`connectserver: request replayed within window`). For example, two
`GetAccountStatus` calls in one second failed this way.

The signing transports now add a fresh `nonce` to every signature: Go
`core.NewSigningTransport`, Python `SigningTransport.sign_outbound` and TypeScript
`signOutbound` / `createSigningTransport`. The nonce is 16 random bytes from the
platform's cryptographic RNG, encoded as base64url. If random generation fails,
nothing is signed or sent. A transport never signs without a nonce: a TypeScript `nonce` option that
returns an empty string is refused.
Resending the same signed bytes is still a replay and is still refused.

The signing helpers take an optional nonce: `helpers.SignOptions.Nonce` (Go), the
`nonce` keyword of `sign_request` / `append_signature` (Python), and
`SignRequestOptions.nonce` (TypeScript). Without it they produce the same bytes as
before, and they still read no clock and no RNG, so a caller that uses them
directly and needs unique signatures must pass its own nonce. A non-empty nonce
must use only base64url characters (`A-Z a-z 0-9 - _`). Otherwise signing fails:
Go returns `helpers.ErrInvalidNonce`, Python raises `ValueError` and TypeScript
throws. Without this check, a quote in the nonce ended the quoted parameter early,
and the three SDKs wrote different bytes.

Verifiers need no change. The v1.0.7 verifiers in all three SDKs already accept a
signature with a nonce, and a signature without one is still accepted. The window
APIs (`MonotonicWindow`, `monotonic_window`, `monotonicWindow`) are unchanged but
are no longer needed for uniqueness. The shared test vectors gain nonce cases:
`post_with_nonce`, `post_empty_authorization_bound_with_nonce`,
`append_relay_leg_with_nonce` and `positive_two_hop_nonce`.

## v1.0.7

**The Go music type accepts a whole-number `music.bpm` written as `90.0`
(SDK fix; no wire change).** `music.Music` refused `{"music.bpm": 90.0}` and
`{"music.bpm": 1e2}`, because its `BPM` field is an `*int` and `encoding/json`
accepts only integer literals for an int. The profile's JSON Schema accepts both
values: JSON Schema counts a number with no fractional part as an integer. The
value also appears in practice. `Offer.ext` is a `google.protobuf.Struct`, which
stores every number as a double, and some encoders, for example Python's
`json_format`, write 90 as `90.0`. A schema-valid offer therefore failed to decode.

`Music` now has an `UnmarshalJSON` method. It decodes every field as before, and
it reads `music.bpm` as a number: a whole number becomes the `int`, and a
fractional value such as `90.5`, a string or a value outside the `int` range is
still an error. `BPM` stays `*int`, so the Go API does not change. The shared
round-trip cases gain `90.0` and `1e2`. The TypeScript and Python types do not
decode, so they need no change. The Python docstring now says that `music.bpm`
can be a whole-number `float` after `json.loads`.

## v1.0.6

**Typed view of the fora-music-v1 extension profile (SDK addition; no wire
change).** The Go, TypeScript and Python SDKs gain a type for the flat
`music.<field>` keys of `Offer.ext` that the fora-music-v1 profile defines, for
example `music.genre`:

- Go: `github.com/FORA-Protocol/protocol/sdk/go/profiles/music` (`music.Music`,
  `music.ProfileID`)
- TypeScript: `@fora-protocol/sdk/music` (`Music`, `ProfileID`)
- Python: `fora_sdk.music` (`Music`, `PROFILE_ID`)

The types keep the profile's presence rules: an absent key stays absent (an
absent `music.vocals` is never `false`), and an empty list stays `[]`. They do not
validate values; the profile's JSON Schema, `music-v1.schema.json`, does. The
proto is unchanged: `Offer.ext` is still a `google.protobuf.Struct`, and the type
is a view over it. The three SDKs share one set of round-trip cases, and the
API-surface parity gate now covers the new Go package.

The website gains the [fora-music-v1 page](https://fora-protocol.org/protocol/ext-music/): the ten fields,
the label rules, who validates what, and the nine `music.*` search filter keys
with their matching rules and error codes.

**`GetAccountStatusResponse` reports the account's balance (additive field; no
behaviour change for Exchanges that leave it empty).** An agent could ask an
Exchange whether its account exists and is active, but not how much it can spend.
The only way to learn that the balance was too low was a refused execute with
`DENIAL_REASON_INSUFFICIENT_BALANCE`. The new field `repeated Cost balances = 5`
closes that gap.

Each entry is the amount the account can spend now in one currency, with holds for
pending transactions already subtracted. The amount is an exact decimal string and
is never negative. The value is a snapshot: it does not guarantee that the next
execute passes the balance check.

An empty list means the Exchange does not report balances. It does not mean a zero
balance. A currency missing from a non-empty list is also not reported, not zero.
An Exchange that reports a zero balance sends the entry with amount `"0"`.

`Cost` is shared with offers and budgets, where an empty amount and a free-form
currency stay valid, so `Cost` itself is unchanged. Four message-level rules on
`GetAccountStatusResponse` state what a balance entry needs:

- `get_account_status_response.balances_requires_billing_ref`: balances are only
  allowed when `billing_ref` is set, the same as `terms_digest`.
- `get_account_status_response.balances_entry_complete`: every entry has a
  non-empty amount and a three-letter upper-case ISO 4217 currency.
- `get_account_status_response.balances_no_unit_cost`: no entry sets `unit_cost`.
  An empty string counts as set.
- `get_account_status_response.balances_currency_unique`: at most one entry per
  currency.

The cross-field corpus gains one case per rule, plus separate cases for an
invalid currency and an empty `unit_cost`. The TypeScript and Python SDKs apply
the same four rules. Field number 5 was unused, and `buf breaking` against the
v1.0.0 tag is clean.

## v1.0.5

**An offer sells exactly one licensing term (documentation correction; no wire
change; behaviour-affecting for Exchanges).** `Offer.pricing` has said since the
licensing core landed that "each projected LicenseTerm yields its own offer" and
that a multi-term resource "produces multiple separate offers, one per term —
never one offer with a 'headline' picked among them." `Offer.terms` said the
opposite two hundred lines later: "Multiple terms when the resource has different
arrangements by use case." Both sentences shipped in v1.0.0. The second is now
corrected to state what the first always required, and to say why the cardinality
is load-bearing rather than stylistic.

`pricing` is the field a Broker ranks on and the field execute charges. A term
that does not sit on its own offer therefore has no price a Broker can compare
and no `offer_id` an agent can name, so fusing several terms onto one offer makes
every term after the first unsellable — a dual-licensed resource sells only under
whichever arrangement the publisher happened to store first. That is the whole
reason the rule exists, and it was not written down anywhere the contradiction
could be caught.

The bound is now ENFORCED rather than asked for: `Offer.terms` carries
`repeated.min_items = 1` and `repeated.max_items = 1` — exactly one, not at most
one. An offer with no term would be an offer projected from nothing, so the floor
is one; a fused offer fails validation at the boundary instead of travelling as a
documented-but-unchecked violation. A rule stated only in prose is a rule nothing
keeps, and this one went three months contradicting its own neighbour precisely
because no gate watched it. The validation corpus gains an `Offer/terms/too_many`
case, replayed by the Go, Python and TypeScript suites, so the ceiling is
cross-language verified; the floor announced itself immediately by rejecting the
corpus generator's own baseline Offer, which carried no term.

No field is added, removed, renamed, renumbered or retyped, and `buf breaking`
against the v1.0.0 tag is clean: `terms` is still field 19, still `repeated`,
still `LicenseTerm`. It stays `repeated` because renumbering a released field is
not available within v1, so the cardinality rides as a validation rule instead.
N terms on a resource project to N offers on that resource, each selling one of
them. `ResourceEntry.terms` remains genuinely plural,
bounded at 32 as before: a resource carries many terms, an offer sells one of
them, and nothing about ingestion changes.

An Exchange that emits a fused offer will now fail validation where its consumers
mount it, which is the intended effect: the tightening is what surfaces the
non-conformance rather than leaving it to be read about.

Implementations that emit one fused offer per resource are non-conforming and
must project one signed offer per entitled term, each carrying that term's
`pricing`, in stored order. Where a term is reachable only under an existing
subscription its offer carries `subscription_id` at zero marginal cost; which
terms a requester may see at all is decided by `LicenseTerm.scopes`.

## v1.0.0 — Initial release

First public release of the FORA Protocol (Federated Open Resource Access):
the wire format (protobuf under `proto/`), the generated Go and TypeScript SDKs
(under `gen/`), and the specification site (under `website/`). FORA extends IAB
Tech Lab CoMP V1 and RSL 1.0 with resource discovery, transaction execution,
post-usage reporting, dispute resolution, and provider domain verification —
enough for an autonomous agent to negotiate licensed access to a publisher's
resources through an Exchange and produce a cryptographically auditable record of
the transaction.

Highlights: a single `ExchangeService` (`DiscoverResources`,
`ExecuteTransaction`, `ReportUsage`, `DisputeTransaction`, and domain
verification) with Brokers and agents as interchangeable clients; unit-agnostic
metering; Ed25519 at every trust boundary, with RFC 9421 HTTP Message Signatures
for request and hop authentication and JWS (RFC 7515) for offer and attestation
signatures; a unified `/.well-known/fora.json` (`WellKnownManifest`) served by
every role with inline RFC 7517 JWKs and explicit key-validity bounds;
cryptographic content attestations with a structured dispute chain; multi-hop
intermediary chains with agent- and exchange-published depth caps; and extension
profiles for domain-specific behavior (news, academic, legal, C2PA, CoMP, pharma,
medical imaging).

### Revisions to the pre-release draft

The v1.0.0 tag was created after the draft below had been revised several times.
These entries, newest first, record those revisions. A compatibility note inside
an entry compares against the earlier draft, not against an earlier public release.

**The SDK serves the account-setup role, in all three languages (no wire change;
conformance-affecting).** `Register` and `GetAccountStatus` land on the agent client —
`connect.Client` in Go, `createClient`'s face in TypeScript, `Client` and its blocking
twin in Python — under the same names, over the same signing transport, redirect
refusal, request-id and validate interceptors and read cap as the other agent verbs.
They sit on that client rather than on a fourth constructor because they are the same
party holding the same key, and they route as a usage report does: the destination is
read off the request's own `exchange`, resolved from that Exchange's own manifest, and
dialled on the guarded leg. An account is per-Exchange and which Exchange is the agent's
choice per call — a denial names where to register — so a configured origin would confine
registration to one Exchange. Neither message carries an idempotency key, so neither verb
takes call options; `ver` is stamped when empty; a request that names no bare-domain
recipient is refused before it is signed. The client-request corpus gains three rows,
replayed in all three languages.

A new resolver face reads what one Exchange asks of a registration — the terms revision
submitting one accepts, and the schema its `registration_data` must match — from that
Exchange's own manifest, and it holds NO document cache. The contract requires a
registering client to read the terms digest from a freshly fetched manifest, and the
endpoint resolver is built out of exactly the mechanism that value may not touch, so a
face with no cache slot to reuse is what makes the rule structural. `Register` fills
`terms_digest` from it only when the caller left the field unset, applies the four
`registration_data` bounds before anything is signed, and pre-checks the payload against
the published schema — skipping the check, never the send, when that schema is one the
SDK refuses. The schema is measured over the bytes AS SERVED in every language, which the
two JSON ports reach by slicing the member out of the served body rather than
re-serialising a parsed value.

The reader dials on the SSRF-guarded transport in all three languages, and is built once
with the client rather than once per registration: the Exchange domain comes off the
request, so it is an address another party chose, which is the provenance that takes the
guard. A deployment reaching a private Exchange injects its own transport or sets the
usual two environment flags.

Two cross-cutting changes anyone re-pinning will see. The client's typed failure now
carries the peer's own developer message as a value — filled where the peer's own answer
is decoded, and empty otherwise: never a transport's synthesized status line, and never a
typed detail the SDK built itself, as the content leg does from an edge's refusal token.
So a consumer reads it instead of parsing it back out of a rendered error; it is
unbounded, and bounding it belongs to whoever displays it. And Python's `ClientConfig` gains `sign_window`, so the
RFC 9421 freshness knob sits at the tier Go and TypeScript already surface it at.

A refusal the pre-check computes carries what it computed. The offending members travel as
a typed `RegistrationFailure` detail beside the sentence, so a consumer that renders the
Exchange's refusal and the client's own through one renderer reads one shape either way
rather than parsing members back out of prose. Its domain names the client's own tier: the
Exchange never saw the request. The field errors are compared across languages by POINTER
only — the constraint text beside each comes from a different JSON Schema library in each
port and the contract calls it validator-defined — and an empty pointer, which is how a
missing required member is reported, now renders without a leading separator instead of as
a member with no name.

Two corrections to the content leg travel with it. The delivery edge's refusal tokens are
recorded in the proto beside each `RetrievalAuthFailureReason`, and the mapping is not
derivable — `expired` is `URL_EXPIRED`, `pop_expired` is `PROOF_EXPIRED`. Both JSON ports
had computed each name by uppercasing the token instead, which matches the record for two
of the eleven tokens, so nine refusals a real edge emits reached a TypeScript or Python
caller with no typed reason at all while any spelling that happened to match an enum
suffix was promoted. Both now carry the record. And an invalid-host refusal from an
injected requirements reader is classified `not_sent` in all three rather than retried in
two, which is what each port's own routing leg already answered.

**The requirements seam gains a verdict for a document it cannot use (additive, no wire
change).** `resolvers.ErrManifestUnusable` / `ManifestUnusableError` / `ManifestUnusable`
says the document arrived and this reader cannot use it — final, not a transport failure,
because the next fetch returns the same bytes. It exists because the reader seam is
injectable: the SDK's own reader refuses three things and treats every other
disappointment as absence or as an outage, so an implementation stricter than it — one
validating the whole manifest, or refusing a version — held a permanent refusal the seam
reported as transient and a caller retried indefinitely. One consequence for anyone
re-pinning: this is a fourth verdict on that seam, and a classifier branching only on the
older three drops it into its transport-failure bucket and retries something that will
never succeed; add the new sentinel alongside. The SDK's own reader returns it for one thing, a
document version it cannot classify; its other two disappointments are unchanged — an
off-spec optional member still reads as absent, and an undecodable document is still a
transport failure. Python also
stops treating an unrelated `ValueError` as a verdict on both the routing and the account
leg: the invalid-host refusal is recognised by its wording now, as TypeScript already did,
so an injected seam raising `json.JSONDecodeError` is retryable there as it is in the
other two.

A new shared corpus pins the details the SDK builds itself rather than receives — the two
above — over every recorded edge token, including the two that must stay untyped, replayed
in all three languages. Two conformance guards sit under it: one holds every committed
`ErrorDetail.domain` to the shape it claims (a `Service` suffix names a service the
contract defines, a bare noun names a tier that is not one), and one holds the corpus to
the token annotations in the `.proto` source. The first found a vector naming a
registration service the contract has never defined; that fixture is corrected.

*Also in this change:* every leg that builds a well-known URL reads one constant. That
path is the protocol's single bootstrap coordinate — a client holding nothing but a
hostname fetches it to learn the endpoint and the keys — and it was already exported in
all three languages and pinned across them by the wire-constants corpus, but the
TypeScript endpoint resolver still spelled it inline, and the registration-requirements
reader added here spelled it inline in all three. All four sites read the constant now.
Nothing observable changes; what it forecloses is a drift that fails as a misfetch from
the right host rather than as an error.

*Also in this change, from review:* the requirements reader now applies the manifest
version gate before it reads any other member, in all three languages — see the entry
below, whose scope this widens. That also settles a divergence the three shipped with: a
manifest body of bare `null` was a final refusal in Go and a retryable transport failure
in both ports, so the same bytes told one caller to stop and another to keep trying
against a third party's origin. The Python requirements seam is typed with the value it
answers rather than `Any`; TypeScript narrows `registration_data` instead of asserting its
shape, so a string payload is no longer reported as carrying too many members; and the
`peer_message` rule — the field carries a sentence the peer emitted and nothing else — is
pinned by two corpora replayed in all three languages instead of by three hand-written
suites. `ClientConfig.sign_window` and the numeric proto-JSON role form gain the Python
tests they shipped without.

*Parity record:* six new mapped symbols and one Go-idiomatic exclusion; the reader's Go
factory folds into the Python class constructor as every other `NewX` does, so the
shrink-only allowlist baseline moves 16 → 17 as a reviewed bump under that one recorded
class.

**SDK endpoint resolvers enforce `WellKnownManifest.ver`; `WellKnownManifestVersion`
exported (SDK behaviour change; no wire change).** The manifest's `ver` comment now
states the full receive-side rule — read before any other member, accept a
recognised MAJOR whatever the MINOR, refuse an unrecognised MAJOR, a non
`MAJOR.MINOR` value and an absent `ver` — and the direction of coupling to the
protocol version (a manifest layout change bumps both; a protocol change alone
bumps only `ProtocolVersion`). Go `helpers.CheckWellKnownManifestVersion` /
`helpers.ErrManifestVersionRefused`, Python `manifest_version_refusal` /
`ManifestVersionRefusedError`, TS `manifestVersionRefusal` / `ManifestVersionRefused`
carry the pure rule. The endpoint resolvers apply it and wrap the refusal as
`resolvers.ErrManifestVersionRefused` (same name in each port), which the client
tier classifies as not-sent; the registration-requirements reader applies the same
rule and answers its own seam's verdict, added later in this section. A `ver` that is not a JSON
string is refused as absent — a verdict, not a decode failure to retry — and the
value a refusal echoes is clipped to 64 characters, in all three languages. The
key resolvers are unchanged — they read JWK Set documents, not manifests — and a
test in each language pins that a key document carrying a `ver` still resolves. New corpus
`sdk/go/helpers/testdata/manifest-version-vectors.json` (`manifest_version`
list; columns `name`, `ver`, `present`, `accepted`), replayed in all three
languages and registered in the parity matrix. `conformance/manifest_version_rule_test.go`
pins the proto comment to the corpus in both directions;
`ver_field_contract_test.go` now reads the manifest's expected value from the
`WellKnownManifestVersion` vector entry rather than `ProtocolVersion`, so the guard
no longer couples the two namespaces. Test fixtures that serve a manifest to the
real resolver now carry `ver`. Compatibility: a manifest without `ver` was accepted
before and is refused now.

**`TransactionRequest.agent_request_acceptance` adds an agent-signed complete
ordered request-set proof (additive wire change).** The proof signs ordered
`(offer_sig, exchange)` references plus requester and idempotency key using the
same RFC 8785 JCS / detached Ed25519 convention as `AgentAcceptance`. A Broker
forwards the envelope unchanged while projecting a mixed-Exchange request; each
Exchange can then require the exact in-order projection addressed to itself
before creating or serving request-level idempotency state. This prevents a
relay from consuming an agent's key with an appended, removed, reordered, or
valid-subset-first request.

The field is optional for wire compatibility. The Go, Python, and TypeScript
SDK clients emit it for valid routed offers, and all three signing/verifying
faces are pinned to shared cross-language canonicalization and ordering vectors.

The payload's item list is capped at 256 entries (`repeated.max_items`, the
same ceiling a discovery query's `uris` list carries). The Go verification
helper enforces the same bound itself and decodes and size-checks the Ed25519
signature before rendering the payload to canonical JSON, because a verifier
may run with wire validation off and the canonical rendering of an unbounded
caller-controlled list is the expensive step. A test pins the helper's bound to
the wire rule so the two cannot drift. The projection check also refuses an
empty subrequest outright: without that, a request carrying zero items for an
Exchange the signed set never names would compare zero against zero and report
a verified projection.

Who authenticates a projected subrequest is now written down. A projected
subrequest is a new HTTP request its sender authors and RFC 9421-signs — a
Broker, or the agent itself when it splits its own mixed-Exchange set. The
agent's original HTTP signature covered the body the agent sent and does not
travel with a projected body; the detached body signatures (`agent_acceptance`
per item, `agent_request_acceptance` for the set) are what carry the agent's
authorization across projection, which is why they exist. The Exchange resolves
the acceptance verification key from the WBA directory of the requester domain
the signed payload names, which must equal the request's `requester.domain`;
when the requester itself signed the arriving request, that is the
request-signing key already resolved. Holder binding for delegations still
matches the wire signer, so a Broker may project a delegated request only when
the agent has delegated to the Broker's key.

**A term is now checked for permitted/prohibited disjointness a second time, over
the canonicalised tokens (`restriction.canonical_disjoint`; SDK behaviour change
plus a comment clarification, no wire change).** `restriction.permitted_prohibited_disjoint`
runs at the wire tier, over the request exactly as received, so it compares token
SPELLINGS. Ten registered aliases resolve to eight distinct restriction tokens —
`scrape` is a registered alias of `crawl`, `adapt` and `derivative` both mean
`modify`, `personal` means `individual` — and every axis also folds ASCII case. A term naming
one spelling under `permitted` and another under `prohibited` therefore passed the
boundary check and became, once the ingest tier folded it, a stored term with the
same token in both lists.

Nothing looked at it again, and the failure surfaced elsewhere: the term rides on
offers, an Exchange validates its own responses, and so every discovery request
returning that resource answered with an internal error while the push had looked
clean. The ingest tier now asserts the same property over the canonical values,
under its own rule id, in `ValidateLicenseTerm` and its Python and TypeScript twins.
The boundary rule is unchanged.

Disjointness is now the one property both tiers assert, deliberately: they read
different values, neither suppresses the other, and a deployment that does not mount
the wire tier still gets the second. The `Restriction` and `CatalogService` comments
say so, and a conformance guard holds the contract's statement to the rule the SDKs
run.

**Signed delivery URLs are documented as Ed25519 signed by the Exchange and
verified with its published public key, not HMAC-SHA256 over a shared secret
(documentation correction; no wire change).** Since the initial public snapshot
the file header, the DomainVerificationConfirmation comments and twenty website
pages described a symmetric scheme with a secret shared between the Exchange and
the CDN. No implementation ever produced one: `git grep -ci hmac — sdk/` finds
nothing, and signing has always been a detached Ed25519 signature that a
delivery endpoint verifies with a public key.

The divergence was wider than the algorithm name, so an implementer following
the documentation got four things wrong at once. The signed message is `"GET\n"`
followed by the canonical URL — the whole URL with the `sig` parameter removed
and the remaining query sorted by key — not four selected fields joined by
newlines, which means scheme, host, path and every publisher query parameter are
covered too. The signature is base64url with no padding, not a hex digest. The
expiry parameter is `exp`, documented as `expires`. There is a `kid` parameter
the pages never mentioned, and there is no `txn_id` parameter at all.

Where the documentation said `txn_id` enables three-sided reconciliation, the
join key is `signed_url_hash` — SHA-256 of the URL verbatim — recorded by the
Exchange on the transaction and by the delivery endpoint on its delivery event.
Neither side chooses the value.

`DomainVerificationConfirmation.signing_key` said key format is "PEM for
CloudFront, hex for HMAC"; hex is an HMAC-secret encoding, so the sentence had no
reading that matched the implementation. Its format now follows `cdn_type`, whose
documented value set becomes `"edge-ed25519"` | `"cloudfront"`. The retired
values named vendors rather than schemes, which made `"fastly"` actively wrong --
a Fastly Compute deployment runs the Ed25519 verifier. The name `edge-ed25519`
is not new; the reference implementation's architecture records already use it
for this path. The value list also
moves into the field's leading comment, because the reference page renders
leading comments in preference to trailing ones and this field already had one,
so the trailing list was invisible to every reader. The field now also states
its custody model: it carries public key material, the Exchange signs with a
private key it holds and never publishes, and where the Exchange must sign with
a key the provider generated — a CloudFront trusted key group is the provider's
own AWS resource — the private half is provisioned out of band and never
travels in this field. Both `cdn_type` values name the tenant signing scheme
they mirror, which the previous wording asserted without saying which is which.

The file header said "the agent is the fetcher", which held for one of the two
deployments. An agent embedding the SDK holds its own key and fetches for
itself; a custodial agent never fetches, because its key lives in its identity
service, which fetches on its behalf. Both present the same key to the delivery
endpoint, which is what makes the binding check work either way. The header's
"fully offline, no JWKS fetch required" is true of the fetcher's key, which
arrives in the request; the edge still resolves `kid` to the Exchange's public
key from a cached directory, so the claim now names the key it applies to.

Two security claims were corrected beyond the primitive. The threat model said
the provider holds the URL-signing private key and the Exchange calls a provider
signing service; no such service exists, and the Exchange signs with a per-tenant
key it holds itself. A walkthrough verified agent binding as
`SHA256(requester.id + ":" + requester.domain)`, which binds nothing an attacker
cannot recompute; the check is a thumbprint comparison against the presented
public key plus an RFC 9421 proof of possession.

Akamai is no longer documented as a supported delivery target: EdgeAuth verifies
with a secret shared with the CDN, which is the model this correction removes.
The retired phrasings are held out by the documentation conformance gate.

No wire change. The `cdn_type` value set lives only in a comment on an
`optional string`, never in an enum, and the field has no consumer in the SDK,
the conformance corpus, or the reference implementation. `gen/` is regenerated
with the pinned buf; the conformance corpus is unchanged, as comments carry no
constraints.

**`Offer.offer_id` is documented as an opaque unique identifier, not a resource
key (comment clarification; no wire change).** The comment already said the id is
assigned by the Exchange, but an implementation historically derived it from the
resource, which made two offers for the same resource collide. The comment now
states the id is opaque — not derived from the resource, its URL, or any other
field — and that two offers for the same resource have different offer_ids. The
wire type stays `string`.

**The offer-signature comments now state the implemented scheme: hex-encoded
detached Ed25519, not a JWS (documentation correction; no wire change).** Since the
initial public snapshot, the comments on `Offer.signature` and
`Offer.signature_algorithm` described a JWS (alg=EdDSA) envelope. No implementation
ever produced one: signing has always been hex(Ed25519) over the RFC 8785 JCS
canonical form, verification has always hex-decoded, and every conformance vector
carries a 128-character hex signature. An implementer who followed the comment
instead of the code emitted a compact JWS that failed verification — and the file
contradicted itself, because `AgentAcceptance` already documented the hex convention
and named `Offer.signature` as the single normative definition.

The proto comments, the website pages, and the SDK comments now state the
implemented scheme. `signature_algorithm` is documented as the JOSE/JWA algorithm
identifier (RFC 8037), advisory and excluded from the signed bytes. The v1.0
entries below are left as written; they record what that release said.
`Delegation.token` is unaffected — it genuinely is a JWT (base64url-encoded JWS).
The attestation signature envelope remains an open decision, and the file header no
longer asserts one.

**The restriction axis set is closed, and the rule that walks the restriction list
against itself is bounded (breaking, pre-1.0).** Two changes; the second is what bounds
the cost, and the first does not.

`Restriction.kind` carries `defined_only` beside its existing `not_in: [0]`, so a number
outside the four defined axes is refused rather than ignored.
A custom axis was never a new number — it is `RESTRICTION_KIND_OTHER`, whose meaning
rides in `permitted`/`prohibited` — and accepting an undefined one admitted a restriction
no consumer can evaluate onto a term whose default is BINDING, which fails open on the
axis a publisher most needs enforced.

Closing the axis does NOT bound the one-per-kind rule, and an earlier draft of this
entry said it did. That rule compares the list against itself, and `defined_only` does
not make the numbers it refuses EQUAL — each stays distinct, so `all()` still finds no
duplicate to stop on. Nor does the cap on the list help: protovalidate collects every
violation rather than short-circuiting, so a field rule that fires still leaves the
message rules to walk the whole oversized list. Measured, before the fix below: four
thousand restrictions cost 17s to refuse from 20 KB of wire, and the reference Exchange
reaches that rule before the caller is authenticated.

So the rule now leads with a size test —
`this.restrictions.size() > 8 || this.restrictions.all(r, …)` — and refuses the same
input in 26ms. It short-circuits to TRUE, so a list longer than the cap reports
`repeated.max_items` alone, which is its actual fault. A conformance guard holds the
threshold equal to that cap, since raising the cap alone would let a list in between
skip the duplicate check and pass. The TypeScript and Python cross-field faces evaluate
this rule themselves and carry the same test, so all three agree on the silence.

Measured on this contract, with the restrictions cap above: the most EXPENSIVE conformant
push that fits under the SDK's 4 MiB default read cap is 83 entries of 32 terms, each term
carrying one restriction per axis with both token lists at their 64-item caps and every
token a single character — 3.97 MiB, ~1.8s to validate; one more entry exceeds the cap.
The shortest legal tokens are what make it the worst case: validation cost tracks the
number of ELEMENTS walked while size tracks their length, so under a byte cap the
expensive shape is the one that spends its bytes on count. The same structure with
64-character tokens is 88 MB and never reaches the validator. A full-cardinality REAL
batch — 256 entries, 32 terms each, one restriction per axis and every field populated —
is 0.81 MiB and 475ms.

An earlier draft of this entry put that figure at 4.15 MiB and 7.4s and called it a
ceiling on conformant work. It was neither: the size was measured in MB and labelled MiB
(and so read as larger than the cap it fits under), the seconds came from a different
token length than the bytes did, and no ceiling follows from the caps — the enumeration
behind it omits quotas, obligations, scopes and attestations, and protovalidate checks a
non-conformant push as thoroughly as a conformant one.

**A cross-field refinement turned off the wire policy for the whole message (TypeScript
SDK fix; no wire change).** The composed cross-field schemas are the surface a TypeScript
consumer is told to parse with, and each one is a Zod refinement wrapped AROUND the
generated object rather than the object itself. `parseWire` drives its policy by
INSPECTING the schema it is handed — strip unknown keys, refuse a lowerCamelCase
`json_name` alias, read a `null` as no value — and a wrapper it could not see through was
returned untouched.

So no TypeScript code path applied the wire policy and the cross-field rules to the same
payload. A camelCase answer parsed SUCCESSFULLY into a message with every multiword field
missing, which is exactly what the alias refusal exists to prevent, and
`get_account_status_response.terms_digest_requires_billing_ref` could not fire on the
payload it was written for: `terms_digest` had already been dropped as an unknown key, and
the call reported success. All eight composed schemas behaved this way, and the rule added
earlier in this release was the eighth. Python was never affected — its composed model
subclasses the generated model and inherits the wire validator.

The policy seam now peels a refinement when it INSPECTS a schema, and still hands the
ORIGINAL schema to `safeParse`, so the refinement itself runs unchanged. The wrapper is
read as a method rather than by naming `z.ZodEffects`, which keeps the file working under
both Zod majors: Zod 4 has no such class, and a refinement there keeps the schema's own
type, so there is nothing to peel.

**`REGISTRATION_FAILURE_REASON_ALREADY_REGISTERED` is deprecated and never emitted, and
the schema gate now states its account-creation-only scope (comment and enum
deprecation; no wire change).** The repeat-registration rule added earlier in this
release says a repeat SUCCEEDS — it is answered from the stored record and returns the
existing `billing_ref`. Reason 4 still read "identity already registered", so the enum
and the rule answered the same request in opposite ways: one implementation refuses the
repeat, another returns the account.

Reason 4 is now marked `deprecated`, with `Register` forbidden from emitting it. The
number is retained and MUST NOT be reused, and the value MUST NOT be given a new
meaning. That last part is deliberate: it reads like a natural home for a future
cross-account identity collision, and this contract defines no way for an Exchange to
correlate business identity across accounts, so repurposing it later would silently
change what it means for every client already built against this text.

`AccountRegistration.data_schema` had the same gap. It calls itself the single home of
the enforce/pass-through contract and stated its gate without exception, so a reader who
went there for the whole rule got the wrong one. It now states that the gate runs on
account creation only and points at the repeat-registration rule.

**The composed cross-field models accepted payloads the Go oracle refuses (Python and
TypeScript SDK fix; conformance-affecting, no wire change).** Both ports offer two
surfaces for the message-CEL rules: a rule-id function that takes proto-JSON, and a
COMPOSED model that layers the cross-field rules onto the generated field-level model.
The rule-id function was correct in both. The composed surface — the one a consumer is
told to use — was not, in two separate ways, and nothing connected the two lists.

`GetAccountStatusResponse` had a registered rule and no composed model in either port,
so a Python or TypeScript consumer accepted a response carrying a `terms_digest` with no
`billing_ref`: an acceptance digest for an account that does not exist.

Python had a second, wider fault. The composed model handed the rules a dump that
renders an enum member as its Python repr, `ObligationKind.OBLIGATION_KIND_SHARE_ALIKE`,
while the rules compare against the wire token, `OBLIGATION_KIND_SHARE_ALIKE`. The
comparison never matched, so **every rule that reads an enum silently never fired** —
`obligation.share_alike.requires_scope_license`, `pricing.free.zero_rate` and
`pricing.per_unit.requires_unit`. TypeScript was unaffected.

Both ports now pin the registry to the composed exports by name, and drive the corpus
mutants through the composed models themselves. The second test is what found the enum
fault: comparing the two lists proves a model EXISTS, never that its validator runs.

**A `google.protobuf.Value` with no `kind` set is a second payload with no JSON form,
and it was accepted (Go SDK fix; conformance-affecting, no wire change).** `Value` holds
its payload in a `oneof`, and a `oneof` with no member set is well-formed on the wire:
the binary decoder accepts it, and proto-JSON refuses to render it with "none of the
oneof fields is set". So it belongs to the same refusal class as a non-finite number —
no canonical encoding, therefore no measurable size — and
`helpers.CheckRegistrationDataStruct` did not catch it, because the class had been
written as though a non-finite number were its only member.

It fails in the same shape as `NaN`, and for the same reason it cannot be caught after
conversion: `AsMap` renders an unset `kind` as an absent value, which is exactly what a
real JSON `null` gives, and `null` is a value a payload may legitimately carry. Both
members of the class are now refused by the raw walk, which already visited every value,
and the contract defines the class by what it means rather than by one example: a payload
with **no JSON representation**. A payload carrying a real `null` is still accepted.

**A registration payload carrying `NaN` or an infinity was accepted by a Go Exchange and
refused by a Python one (Go SDK fix; conformance-affecting, no wire change).** `Struct`'s
`number_value` is an IEEE-754 double, so a non-finite number crosses the wire intact —
`structpb.NewNumberValue` does not refuse one and the binary codec carries it unchanged.
JSON can write none of the three, so such a payload has no canonical form and no
measurable size, which is what `uncanonicalizable` names. Go could not see it. The SDK's
own doc comment named `RegisterRequest.GetRegistrationData().AsMap()` as the call site,
and Go's protobuf runtime renders the three values as the STRINGS `"NaN"`, `"Infinity"`
and `"-Infinity"` during that call, so the check received a well-formed string and
answered `accepted`. Python and TypeScript decode into objects that keep the real float
and refused the same payload. Two conformant Exchanges therefore answered the same
signed request differently, and a Go Exchange stored the text `"NaN"` where the caller
had sent a number.

The fix is a new Go entry point, `helpers.CheckRegistrationDataStruct`, which reads the
raw `*structpb.Struct`. **It cannot be a repair of the map-based check**, and that is
worth stating because it looks like one: after `AsMap` has run, a non-finite number and
an operator legally named `NaN` are the same three bytes, so a check that refused the
text would refuse a valid registration. The conversion destroys the evidence, so the
check has to precede it. `CheckRegistrationData` still exists for a caller whose payload
never was a `Struct`, and its comment now says what it cannot see. Python and TypeScript
get no new face: their existing checks already see the case, so a second entry point
there would be an alias with nothing to do — it is recorded as a Go-only divergence in
the parity matrix instead. No shared corpus can carry the case in any language, because
JSON cannot write the value down.

**The order of the registration gates is pinned, and two of the orderings were
previously free choice (comment-only; conformance-affecting).** A payload is now checked
in a stated sequence: top-level member count, nesting depth, canonicalizability, canonical
byte size, then `terms_digest`, then the published `data_schema`.

Two of those were unstated. **Canonicalizability precedes the byte cap** because the cap
is DEFINED as the length of the RFC 8785 encoding — until that encoding exists there is
no number to compare against, and answering "too large" for a payload that has no
encoding at all asserts a measurement that was never taken. **The terms gate precedes the
schema gate** because the schema may itself have changed in the revision the caller has
not read. Validating a stale-terms caller against the CURRENT schema hands back field
errors describing a document it has never seen, so it fixes those members, re-fetches,
and finds the requirements have moved. Terms first means a caller is always told to read
the current manifest before it is told anything about that manifest's contents. It also
keeps one refusal to one remedy: `TERMS_DIGEST_STALE` says re-fetch and echo,
`INVALID_REGISTRATION_DATA` says fix the payload, and a request earning both is given the
one that has to be done first.

**A repeat `Register` is answered from the stored record and runs none of the
account-creation gates (comment-only; conformance-affecting).** Two rules were each
stated absolutely and neither mentioned the other: `Register` returns the same
`billing_ref` for the same agent, idempotent by design; and a `terms_digest` that differs
from the published one is refused as stale, in a paragraph that calls its four cases "all
defined". For a returning agent after the operator revises its terms the two give
opposite answers, and an implementer reading the second paragraph alone will refuse the
caller and believe they are conformant — which breaks every returning agent on the day
the terms change, because the account it already holds becomes unreachable through the
RPC that exists to return it. The rule is now written where the idempotency promise is
made, together with the reason: a repeat discards `registration_data` entirely, so
checking a member about to be thrown away reports an error about a value that has no
effect. What a repeat still runs is stated too — signature verification and caller
identity, the recipient check on `RegisterRequest.exchange`, and the field-level
constraints — so "no gates" is not read as "no checks".

**`GetAccountStatusResponse.terms_digest` (field 4) makes the accepted terms readable.**
The protocol already required an Exchange to record the accepted digest with the account,
and said plainly that this is what makes "which terms did this operator accept"
answerable later. Nothing could ask. No RPC and no field returned the value, so the only
party who could check what an operator had agreed to was the party holding the database —
and the `MUST NOT` beside it, that an Exchange publishing no digest must ignore a
presented one and must not record it as an acceptance, could not be tested through a
public surface at all. Absence of the new field has exactly one meaning: no acceptance is
recorded, either because the Exchange publishes no digest or because the account predates
one. An Exchange holding a digest MUST return it — absence is already spoken for, so
withholding would make the field state something untrue. The value is what was ACCEPTED,
not what is published now; comparing it against a freshly fetched
`WellKnownManifest.terms_digest` is how an agent discovers the terms moved under an
account it already holds, which a repeat `Register` will no longer tell it. A message rule
(`get_account_status_response.terms_digest_requires_billing_ref`) joins the digest to the
account handle it hangs on, so a reader can never take an acceptance from a response that
carries no account.

**The catalog lists are bounded, and the bound names the quantity it controls
(breaking, pre-1.0).** `LicenseTerm.quotas` and `.obligations` carry at most 64 items
each — the bound every per-message list in this contract carries when no rule walks it
more than once — and `PushResourcesRequest.entries` and `RemoveResourcesRequest.paths` at
most 256, the bound a caller-chosen batch carries at `ResourceQuery.uris`. Every committed
feed is under ten entries, so the batch cap sits far above real traffic and a larger feed
is pushed in several submissions.

`LicenseTerm.restrictions` carries at most 8, and like the others this bounds the
DOCUMENT rather than the rule — an earlier draft claimed otherwise. Only one restriction
per axis is valid and `Restriction.kind` is now defined-only, so four is the longest
conformant list and eight leaves room for an axis this version does not have. The largest
downstream feed carries three.

The tighter bound still earns its place, for a different reason: this is the one list a
message rule walks against ITSELF, so the number is also the threshold of the size test
that rule carries, and a conformance guard holds the two equal. The disjointness rule on
each element is quadratic only in that element's two token lists, both capped at 64, so
its cost is bounded per restriction and linear across the list.

What these caps bound is the DOCUMENT: how large one entry may be, what a push can store,
and how much a rejection has to name back. They do NOT bound the work of checking a push,
and the `ResourceEntry` comment no longer says they do. A validator walks every element it
is handed and reports every violation before any cardinality rule is applied — measured on
this contract, an entry with 100,000 terms costs 393ms and allocates 100,001 violations
even though `terms` was already capped at 32. A bound belongs on the phase whose cost it
models, so the work is bounded one layer down, by the maximum request size the recipient
will read.

`CATALOG_REJECTION_REASON_TERMS_LIMIT_EXCEEDED` is recorded as retired on the
`PushResources` path. An over-cap entry always refused the whole submission — a catalog
push is all-or-nothing — so moving the cap onto the wire changed WHEN it is refused, not
what survives: the refusal now happens at the boundary, before any per-entry classification
runs, and no rejection naming that reason can be produced for a push. The value stays for a
deployment that applies the cap somewhere the wire rules do not reach.

*Tooling:* the corpus grows from 602 to 607 cases — one `too_many` mutant per newly bounded
field; `LicenseTerm` goes from 4 to 7, `PushResourcesRequest` from 20 to 21 and
`RemoveResourcesRequest` from 28 to 29. The `entries` mutant carries 257 full
`ResourceEntry` instances and is the reason `cases.json` roughly doubles; that cost is
accepted rather than paid for with a smaller cap. The catalog-path pattern gains the
descriptor-derived membership guard the domain and digest patterns already have
(`wantResourcePathFields = 2`) — it was the one shared pattern without one, and the
generator keys its killer table by the pattern string, so a drift would have silently
emitted no mutants at all.

**The SDK's server binding bounds what a handler reads (no wire change;
conformance-affecting).** `connectserver` sets a per-request read cap on all three handler
bindings, defaulting to 4 MiB and overridable with `WithMaxRequestBytes`. It bounds two
quantities, because a caller can exhaust a server through either: the decompressed Connect
message, refused as `resource_exhausted`, and the raw HTTP body the verify face must buffer
whole to check an RFC 9421 signature over the exact bytes — which it does before it knows
who the caller is, so an unauthenticated caller reaches that one. The body bound is
composed inside request-id and outside verify, so a refusal still carries its
`X-Request-ID`, and a body past the cap is now classified `resource_exhausted` rather than
told its credentials were wrong. Measured: a full-cardinality push — 256 entries each
carrying the full 32 terms, one restriction per axis, every field populated — is 0.81 MiB
and validates in ~475ms, while the most expensive conformant shape that still fits under
the cap is 83 entries with both token lists at their caps and single-character tokens,
3.97 MiB and ~1.8s. That is what the default buys: not a small worst case, but a bounded
one. It is a measurement of one shape rather than a ceiling over all of them — raising the
cap raises the worst case roughly linearly, with no value past which it stops mattering.

The decompressed bound is not a bound on decompression WORK. Connect drains the remainder
of an over-cap stream to size the error it returns, so the body is fully inflated before it
is refused; what keeps that finite is the raw-body bound, and at 4 MiB of compressed input
it is 4.32 GB inflated in ~850ms of CPU on a request that is then rejected. The byte figures
size a representative batch, not a ceiling on a conformant one: the contract's caps bound
how many entries and terms a push carries, never how many bytes, so a conformant push can
exceed this cap and be refused.

**The server binding's refusal answer is exported, so a consumer stops re-deriving it
(SDK only; no wire change).** `connectserver` now exports `RejectCode`, `IsBodyTooLarge`
and `WriteReject` — the classification, the over-cap predicate and the writer that pairs
the Connect error body with its HTTP status. They were unexported, so a third-party
Exchange, or any mount composed by hand rather than through `NewCatalogServiceHandler`,
had to write its own. That copy does not stay level: Connect maps `ResourceExhausted` to
429 for every cause, and this binding answers 413 for a body past the read cap because
that is the one refusal a caller fixes by sending less. A re-derivation lands on the
specification's answer and diverges silently. `WriteReject` takes the Connect code as a
parameter rather than deriving it, so a gate carrying its own resource-limit sentinel
answers that case itself and defers every other to `RejectCode` — a delegation, not a
fork. The over-cap arm is now gated on the code as well as the error, so a rejection
classified as something other than a resource limit cannot be answered 413 over a body
that names a different verdict; on the path that existed before, that guard is always
true, so no response changed.

**The contract states that a push is all-or-nothing, and the prose follows it (docs).**
`CatalogService` described both validation tiers in full — folding, alias resolution, which
checks reject and which warn — and never said whether a rejection costs the entry or the
submission. Readers therefore inferred it from an implementation, and inferred wrong. The
rule is now in the contract: a hard rejection at either tier refuses the entire submission
and persists nothing, and the per-entry detail a refusal carries is reporting, never partial
acceptance. `CatalogRejection.rejected_paths` says which entries a refusal is about rather
than calling itself a partial-batch failure, and the JSONL ingestion page states the rule
once, for both tiers. The publisher-onboarding and
verification-vendor pages had told a reader to build the catalog client against the
Exchange's advertised `catalog_endpoint`; the address is configuration, and a deployment
that does read it from a manifest MUST itself check the host binding that field states —
no SDK reads the field, so nothing else will. The one TypeScript SDK import sample on the
site named a package that does not export those symbols.

**`ResourceEntry` carries envelope rules, and the catalog request lists are bounded
(breaking, pre-1.0).** The terms inside an entry were guarded by the `LicenseTerm` rules;
the envelope around them was not, so an entry with an empty `domain`, a `path` without a
leading slash, or a `domain` carrying a scheme or a path reached the Exchange and was
refused — or quietly synthesised into a wrong catalog URI — only after ingestion had
started. `domain` now carries the shared bare-host rule every addressed `exchange` field
carries (a port is allowed; a scheme, path, query or userinfo is not; 260 characters);
`path` is an absolute URL path (`^/[^?#\x00-\x20\x7f]*$`, 1–2048 characters); `title` (512),
`content_id` and `content_hash` (255), `hash_method` (64) and `provenance_source` (260)
are length-bounded — every one of these counts CHARACTERS (Unicode code points), which
is what protovalidate's `max_len` counts, so a conformant value can exceed its character
count in bytes; `word_count` and `estimated_quantity` are non-negative;
`attestations` carries at most 64 entries and `terms` at most 32 — the cap
`CATALOG_REJECTION_REASON_TERMS_LIMIT_EXCEEDED` named, stated on the wire so every
implementation refuses the same size. `content_hash` is deliberately not format-checked:
a bare hex digest and a `method:hexdigest` form both travel today, and `hash_method`
names the algorithm. `PushResourcesRequest.entries` and `RemoveResourcesRequest.paths`
require at least one item, and each removed path carries the same absolute-path shape.
Adding a rule changes no signed bytes — a protovalidate rule is a field option, not a
field — and `buf breaking` cannot see it. Every committed fixture and the reference e2e
catalog (ports on `domain`, single-label hosts, bare-hex hashes) passes the new rules;
what changes is that a malformed push is refused at the boundary rather than after
ingestion, and a path without a leading slash — accepted before, and synthesised into a
URI that named the wrong resource — is now refused.

`WellKnownManifest.catalog_endpoint` states the same host binding as `endpoint`: on the
host and port that serve the manifest or a subdomain of it, no userinfo, and a consumer
refuses anything else and does not fall back to `endpoint` when the field is absent. A
publisher's push is a signed call to that address; without the rule a manifest could
redirect it to a host the signature never covered. `CatalogService` and `ResourceEntry`
also document the two validation tiers a push passes — the wire rules, then
canonicalisation and registry membership over the terms — so a publisher can run both
before sending.

*Tooling:* the corpus grows from 549 to 602 cases; `ResourceEntry` goes from 3 to 48 and
`RemoveResourcesRequest` from 20 to 28. The generator's sample list gains `"/x"`
(append-only, so no existing field re-values) and the path pattern gains its own killer
table — no leading slash, `?`, `#`, whitespace, a control byte. The guard counting the
shared domain rule's fields moves from 17 to 18, and the manifest endpoint-comment guard
now reads `catalog_endpoint` too.

**Restriction-token aliases are authored in the proto and generated into every SDK
(additive, no wire break).** The licensing core's vocabulary table always recorded that
`train-ai` is AIPREF's spelling of `ai-train`, `generative-ai` the industry's spelling of
`ai-input`, `scrape` of `crawl`, `tdm` of `text-and-data-mining`, `copy` of `reproduce`,
and `adapt` and `derivative` of `modify`; the reference Exchange resolved them from a
private map, and the user-type aliases (`personal` → `individual`, `business` and
`enterprise` → `commercial_entity`) existed only in that code. They are now
`(fora.v1.vocab_enum_alias)` entries beside the tokens they resolve to, in the form
`alias=canonical`, and `protoc-gen-foravocab` emits an `Aliases` map and a `Canonical`
lookup (`canonical` in TypeScript and Python) per axis in all three languages — an axis
without aliases carries an empty map so every axis has the same face. Codegen refuses an
alias that is itself a token, a canonical that is not one, a duplicate, and a spelling
that is not already trimmed and lowercase: the SDK folds a token before it looks it up,
so any other spelling could never match. The generated lookup does no folding of its
own. The docs' vocabulary tables render the aliases from the same descriptor option.

*Tooling:* the three generated alias maps are held to one answer per axis, and to the
registry, the way the token sets already are.

**The SDK serves the publisher role, in all three languages (no wire change;
conformance-affecting).** Three additions, one per gap. A catalog client —
`connect.NewCatalogClient` in Go, `createCatalogClient` in TypeScript, `CatalogClient`
(async, with a blocking twin under `fora_sdk.sync`) in Python — issues `PushResources`,
`RemoveResources` and `RefreshCatalog` under the same names in each language, over the
same signing transport, redirect refusal, request-id and validate interceptors and read
cap as the agent verbs. It is a separate constructor because CatalogService is a separate
address (`WellKnownManifest.catalog_endpoint`) and its caller holds a contributor key
named by `caller_id`; the publisher chose the Exchange, so the leg runs on the plain
transport. The messages carry no idempotency key and the client mints none; `ver` is
stamped when empty; a request that names no bare-domain recipient is refused before it is
signed. The client-request corpus gains the three verbs, replayed in all three languages.

The ingest-tier license-term checks moved out of the reference Exchange into the L1
helpers — `NormalizeLicenseTerm`, `NormalizeResourceEntry`, `ValidateLicenseTerm`,
`ValidateResourceEntry`, `CanonicalRestrictionToken`, `KnownRestrictionToken` in Go, the
same faces in snake and camel case in Python and TypeScript — so a publisher runs the
checks the Exchange will run before sending: RFC 8259 trim, ASCII-only case fold, alias
resolution through the generated vocabulary, a hard reject for a bare unregistered
`Pricing.unit` or `Quota.metric`, a warning for an unregistered restriction token or an
`OBLIGATION_KIND_OTHER` obligation without detail, and a per-entry verdict composing the
wire tier and the ingest tier in the Exchange's order. Warning messages are the exact
wire strings. A new Go-emitted corpus (`licenseterm-vectors.json`: fold, normalize, known,
validate, entry) is replayed by both ports, and a conformance guard holds the SDK rule
ids to the descriptor's CEL-id namespace without collisions.

`connectserver.NewCatalogServiceHandler` composes the same request-id · verify · validate
· error-detail stack over the generated CatalogService handler, so an Exchange
implementer has a server-side starting point for the publisher-facing RPCs; contributor
authorisation, tenant binding and per-entry verdicts stay the handler's job. The validate
step is opt-in on all three bindings and always has been — `ValidationOff` is the enum's
zero value — so a deployment that wants the contract's boundary rules passes
`WithValidation(ValidationStrict)` on the mount. The handler docs now say so rather than
leaving it to be inferred from a stack diagram, and a handler asked for strict validation
that cannot build the validator now fails at construction instead of serving without it.

*Parity record:* thirteen L1 exports and the catalog client are mapped at
three-language parity (130 symbols, 34 corpora). Two documented divergences join the
record — the catalog client's Go factory folds into the Python constructor as every other
`NewX` does, and the Catalog handler binding is a third symbol under the recorded
full-Connect-handler decision — so the shrink-only allowlist baseline moves 14 → 16 as a
reviewed bump, and the gate now names that one sanctioned growth shape.

**The TypeScript and Python SDKs gained a client, and it changed what they accept
from a peer (no wire change; conformance-affecting).** Neither could SEND a FORA
request before; both now speak the Connect-unary JSON form the protocol's unary RPCs
are fully described by. Seven consequences reach anyone re-pinning, and none of them
moves a field, a message or an encoding — `buf breaking` reports nothing.

**Every signed request now carries `authorization` and `signature-agent`, empty values
included.** The RFC 9421 covered set binds both unconditionally — that is what stops a
later injection piggy-backing an existing signature — and a verifier rebuilds the base
from the request it RECEIVED, so a value bound but never sent is not bound at all. Both
ports bound them and attached neither, so every signed RPC was refused with
`header "authorization" missing from request` while all three languages agreed
byte-for-byte on the signature itself. Re-pinning changes the header set your clients put
on the wire; nothing about the bytes they sign moves.

Three further consequences of the same rule. The TypeScript signer emits the covered header
names **lowercase**, so a caller supplying its own `Authorization` has it replaced rather
than duplicated — two field lines under one covered name are joined with `", "` before the
base is rebuilt, which breaks an otherwise valid signature. And every server-verify face
in both ports now **refuses a request that OMITS a covered header** while still accepting
one that carries it empty: defaulting an absent header to empty invents a value the signer
may never have bound, and accepted exactly the request the Go verifier refuses.

Those faces also read every header the way the wire defines it, which changes what they
accept. Names are matched **case-insensitively**, so a header bag spelling them
`Authorization` / `Signature-Agent` now verifies where it used to be refused. Repeated
spellings of one name are **joined** with `", "` rather than one being picked, so an
unsigned `Authorization: Bearer …` placed beside a signed empty one changes the covered
value and is refused — previously it was read past and the request was accepted, on every
face. If you built a header mapping for these faces by lowercasing keys, nothing changes
for you; if you passed one straight from a framework, it now behaves as the oracle does.

**The Go entitlement-coverage check reads every field line too, and this one is a
behaviour change in `sdk/go/helpers`.** It resolved `X-Entitlement-Token` with
`Header.Get` — the first line only — at both the sign site (whether the covered set
commits to the header) and the verify site (whether an unsigned token is being slipped
in). A request that simply sends the header **twice**, an empty line ahead of a real
capability token, made both answer `""`: the signer left the header uncovered and the
verifier skipped the rule, so the token rode in under a signature that never committed
to it. Ordinary HTTP, no unusual client. Both sites now join every line, so any second
line makes the value non-empty. Nothing in a single-line request moves — no API changes,
both functions are unexported — but a peer that sends the header twice is now refused
where it was accepted.

A **`null` means the field has no value**, and the TypeScript wire policy now reads it
that way. The canonical wire is proto-JSON, where a null is a field's default — for **any**
field, not only a message-typed one — so the policy drops it wherever the schema does not
require a value, and leaves it for the schema to refuse where it does. `EmitUnpopulated` —
what `connectserver`'s codec emits, and therefore what a FORA Exchange serves — renders an
unpopulated non-optional field as `null` rather than omitting it, so `{"ext":null}` is the
ordinary shape of a real response. (An unset **map** renders `{}`, and an unset `optional`
field is omitted outright.) Every generated Zod schema rejected `null`, which meant a
TypeScript consumer could not read a conformant answer at all. Pydantic already spelled
those fields `X | None`.

An earlier form of this note said only a message field and a `Struct` arrive as `null`.
That described what the codec emits and was read as a bound on what a client must accept,
which it is not: an unset `google.protobuf.Timestamp` arrives as `null` too, and because
the type generator flattens it to a string schema, a rule written for message-typed fields
refused it. An attestation without an `attested_at`, or a rate limit without a `reset_at` —
both conformant, neither carrying a validation rule that requires the field — took the
whole answer down for a TypeScript reader while Go and Python read it. The rule now asks
about presence rather than type, and a shared corpus pins it in all three languages.

Where that policy lives matters to a consumer: the schemas themselves are unchanged, and
`parseWire()` in `wire/base.ts` is what applies it — together with the naming refusal
below. `@fora-protocol/sdk` now exports `./wire/base` and `./wire/names` so a consumer of
the generated types can reach it; parse an answer off the wire with `parseWire(Schema, body)`
rather than `Schema.safeParse(body)`.

A **lowerCamelCase answer is refused**, at every depth, with the reason
`not_canonical_wire_naming`. The FORA wire is snake_case proto-JSON and the `json_name`
alias is out of contract; a stock `connect-go` server that registers no `UseProtoNames`
codec serves the alias, and the generated clients accept snake_case only and drop what
they do not recognise — so such an answer parsed successfully into a message with every
multiword field missing. A deployment must register the codec on every JSON-serving
listener; the reference services already do.

**`Offer.title`, `ResourceEntry.title` and `UsageAsset.title` exist in the generated
Pydantic and Zod models** for the first time. They are proto fields whose NAME is `title`,
and the types pipeline removed every key of that name while meaning to drop the
JSON-Schema keyword.

**`mimeTypeOf` narrowed in Go**: `text/plain; ;` now reduces to `text/plain` instead of
the default, and a bare token carrying no slash now reduces to the default instead of
passing through. The rule is stated rather than delegated — the text before the first
`;`, trimmed and lowercased, must be `token "/" token` — so all three languages answer
alike. The function is unexported with one call site, so no Go caller depended on the old
behaviour.

**A hex signature carrying a sign, whitespace or an odd length is refused in
TypeScript**, as Go and Python already refused it. And Python's edge refusal-token anchor
no longer admits a trailing newline, which Go and TypeScript never did — the token is
echoed into a caller's logs.

**Nine TypeScript modules the root export map could not reach are importable**, and the
root manifest now carries `undici` and the peer metadata `sdk/ts` declares. `exports`
carries no wildcard, so an unlisted subpath failed with `ERR_PACKAGE_PATH_NOT_EXPORTED`
and had no deep-path workaround; `./resolvers` was listed and still unimportable for want
of the dependency.

Five shared vector files are new against the previous revision, all replayed by all three
SDKs: `connect/testdata/{connect-error,client-request,transport-failure}-vectors.json`,
`helpers/testdata/wire-names-vectors.json` and
`resolvers/testdata/content-fetch-vectors.json`. The transport-failure set records what
class an answer that did NOT come from the service falls into, captured from a real
`connect-go` client rather than transcribed; the wire-names set pins the two textual rules
above. The `null` and naming rules are pinned
beside the generated types instead, in `gen/{ts,python}` — they belong to the schema seam
every message routes through, not to one tier's corpus. The endpoint rule's existing
corpus now replays through the CLIENT as well as the resolver in all three languages, which
is what holds the re-check an injected resolver's answer gets. Per-language surface:
`docs/sdk-parity-matrix.md`.

**The endpoint rule is enforced in all three SDKs, and it now refuses a credential
it used to accept (no wire change; conformance-affecting).** `WellKnownManifest.endpoint`
has stated its rule as a MUST since the previous revision — the advertised endpoint must
be on the host and port that served the manifest, or a subdomain of that host on that
port, and must not carry userinfo — but only the Go SDK enforced it. Python and
TypeScript shipped endpoint resolvers that returned whatever the manifest said, and
neither language exported the predicate the rule is built from; each carried a private
near-namesake in its WBA module that answered a slightly different question. Both
resolvers now vet the advertised endpoint before returning or caching it, both refuse a
`host` argument that is not a plain hostname before building the fetch URL from it, and
`hostOf`/`isBareHost`/`hostAnchored` (`host_of`/`is_bare_host`/`host_anchored`) are
public in both. The private copies collapsed into the shared predicate, so the WBA
revocation poll compares its candidate by the same rule as the endpoint. The value
it anchors AGAINST is still derived by each platform's own URL parser, so a
directory that spells out a default port is read differently in TypeScript than in
Go and Python; aligning that is the port of the fetchable-directory policy, tracked
separately.

The refusal itself also got one shape wider, in all three. It was decided over a plain
URL parse of the advertised value while the anchoring half re-read the same string
through its own parse, and the two disagreed on exactly the shape the refusal exists to
stop: `u:p@exchange.example` names no scheme, so a plain parse takes `u` for one and
reports no userinfo, while the anchor check reads the value as https and matches the
host. An endpoint carrying credentials without a scheme was therefore accepted; it is
refused now. Both halves read the reference once, the same way.

Two consequences for anyone re-pinning. Resolution can fail with a new verdict —
`EndpointRefusedError` in Python, `EndpointRefused` in TypeScript, joining Go's
`ErrEndpointRefused` — which is FINAL, not something to retry; and a deployment whose
manifest advertises an endpoint on an unrelated host, on another port, or with
credentials in the URL will now be refused by a Python or TypeScript consumer that
previously accepted it. `buf breaking` reports nothing: no field, message or encoding
moves. The rule is corpus-locked to two new shared vector files
(`helpers/testdata/host-rule-vectors.json`, `resolvers/testdata/endpoint-vet-vectors.json`)
that all three SDKs replay. What that buys is narrower than "the three now agree
about everything", and worth stating precisely: a divergence on a rule the corpus
covers fails CI instead of shipping, and the corpus covers the rule's boundaries
rather than every string a caller can construct. Per-language surface:
`docs/sdk-parity-matrix.md`.

One consequence for Go consumers who set a GODEBUG. `net/url`'s host-colon strictness
is the `urlstrictcolons` setting, and a GODEBUG belongs to whoever builds the program:
under `urlstrictcolons=0`, from the environment or a `//go:debug` line,
`helpers.IsBareHost` was reading `exchange.example::443`, `exchange.example:44:3` and
five near relatives through a parser that accepts them, while the vectors this repo
publishes record every one of them refused. GODEBUG exists so an operator can back out
of a behaviour change, so one set for an unrelated URL reason would quietly loosen a
predicate standing in front of a signed call. The second colon is refused by the
predicate itself now. A consumer running the default posture sees no change, and no
committed vector moves.

**The registration schema's rules become checkable, and two of them were wrong
(comment-only, no wire change).** The previous revision stated a rule set for
`AccountRegistration.data_schema` and shipped an SDK to enforce it. Reviewing what
shipped found the central promise — that two conformant validators agree about which
payloads a published schema accepts — was false, and that the resource caps bounded the
wrong thing. Both are corrected here, and the shared corpus gains the dimension that
would have caught them.

**`pattern` needed two mechanisms, not one.** Draft 2020-12 patterns are ECMA-262 and
the engines implementations run disagree about them in two different ways. Some
constructs one engine cannot express at all, and those are refused — that much the
previous revision had. The rest every engine compiles and then reads DIFFERENTLY, and
refusing those would have gutted the feature, because they are `$`, `\d` and `\w`,
which appear in almost every real pattern. `^[A-Z]{2}[0-9]+$` — the example this
contract itself gives — accepted `"DE12345\n"` under one implementation and refused it
under two, with nothing logged. So an implementation whose engine differs is expected to
correct it: match ASCII character classes, and anchor `$` at the end of the text and
nowhere else. `\s` and `\B` are refused instead, because for those there is no single
meaning to correct TO — RE2 reads `\s` as `[\t\n\f\r ]`, Python adds the vertical tab,
and ECMA-262 adds that plus every Unicode space separator, while `\B` finds no word
boundary in the empty string for two engines and finds one for the third. An explicit
character class says what was meant.

**The alphabet is now stated as what a pattern MAY contain.** The previous revision
enumerated the divergent escapes, and that list was wrong in both directions and could
not be finished: the set of escapes three engines disagree about grows with every
dialect and library version, so it needed a new entry each time somebody found one, and
`\B`, `\cA`, `\a`, `\012`, `\x{41}`, `\uHHHH` and the identity escapes were all admitted
until somebody did. The portable set is small and closed — the shorthand classes, the
control characters, `\xHH`, and the metacharacters that stand for themselves — and it
was derived by running every ASCII escape through all three engines in three positions
rather than by reasoning about them. An author who wants anything else writes the
characters out.

Four more shapes join the refused list, each of which two engines read differently
without erroring: a POSIX name anywhere inside a bracket expression (not merely at its
start, which is all the previous rule checked, so `^[a[:alpha:]]+$` slipped through and
produced three different answers); a counted repeat over 1000, which RE2 refuses and the
others expand; a bracket expression that opens with `]` or never closes; and a range
whose endpoint is a shorthand class (`[\w-x]`), which RE2 reads as a range while the
other two refuse it outright.

**Where a pattern may appear is now stated.** `pattern` carries its regex as a value and
`patternProperties` carries its regexes as KEYS. Both are patterns, both are held to the
alphabet, and they are the only two keywords in the dialect that carry one. Saying so
matters because it is exactly what an implementation gets wrong: correcting the `pattern`
keyword alone leaves `patternProperties` uncorrected, and a property name that is a
non-ASCII digit then matches `^\d+$` for one implementation and not the other two — the
same silent split, on the keyword the rules already single out for pattern SAFETY.

**Nested quantifiers are refused outright.** `(a+)+`, `(a|a)*` and `([a-z]+)*` are the
catastrophic-backtracking forms, they need neither lookaround nor backreferences, and
the previous revision's claim that excluding those two "falls out of the same rule" was
simply wrong — every one of them was admitted. It has to be a PUBLISHING rule rather
than a runtime bound, because a regex spin holds its interpreter: a consumer cannot
reliably interrupt one it has already started.

**The caps bounded the document, not the work.** 16KB and 32 containers say nothing
about how expensive checking a payload is. Branches multiply along a reference chain, so
a 1,675-byte schema five containers deep — a tenth of the size cap, a sixth of the depth
cap — cost 16.7 million evaluations and twenty-seven seconds against a two-member
payload. A new bound of **10000 evaluations**, counted statically before anything runs,
is the missing one; it is about fifteen milliseconds of work, several hundred times what
a schema describing a business entity needs. It bounds the SCHEMA: it is the cost of
applying the schema at one location in a payload, so a subschema under `items` is counted
once here and evaluated once per element at runtime.

**Reference cycles are refused.** A `$ref` chain that returns to a schema already on it
is legal JSON Schema and has no static cost bound; it is also what made validators
recurse until they aborted, out of an API documented as returning a verdict rather than
throwing. `{"$ref":"#"}` is twelve bytes. The same walk that counts evaluations follows
every reference to its target, so it decides this and the resolvability of a
same-document reference at the same time — three questions the libraries had been
answering three different ways.

**The encoding is pinned, because it decides which document the rules are read
against.** The bytes MUST be well-formed UTF-8 and MUST NOT begin with a byte order
mark. RFC 8259 forbids adding a mark and permits a parser to ignore one, so both
policies conform and the contract makes the choice once: a parser that strips a mark
validates a different document than the one served, and counts three bytes against the
size cap that the schema does not contain. Ill-formed bytes MUST NOT be repaired either
— one implementation's parser silently substituted U+FFFD and enforced a `pattern` with
a different character inside it, while the other two refused the same bytes. The
JavaScript-only literals `NaN` and `Infinity` are not JSON (RFC 8259 §6) and are refused
with them; one implementation's parser accepts all three as an extension.

**The payload's nesting is bounded too, at 32 containers — because without it the answer
depended on who was reading.** A deeply nested payload is small and has few top-level
members, so neither the byte cap nor the member cap saw it, and canonicalising one walks
it recursively. Where that walk runs out of stack is a property of the runtime, not of
the payload: one implementation refused past roughly five hundred containers on one
release of its language and accepted nine hundred on the next, while two others accepted
every depth tried. Two deployments of the same SDK on different runtimes therefore
disagreed about the same registration. The bound is the same number and the same counting
rule as the schema's own depth cap, it is checked before anything walks the payload, and
the walk that checks it is iterative — a recursive check would hit the very limit it
exists to keep a caller away from.

**A reference chain is bounded on its own axis: 100 hops.** A chain of definitions each
referring to the next is three JSON containers deep however long it is, so the depth cap
never saw it, and it costs one evaluation per link, so the work cap did not either. Both
caps passed a five-hundred-link chain and every SDK called it valid — and then the
recursion each validator performs while resolving that chain exhausted one
implementation's stack outright, raising out of a face documented as returning a verdict.
A third bound is what stops the document being published, rather than asking three
libraries to survive it. A schema describing a business entity chains one or two
references; the deepest chain in a conformance vector that is accepted is eleven. The
refusal is its own verdict, `ref_chain_too_long`, because it is its own rule — a cycle
still reports `ref_cycle`, which is the more specific answer.

**Two more brace rules, found the way the bracket rules were.** A counted repeat MUST
state its first bound, and a `}` outside a bracket expression MUST close one. `a{,5}` is
five literal characters to RE2 and a repeat of zero to five to Python, so both engines
compile it and then disagree about which payloads match, with nothing logged — the silent
kind. An unmatched `}` is a literal to RE2 and Python and a syntax error to ECMA-262 under
the `u` flag, which is the loud kind and exactly what the unmatched `]` rule already
refuses. A literal brace is written `\}`, which the alphabet admits. `{n,}` is unaffected.

*Tooling:* three corrections in the SDKs behind those rules, none of them contract
changes. The dot's line-terminator set is now corrected in the TypeScript port rather
than left to diverge — RE2 and Python exclude only `\n` where ECMA-262 excludes all four
terminators, so `^.$` against a carriage return conformed in two SDKs and violated in the
third; that port gains the same kind of source-level correction the Python `$` rewrite
already uses, which reaches every place its validator compiles a regex. A multi-part
repeat like `a{1,2,3}` was admitted by the TypeScript scanner alone, because
`String.split`'s second argument caps the result and discards the remainder where Go's
`SplitN` and Python's `maxsplit` keep it. And the Python compile face no longer runs out
of interpreter stack on a long flat `$ref` chain: a chain is three containers deep however
long it is, so the depth cap never saw it, and the walk that follows references is now
iterative. The payload face answers with a verdict for an oversized integer and a deeply
nested payload instead of raising, out of an API documented as never raising.

**The payload is bounded too, and the bound names its unit.** A published schema is
applied to `RegisterRequest.registration_data`, and the cost of that is roughly the
schema's own cost multiplied by the elements in the payload — a subschema under `items`
is counted once by the evaluation cap and evaluated once per element. The multiplier was
unbounded. It now is: at most **64 members at the top level**, and at most **16384
bytes**, measured as the payload's **RFC 8785 (JCS) canonical JSON encoding**.

The unit is the load-bearing half. Every other cap in this contract is over bytes a
party actually served; `registration_data` is never served as bytes — it is a `Struct`,
decoded before any consumer sees it — so "16KB" means nothing until an encoding is
chosen, and two implementations choosing privately is the same both-ends disagreement
the schema rules exist to prevent. JCS also pins number formatting, which is not a
detail: a payload carrying `1e300` is seven bytes under one renderer and three hundred
under another. Both bounds are checked before the schema runs, and a payload breaking
either is a malformed request rather than
`REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA`, which names non-conformance to
a published schema and applies only where one is published.

**"No schema published" is defined at the byte level, because it is the enforcement
switch.** Absent means no bytes, or only JSON whitespace — RFC 8259's space, tab,
carriage return and line feed, and no others. Each implementation had been asking its
own language what "blank" means, which is three different questions: U+00A0 and U+3000
are whitespace to some runtimes and not to others, and a decoder that strips a byte
order mark makes a mark followed by a space look like nothing at all. That last one
silently bypassed the rule refusing a mark, so an Exchange whose configured schema was
an empty file saved with one would have run with validation OFF while the other two
implementations called the same bytes malformed. A document that is not empty and not
JSON is malformed, which is a refusal; it is never silence.

**Data is not schema, stated explicitly.** `const`, `enum`, `default` and `examples`
hold arbitrary JSON values whose contents are never read as keywords, so the `$ref` and
`$schema` rules stop at them — a `const` carrying a "$ref" member states a value a
payload may equal, not a reference to resolve. The rules said "every `$ref`" and
"`$schema`, wherever it appears", which an implementor following the text literally would
apply inside those four keywords and refuse schemas every SDK accepts.

**Smaller corrections.** The value MUST be a JSON object: 2020-12 admits a bare boolean
as a schema, but a `Struct` cannot carry one, so the previous rules pinned behaviour for
a document the wire cannot transport. A consumer that refuses a schema MUST skip its
local pre-check rather than decline to send — stated before as a SHOULD in one sentence
and a MUST in another, in the same comment. And the escape list is spelled out character
by character rather than ranged, so a conformance guard can compare the contract's set
with the SDK's in both directions; the previous guard compared five of eight rules
against string literals in its own test file, and dropping an escape from every SDK left
every gate green.

*Tooling:* the shared corpus gains a fourth dimension recording what an admitted pattern
MATCHES, not merely which schemas are admitted. Its absence is why none of the above was
visible: 141 cases across three dimensions all passed while the three implementations
disagreed about payloads. The corpus can now also state a case as raw bytes, because the
encoding rules above are defined over the bytes as served and ill-formed UTF-8 cannot be
written into a JSON string at all. Also corrected in the SDK: the refusal list is clamped by
CHARACTERS rather than bytes or UTF-16 units, which is what `string.max_len` counts and
what stopped one implementation naming a different member than the others; a refusal
carrying a non-ASCII constraint no longer cuts mid-character into a message
`proto.Marshal` rejects; and the JSON Schema library is given an explicitly REFUSING
loader, since leaving it unset does not mean "resolves nothing" — one library's default
reads a reference off local disk and another's fetches it over HTTP.

**The published registration schema states its safety rules as numbers (comment-only,
no wire change).** `AccountRegistration.data_schema` already required a self-contained
schema, forbade resolving a remote `$ref`, and capped the document at 16KB. What it did
not say was how deep a schema may nest, which regex constructs a `pattern` may use, or
whether `format` is asserted — it said only that a consumer SHOULD bound validation time
and recursion depth, and left every implementation to pick. Those are numbers chosen
privately at BOTH ends of one registration: the Exchange enforces the schema and a client
pre-checks against it before signing, so a bound one side invents refuses payloads the
other accepts, which is the disagreement the field exists to prevent. The rules are now
stated. Every `$ref`, `$dynamicRef` and `$recursiveRef` begins with `#`; every `$schema`
in the document names 2020-12, and a document declaring none is read as 2020-12; 16KB as
served; 32 nested JSON containers; and a `pattern` alphabet in which a group opens `(`
or `(?:` and nothing else, the escapes `\1`-`\9`, `\k`, `\p`, `\P`, `\A`, `\z`, `\Z`,
`\Q`, `\E`, `\C`, `\G` and `\K` do not appear, and `[[:` does not appear.

The pattern rule is the one that is not obvious, and it is a MUST rather than a SHOULD
because half of what it excludes fails SILENTLY. Draft 2020-12 `pattern` is ECMA-262 and
the engines implementations run do not agree on it. The loud half is RE2 refusing the
lookaround, atomic groups and backreferences ECMA allows: a schema using them compiles
for one implementation and fails for the next, which is visible and merely annoying. The
quiet half is the reason for the rule — inline flags, Unicode property classes, text
anchors and POSIX bracket names are accepted by one engine and either refused or read
DIFFERENTLY by another, so two conformant validators both compile the pattern and then
disagree about which payloads match it, with nothing to log and no error to catch.
Excluding catastrophic backtracking, the hazard the field comment already named, falls
out of the same rule instead of needing its own. `format`, `contentEncoding` and
`contentMediaType` are pinned as annotations for the same reason at a smaller scale: the
libraries default differently on each, so a schema whose verdict depended on which
library read it had no single answer.

*Tooling:* the rules ship as an executable SDK face rather than as prose alone —
`CompileRegistrationSchema` returns a verdict naming WHICH rule a schema broke, because
the two callers act on it differently: a client that cannot check locally sends anyway
and lets the Exchange decide, while an Exchange that cannot compile its own configured
schema is looking at a misconfigured deployment. A refusal names the offending members as
`RegistrationFieldError` values, built from the failed keyword rather than from the
validating library's own message, which quotes the value that failed — the field forbids
carrying an operator's business data back out, and the obvious implementation leaks. The
reported set is deduplicated by pointer and keyword and sorted before the 64-item cap,
because the three libraries surface duplicates and orderings that differ, and a list
whose length depends on the library is one no shared corpus could pin. A conformance
guard reads the SDK's numbers back out of the shared corpus and fails if the field
comment stops stating them, which is the only drift gate available for a bound that lives
in a comment: `data_schema` is a `Struct`, and no field-level rule can reach inside one.
The depth bound is measured lexically over the raw bytes, BEFORE the document is parsed:
every JSON parser involved descends recursively, and one of them aborts on a deep
document by raising an error that is not a verdict at all, so a check placed after the
parse is reached only for documents harmless enough to parse.

**Every addressed request names its recipient: `exchange` becomes required (breaking,
pre-1.0).** `ResourceQuery` (field 10), `DisputeRequest` (field 10), `RegisterRequest`
(field 3), `GetAccountStatusRequest` (field 2), `DomainVerificationRequest` (field 4),
`DomainVerificationConfirmation` (field 6), `PushResourcesRequest` (field 5),
`RemoveResourcesRequest` (field 4) and `RefreshCatalogRequest` (field 3) gain the field;
`UsageReport.exchange` keeps field 8 and is promoted from `optional`, which is the breaking
half — an absent or empty value used to skip the recipient check entirely, so the check was
opt-in for the caller, and it is now a rejection. The value is the bare host of the
recipient ("exchange.example", "exchange.example:8081"), never an endpoint URL: an endpoint
in the payload would hand the caller the choice of where the next hop dials, which is the
lever the well-known resolver exists to remove. A recipient MUST reject a request whose
`exchange` is not its own domain, with `INVALID_ARGUMENT` and no typed reason — a
mis-addressed request is malformed rather than a domain-level failure.

The signature does not already establish this. It proves the sender signed *the URL it
dialled*, not that the URL was right: the dial target is resolved from a fetched, cached
manifest, so a poisoned or stale resolution redirects the request while every signature
still verifies. The body field states whom the sender meant, independently of that
resolution, and the genuine recipient rejects a request naming someone else. The field is
stamped by whoever authors each request — the agent on the requests it signs, a Broker on
the legs it authors as sender — so it is a statement by that sender, not tamper-evidence
against it. On a verbatim-forwarded path the agent signs its `@target-uri` against the
final recipient's endpoint, not the Broker's. Two messages are exempt and
both absences are load-bearing: `DiscoveryRequest` travels one direct hop and terminates at
the Broker, which authors fresh per-Exchange `ResourceQuery` messages rather than
forwarding it, and the agent cannot name the fan-out set in any case
(`RequestConstraints.exchanges` stays its optional filter); `TransactionRequest` carries no
top-level field because its audience statement is per item.

The pattern is deliberately permissive — one or more labels, an optional port, no scheme,
path, query, userinfo or trailing root dot, and case normalised (both sides lowercase
before comparing). It matches the structural bare-host rule the reference clients already
apply, whose job is to stop a path or query being smuggled into a value that gets
concatenated into a URL, not to check that a name looks like a DNS record. A stricter rule
demanding a dotted name with an alphabetic suffix would reject single-label service hosts
such as `exchange:8081`, which real deployments use.

The same constraint is applied in one pass to the domain-carrying fields that until now
accepted any string at all: `ResourceResponse.exchange`, `RequestConstraints.exchanges`,
`RequestConstraints.preferred_exchanges`, `Requester.domain` and
`AuthorizedExchange.domain`. Tightening them is breaking for the same reason the
`UsageReport` promotion is — a value accepted today becomes a rejection — and it is done
now because one value space with two contracts is the state that produces the bugs.
`Requester.domain` earns it most: a verifier concatenates that value into
`{domain}/.well-known/fora.json` and fetches the result, so a smuggled path or query would
choose WHAT gets fetched, not merely from where.
The port group spells the range out rather than counting digits: `:0` and `:99999` are
refused like any other value that cannot name a listening service, where a `[0-9]{1,5}`
group would have admitted both. And `TransactionDenial.exchange` is documented as a HINT,
not an instruction — it rides in a response, a relayed response passed through an
intermediary, so nothing signs it. A caller MUST check it against a domain it already
trusts for the transaction (the denied item's signed `offer.exchange`, or its own
`RequestConstraints.exchanges`) before acting, because registering hands an operator's
business data and a signed acceptance of that Exchange's terms to whoever answers. A conformance guard walks the descriptor
for every field carrying the shared pattern and asserts each refuses a scheme prefix, a
path or query suffix, userinfo, a malformed port, a trailing root dot and an empty label —
shapes the corpus generator cannot produce, because its bad-string table is shared with the
money and token fields and widening it there would add a mutant to every pattern-ruled
field in the contract.

**`Offer.exchange` is presence-enforced (breaking, pre-1.0).** It was a plain string with no
rule, so an empty value passed. It is the execute-routing target, the value a relaying
Broker groups a mixed batch by, and — because `TransactionRequest` has no top-level
`exchange` — the audience statement of an execute: on receipt an Exchange MUST reject the
request unless EVERY item's `offer.exchange` names its own domain. An empty value is
unroutable, and the swap-protection the offer signature is supposed to provide is vacuous
when the signed bytes carry no recipient at all. Adding the rule does not change any signed
bytes: a protovalidate rule is a field option, not a field.

**Manifest registration becomes a block: `WellKnownManifest.account_registration` (field 30)
replaces `registration_schema` (field 29), and `terms_digest` (field 31) joins `terms_uri`
(breaking, pre-1.0).** The new top-level `AccountRegistration` message carries the same JSON
Schema, now as `data_schema`, with the same publish-is-enforce contract and the same safety
rules. The block exists because registration has more than one publishable facet: field 2 is
left free for a future web mode, a URL to a page where a human completes steps an API call
cannot carry. The precedence rule is fixed now, while it is still cheap: an Exchange
publishing `data_schema` MUST accept registration through the API, and a registration URL is
an additional option an agent may offer its user, never a replacement. Field 29 is not
reused — the manifest already leaves 5 and 6 free after the WBA split, and appending keeps
the numbering legible.

`terms_digest` pins the document served at `terms_uri` in the existing `method:hexdigest`
form, and `RegisterRequest.terms_digest` (field 4) echoes it. A URL alone cannot say WHICH
terms were accepted: its content changes, so after the first revision every earlier
registration points at text that no longer says what was agreed. The echo is covered by the
request signature, and the Exchange records the accepted digest with the account — which
also makes keeping the historical terms documents retrievable the Exchange's obligation, since
a digest identifies a document only while a copy of it still exists. It sits at the top level
rather than inside the block so an Exchange with pass-through registration can still pin its
terms version; a message rule (`well_known_manifest.terms_digest_requires_terms_uri`) keeps
it from being published without the address it pins, mirroring the existing
`license.digest_required_with_uri`. Operators should treat first publication as a
coordinated change: it refuses every client that does not yet echo the value.

**`REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE` (additive, no wire break).** All
four digest cases are now defined rather than only the stale one. Matching echo: the
registration proceeds. Differing echo: refused with the new reason. Absent echo while the
Exchange publishes a digest: refused with the SAME reason, because the caller's remedy is
identical — read the manifest, echo, retry — and a second reason would split one fix in two.
An echo sent to an Exchange that publishes no digest: ignored, and explicitly NOT recorded as
an acceptance, since an Exchange publishing none cannot verify what document the value refers
to and storing it would put an unverifiable claim exactly where the field exists to hold a
verified one. A registering client MUST read the digest from a freshly fetched manifest
rather than a cached copy: a client cannot detect staleness locally — only the Exchange can —
so a warm cache would otherwise make it retry a refused value until the cache expired.
Registration happens once per Exchange, so the extra fetch is cheap.

**`DENIAL_REASON_BILLING_REF_INACTIVE` splits into `DENIAL_REASON_ACCOUNT_INACTIVE` (keeping
its wire number) and `DENIAL_REASON_ACCOUNT_NOT_REGISTERED`, and `TransactionDenial` gains
`exchange` (field 4) (breaking, pre-1.0).** The agent hits this wall at execute, not at
register, and the old single reason conflated two states of the caller with two different
remedies: wait for an operator to activate an account that exists, versus call `Register`
because none does — an action an agent can take unattended. The denial names the Exchange
that produced it, which on a relayed or fanned-out execute need not be one the agent named,
so the agent learns where to register without fetching a manifest to work it out. This
reverses a recorded decision; the reasoning, and why the neighbouring
`DELEGATION_EXPIRED` → `DENIAL_REASON_DELEGATION_INVALID` broadening still stands, are in
`docs/design-history.md` under "DenialReason consolidation".

**Contract text: `registration_data` is documented as business-registration data (no wire
change).** The details an Exchange needs to open a commercial account — legal entity,
address, jurisdiction, tax identifiers. The specific members stay operator-defined; what is
now explicit is that this is not an identity claim, since the caller's identity comes from
the verified request signature and nothing in the payload is trusted as authentication.

*Tooling:* the corpus grows from 208 to 319 cases and `Offer` enters it for the first time,
because a message with no field rules produces no cases at all and `Offer` previously had
none. `WellKnownManifest` gains a seed: auto-fill populates `terms_digest` (it carries a
pattern) but never `terms_uri` (no field rule to trigger on), so the generated baseline
would otherwise violate the new message rule. The reviewable part of that diff is the seed
and the pattern, not the generated output.

**`WellKnownManifest.endpoint` states its host binding (no wire change; conformance-affecting).**
The field said only "Exchange-only. ExchangeService endpoint URL", so nothing told an Exchange
operator that the address it advertises must stay on its own domain. It now does: the endpoint
MUST be on the host AND PORT that SERVE the manifest — not the self-asserted `domain` member
inside it — or on a subdomain of that host on that port, and MUST NOT carry userinfo. The manifest
is only as trustworthy as the host that served it, so an endpoint naming an unrelated host would
let whoever answers for the manifest redirect a signed call to a party the offer's signature never
covered — and a dial-time address guard has no objection to an unrelated PUBLIC host. Another port
is another service, which the party publishing the manifest need not control. The host match is on
a full dot-delimited label boundary, so `evil-a.com` is not a subdomain of `a.com`. A port equal to
the scheme's default and an omitted port are the SAME port, so `https://x`, `https://x:443` and `x`
all match; the scheme itself is not compared, and the default-port folding is scheme-relative so
that it cannot become a scheme check by accident.

**This is the first entry in this changelog that changes what conforms without changing the
wire.** The classifier is deliberately not `(breaking)`: this change moves no field, message, or
encoding, and `buf breaking` reports nothing — while the bare `(breaking)` entries below all mark
a descriptor delta, and the one qualified use ("breaking for the generated clients") names the
audience it breaks. What this change does instead is narrow what a conformant manifest may say.

**Two shapes that are conformant today will be refused after this.** The first is an Exchange
serving its API from a separate DOMAIN — a CDN, a hosting provider. The second is an Exchange on
a separate PORT: a single-domain deployment serving `/.well-known/fora.json` on its default port
and advertising `"endpoint": "https://exchange.example:8443/v1"` is refused, as is the mirror
image (a portless endpoint under a manifest served on `:8443`) and a subdomain reached across
ports. A single domain is therefore no longer sufficient on its own — the authority must match on
both halves.

Remedies, by shape. For a separate domain, front the API under a subdomain of the domain serving
the `fora.json`. For a separate port, either move the API onto the port the manifest is served
from, or serve the manifest from the API's own authority — `https://exchange.example:8443/.well-known/fora.json`
alongside `https://exchange.example:8443/v1`. Writing a scheme's default port out in full is NOT
a mismatch and needs no change.

Both are refused as `ErrEndpointRefused`, which classifies as a FINAL verdict rather than a
transport failure — so a client will not retry its way out of a misconfiguration, and the symptom
is a usage report that never lands rather than one that is slow.

Enforcement moved with the rule: it now runs in the SDK's shared endpoint resolver rather than
in one client, so every consumer of that resolver inherits it without changing a line. Two
consequences for anyone re-pinning. Resolution can now fail with a new `ErrEndpointRefused`
sentinel, which is a VERDICT — the Exchange answered and the answer is unusable — and a
classifier that branches only on the older `ErrNoEndpoint` will drop it into its
transport-failure bucket and retry something that will never succeed; add the new sentinel
alongside. And a Broker that resolves endpoints through this package inherits the rule for the
paths that use it. `gen/` and the website mirror are regenerated; proto comments only.

**Go SDK: the delivery fetch correlates, and the offer-key cache is bounded (additive, no wire
change).** `resolvers.ContentFetchOptions` gained a `RequestID` hook, and `connect.NewClient`
feeds it the same mint the RPC legs read — so `WithRequestIDFunc` now reaches all three legs and
a delivery GET carries `X-Request-ID`. It did not before, and could not: the RPC legs correlate
through a Connect interceptor, which a plain GET never traverses, and there was no seam to add
one. **This changes what arrives at a delivery edge.** An edge that mints its own id when the
header is absent will now see the caller's instead, which is the point — a refused delivery used
to produce two log records under two ids with nothing joining them, on the one leg where
delivery failures are diagnosed. A fetcher built directly with no `RequestID` still sends no
header: this tier mints nothing of its own.

`resolvers.CachedOfferKeyResolver`'s per-domain cache now evicts least-recently-used at a fixed
cap, like the endpoint cache and the per-origin client pool. Its key is a domain off
`Offer.exchange`, so which entries appear is driven by incoming offers, and an entry's expiry is
a freshness check rather than a removal — a stale entry held its slot indefinitely. Reaching it
needed a resolvable host serving a valid directory per domain, so the case was narrow rather
than open, but two sibling structures over the same key space were already bounded and this one
was not.

**Go SDK: the Connect client covers the agent verb set, and its signing knobs are reachable
(additive, no wire change).** `connect.Client` gained `ReportUsage`, `Dispute` and `Fetch`, and
`connect.NewBrokerClient` gained `Resolve` — the client previously exposed `Discover` and
`Execute` alone, so a caller needing any of the rest had to assemble its own from
`forav1connect` plus `core.NewSigningTransport`, which is the duplication the SDK exists to
remove. `Resolve` returns the same fail-closed `{verified, rejected}` split `Discover` does,
through the same `core.Verifier`; `Fetch` performs proof-of-possession on an agent-bound URL and
dials only through the SSRF-guarded client.

Five client options join them, each because a value the tier below already accepted had no way
in: `WithSignWindow` (the RFC 9421 request freshness window — pair it with
`core.MonotonicWindow` when the peer screens replays on `(key id, signature)`, since one-second
timestamp resolution makes two identical requests inside a second sign to the same bytes),
`WithSignatureAgent` (the WBA directory origin the client signs as), `WithProofWindow`,
`WithContentTimeout` and `WithMaxContentBytes`.

`WithSignatureAgent` is worth reading twice if you verify signatures. `signature-agent` is one
of the five REQUIRED covered components, so the header is signed whether or not a value was
supplied — a client that does not set it signs an EMPTY one. A peer that resolves the caller's
key by fetching the WBA directory at that origin then has nothing to resolve and refuses the
call at verification, which surfaces as a 401 from an otherwise healthy Exchange rather than as
anything the routing checks would catch. The value is stamped set-if-absent, so a relay
forwarding an originating agent's request does not overwrite the value that agent's own
signature covers. See `docs/sdk-parity-matrix.md` for the per-language surface.

**SDK (all 3 languages): the registration-failure builder can carry the field errors
(additive, no wire change).** `helpers.RegistrationFailureDetail` (Go),
`registration_failure_detail` (Python) and `registrationFailureDetail` (TS) now accept the
offending `registration_data` members alongside the reason — variadic in Go, an optional
trailing argument in Python and TS, so the six reasons that carry no per-member detail keep
their three-argument call. Without this a service refusing a non-conforming registration had
to build the `ErrorDetail` by hand or mutate the builder's result, defeating the rule these
helpers exist for: one place per language where the ADR-019 envelope is constructed. This is
the only `*Detail` builder that reaches past the reason enum — the schema refusal is useless
without naming what failed, whereas the sibling detail lists
(`TransactionDenial.restriction_mismatches`, `CatalogRejection.rejected_paths`) stay
caller-set after construction.

The shared oracle gains a `registration_failure_field_errors` vector and a `field_errors`
projection, replayed on both halves in all three languages: the construct replays feed the
members back through the builder and assert byte-parity with the Go wire, and the read
replays assert a reader extracts them positionally. The vector carries both member shapes —
a pointer into the payload and the empty root pointer for a whole-object failure. That
second one caught a real divergence: canonical proto-JSON omits an empty scalar, so the wire
form of a root-pointer entry has no `path` key at all, while the generated Pydantic model
defaults `path` to `""` and the generated Zod schema declares `.default("")`, both
materializing a member Go omits. Both builders now map an empty path to unpopulated, the
exact inverse of the read side normalizing an absent path to `""`.

**Registration data becomes schema-enforceable: `WellKnownManifest.registration_schema`
(field 29) + `REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA` (additive, no wire
break).** An Exchange MAY publish, in its `fora.json`, a JSON Schema (draft 2020-12, max
16KB) describing the `registration_data` object it expects on `Register`. Publication and
enforcement are one decision: an Exchange that publishes the schema validates incoming
`registration_data` against it and refuses a non-conforming payload with the new failure
reason; an Exchange that publishes none accepts the payload uninspected and passes it to
its system of record exactly as before, so existing Exchanges stay conformant with no
change. This replaces the former unconditional contract text ("the Exchange passes it
through to its system of record without inspecting it") on the Agent Account Registration
banner and on `RegisterRequest.registration_data`, both of which now defer to the field
that owns the contract rather than restating it.

The field carries normative safety rules, because a consumer reads this schema out of a
third party's manifest: the schema MUST be self-contained and a consumer MUST NOT resolve
a remote `$ref` out of it — doing so would turn every reader into an SSRF vector aimed at
a URL the schema's author chose — and a consumer SHOULD bound validation time and
recursion depth, since draft 2020-12 `pattern` admits regexes with catastrophic
backtracking. The 16KB cap is measured as the UTF-8 bytes of the member as served in
`fora.json`; an oversized schema SHOULD be rejected and its local pre-check skipped rather
than truncated, which leaves the Exchange's own enforcement deciding exactly as it does
when no schema is published. These are prose, not protovalidate rules: the field is a
`Struct`, and no field-level rule can reach inside it.

The refusal names what to fix: `RegistrationFailure` gains
`field_errors` (field 2, ≤64 items) carrying the new top-level `RegistrationFieldError`
`{path, error}`. `path` is an RFC 6901 JSON Pointer relative to `registration_data`
(`"/vat_id"`, `"/address/postal_code"`); the empty string addresses `registration_data`
itself, which is how whole-object failures (`oneOf`, `minProperties`) that belong to no
single member are reported. A free-text pair rather than a closed `kind` enum because
JSON Schema's composite keywords do not attach to any one member and the standard is
extensible by design, so a closed vocabulary could not stay complete. `error` is
developer-facing and NON-authoritative — wording is validator-defined and varies across
Exchanges, clients branch on `reason` — and, like `ErrorDetail.message`, it states the
violated constraint and never the submitted value, so a refusal cannot echo an agent's
business data back over the wire. A machine-readable `kind` can join at field 3 later
without a wire break.

Motivation: an agent integrating the SDK directly signs and sends `Register` itself and
passes through no registration front-end, so a check only a front-end performs is a
suggestion, not a rule — and the agent had nowhere to learn which fields a given Exchange
expects. Both now resolve against the manifest the agent already fetches to find the
Exchange's endpoint.

*Tooling:* `RegistrationFailure` is now seeded in the corpus generator with the new reason
and an empty-path field error, so the cross-language oracle exercises the reason this
change adds and pins the empty-path accept boundary in all three languages; without the
seed the auto-filled baseline picked the first allowed reason and published a
`DOMAIN_NOT_VERIFIED` refusal carrying `field_errors` as valid — the pairing the field
comment rules out. The generator also gained valid-item construction for repeated
**message** fields (seed-or-autofill, mirroring the top-level baseline). `field_errors` is the
contract's first repeated message field carrying its own `repeated.max_items`, and the
generator previously produced only scalar list items.

**The `ver` envelope field states its contract, and the version string gets one owner
(no wire change).** All 29 `ver` fields — 25 in `fora.proto`, 4 in `admin.proto` — now name
the expected value `"1.0"` and the receive-side rule. Before this, 27 of them said only
"Protocol version" or "FORA protocol version", and `DiscoveryResponse.ver` carried no comment
at all — 28 fields from which an integrator could not learn what to stamp. Only
`WellKnownManifest.ver` named the value. The contract: senders MUST stamp `ver` from a single
constant, and receivers treat it as **advisory** — `ver` is not an authenticity or
authorization control and MUST NOT be used as one, a receiver is not required to check it,
and one that does check it MAY reject an unrecognised MAJOR version but MUST NOT reject an
unrecognised MINOR version. Version negotiation, where it is needed, happens out of band via
`WellKnownManifest.protocol_versions_supported`, which is why the in-band field need not be a
rejection gate. `ver` deliberately carries no protovalidate rule: an exact-match rule would
make every peer reject a `"1.1"` message outright, contradicting the
reject-unrecognised-majors policy the manifest already states, and a major-version pattern
would additionally make `ver` structurally required on every message — a wire change no
consumer has asked for. The full reasoning is recorded under "Protocol version" in
`fora.proto`. `WellKnownManifest.ver` keeps its stronger MUST-equal rule and now says why it
differs: it versions the `/.well-known/fora.json` document schema, a namespace deliberately
separate from the RPC envelope and not coupled to it.

**SDK (all 3 languages): `ProtocolVersion` exported (additive, no wire change).** The FORA
`ver` value is now a public SDK symbol — `helpers.ProtocolVersion` in Go, `ProtocolVersion`
in Python and TypeScript — pinned to the shared `wire-constants-vectors.json` oracle
alongside the existing wire constants. It is the FORA protocol version, not the Connect
transport version that `ConnectProtocolVersion` carries. Consumers import it instead of
minting their own constant, so a protocol bump is one edit here plus a re-pin rather than a
literal hunt across every message builder. Two structural guards keep the pair honest: a
conformance guard fails the build when a contract message declares `ver` without documenting
its value and receive-side rule, and an SDK guard fails when a message builder in non-test
`sdk/go` source stamps a bare string literal on a `Ver:` struct-literal field. Both bind what
this project emits; neither can bind a third party, which is the accepted limit of an
advisory field.

**`ResourceEntry` gains typed `resource_mutability` (field 14) (additive, no wire break).**
Publishers submit `resource_mutability` as a typed `ResourceEntry` field instead of inside
`ext`/`ext_critical`; the Exchange reads the typed field, not `ext`. The field is `optional` —
when omitted the Exchange defaults to `STATIC` at Offer build; an explicit
`RESOURCE_MUTABILITY_UNSPECIFIED` is rejected (`not_in:[0]`, matching the Offer-side twin).
Offer-side `ResourceIdentity.resource_mutability` is unchanged.

**SDK parity matrix is now generated, not hand-maintained (no wire change).** The
three overlapping, drift-prone parity docs (`docs/sdk-parity-matrix.md`,
`sdk-api-parity-map.md`, `sdk-parity-audit.md`) collapse to a single generated
artifact, `docs/sdk-parity-matrix.md`, rendered by `scripts/gen-parity-matrix.py` from
the two ground-truth sources CI already enforces against the code: the API surface from
`sdk/parity/symbol-map.json` (gated by `test_api_surface_parity.py`) and the
conformance-vector replay table from the committed corpora (gated by
`test_corpus_replay_completeness.py`). A regenerate-and-diff drift gate runs both in
`scripts/ci-local.sh` and as `sdk/python/tests/test_parity_matrix_generated.py`
(`sdk-types-ci.yml`), so the matrix can no longer drift from the real surface. The two
superseded audit docs are deleted.

**Go SDK: the network-fetching resolvers move `sdk/go/helpers` → `sdk/go/resolvers`
(source move, no wire change).** The IO-bearing key/endpoint resolvers — the
well-known JWKS resolver (`NewWellKnownKeyResolver`), the revocation-aware WBA
directory resolver (`NewWBAKeyResolver`), the `fora.json` endpoint resolver
(`WellKnownEndpointResolver` / `NewWellKnownEndpointResolver` / `WellKnownOptions` /
`ErrNoEndpoint`), and the SSRF-guarded fetch client — now live in the new L2 I/O
package `sdk/go/resolvers`, one tier above the pure, IO-free `sdk/go/helpers`. This
keeps every network dial out of the trust core (enforced by an io-leaf guard).
Migration: import these from `github.com/FORA-Protocol/protocol/sdk/go/resolvers`
instead of `.../sdk/go/helpers`. **No alias shim is provided** — the move is a hard
rename and the downstream app already compiles against the moved layout; consumers
import the resolvers from `sdk/go/resolvers`. The pure `KeyResolver` interface and
the static `NewStaticKeyResolver` stay in `helpers`.

**SDK (all 3 languages): new public faces this cycle (additive, no wire change).**
Document-order active-key selection — `ActiveEd25519Key` /
`ActiveEd25519KeyWithExpiry` and their revocation-aware `…Screened` variants
(`active_ed25519_key*` in Python, `activeEd25519Key*` in TS) — plus a
`CachedOfferKeyResolver`, an injectable Ed25519 verify primitive on
the TS signed-URL verify (`Ed25519Verifier`), and cross-language `ErrorDetail`
readers: Go `AttachErrorDetail` / `AttachDetail` on the server binding, and
`parse_error_detail` / `error_detail_from` (Python) and `parseErrorDetail` /
`errorDetailFrom` (TS) decoders, all pinned to the shared `error-detail-vectors.json`
oracle. The SSRF-guarded transport is now a single env-driven client
(`NewGuardedClientFromEnv` / `guarded_client` / `guardedFetchFromEnv`) governed by
two flags (`SKIP_SSRF`, `ALLOW_INSECURE`). See `docs/sdk-parity-matrix.md` for the
per-language surface.

**Go SDK: `helpers.CanonicalOfferBytes` exported (additive, no wire change).**
The offer-canonical-bytes accessor — RFC 8785 JCS over canonical proto-JSON with
`signature`/`signature_algorithm` cleared, `expires_at` included, byte-identical to
what `SignOffer` signs and `VerifyOffer` verifies — is now a public Go symbol. It
exposes the single canonicalization the signer and verifier already share, so a
caller can persist the signed offer as verbatim, independently re-verifiable
evidence. Python (`canonical_offer_payload`) and TS (`canonicalOfferPayload`) already
expose the equivalent public accessor; this brings the Go surface to parity.

**Go SDK: `helpers.CanonicalAcceptanceBytes` exported (additive, no wire change).**
The acceptance-canonical-bytes accessor — RFC 8785 JCS over canonical proto-JSON of
`AgentAcceptancePayload{offer_sig, requester_id, requester_domain, idempotency_key}`,
byte-identical to what `SignOfferAcceptance` signs and `VerifyOfferAcceptance`
verifies — is now a public Go symbol, completing the pair with
`CanonicalOfferBytes`. A caller can persist an agent's acceptance as verbatim,
independently re-verifiable evidence rather than re-deriving the bytes at
verification time, which would pin an already-signed acceptance to whatever
canonicalization the SDK implements later. Python (`jcs_acceptance_payload`) and TS
(`acceptancePayload`) already expose the equivalent public accessor; this brings the
Go surface to parity.

**Acceptance canonical-form text corrected (documentation only, no wire change).**
`AgentAcceptance` and `AgentAcceptancePayload` still described the RETIRED signing
form — "the deterministic protobuf serialization", "`proto.Marshal(Deterministic:
true)`" — contradicting the canonical-signing block on `Offer.signature` in the same
file, which already states that RFC 8785 JCS over canonical proto-JSON "applies to
the agent offer-acceptance signature". The acceptance text now points at that single
normative definition instead of restating a superseded recipe:
`AgentAcceptancePayload` fixes the field set, `Offer.signature` fixes the byte
layout. Implementations that followed the stale text would have produced
non-verifying signatures. No field, message, or wire change — comments only, with
`gen/` and the website mirror regenerated.

**Python + TS SDK: the hand-built acceptance payload omits every unpopulated field
(bug fix, no wire change).** `jcs_acceptance_payload` (Python) and `acceptancePayload`
(TS) assemble the `AgentAcceptancePayload` JSON object key by key, and omitted only an
empty `requester_domain` — `requester_id` and `idempotency_key` were always emitted.
Go renders the same object through `protojson` with `EmitUnpopulated=false`, which omits
EVERY unpopulated field, so the three SDKs signed different bytes whenever `requester_id`
was empty. That input is wire-valid: `Requester.id` carries no `min_len`. Verification
failed closed on it (a byte mismatch, never a bypass), but the byte-equivalence the
canonical-bytes accessors promise did not hold. Both hand-built faces now drop each empty
string field, and two new vectors in `sdk/go/helpers/testdata/acceptance-vectors.json` —
`empty_requester_id` and `empty_idempotency_key`, one per omittable field left uncovered —
pin the agreement across Go, Python and TS. Without them the omission can be dropped in any
one language with every gate still green. The corpus change is purely additive — the
pre-existing vectors and their signatures are byte-identical, so no already-issued signature
is affected.

**Canonical signing refuses messages carrying unknown fields (normative; Go SDK
behavior change, no wire change).** `Offer.signature` — the single normative definition of
the canonical form — now states the rule, which turns on whether a canonicalizer omits or
preserves content it has no schema for. An OMITTING canonicalizer (proto-JSON emits only
schema-defined fields) cannot reproduce the signed bytes of a message carrying unknown
fields, so it MUST refuse the message rather than emit the reduced bytes, at EVERY depth —
a nested message and each element of a repeated or map field carries its own unknown-field
set. A PRESERVING canonicalizer carries unrecognized members through, reproduces the
signed bytes faithfully, and has nothing to refuse.

Either way an APPENDED field cannot pass, which is the point: the omitting case refuses
the message, and the preserving case renders the appended member into bytes the signer
never covered. Without the refusal the omitting case failed OPEN — an intermediary could
add unknown fields to an already-signed `Offer` **without invalidating its signature**,
smuggling unauthenticated content through a message the recipient treats as verified. That
is what the Go SDK now closes: `helpers.VerifyOffer` surfaces the refusal as
`ErrOfferSignatureInvalid` (a message that arrived carrying extra bytes is a tampered
offer, not an internal fault) wrapping the new `helpers.ErrUnknownFields`, so a caller can
branch on either; `helpers.CanonicalOfferBytes` and `helpers.SignOffer` return
`ErrUnknownFields` directly.

Python (`from_wire_offer`) and TypeScript (`canonicalOfferPayload`) are preserving
canonicalizers and need no change — they already reject the appended-field case on a byte
mismatch. They are NOT expected to reject a message whose signer covered the unknown
member: they reproduce those bytes exactly and verify, which is the forward-compatible
outcome. Go, being an omitting canonicalizer, cannot reconstruct such a message at all and
refuses it; that asymmetry is inherent to the renderer, not new here — before this change
Go rejected the same message on a byte mismatch instead.

No legitimate traffic regresses: an offer signed WITH a field this build cannot render
already failed to verify; the refusal only makes the reason explicit. Extensions are
unaffected — they ride in `ext` / `ext_critical`, defined fields that sit inside the signed
bytes, never undeclared field numbers. One new exported Go symbol (`ErrUnknownFields`,
registered as a Go-idiomatic exclusion in the parity map); no field, message, or wire
change — proto comments only, with `gen/` and the website mirror regenerated.

**`Requester.billing_ref` removed (breaking, pre-1.0).** The caller-written
billing label on `Requester` is gone; the field is deleted outright with no
`reserved` statement — pre-v1 the number returns to the free pool, and
`reserved` becomes the tool for field removals only once v1.0.0 is tagged.
Nothing read it: billing and cost attribution key on the verified caller identity and the
account handle minted at `Register` (`RegisterResponse.billing_ref`), which the
Exchange resolves from the request signature — never from anything the caller
sends. Dropping the field also removes the name collision between the
caller-written label and the authoritative account handle. Binary
wire-compatible: an old caller still sending field 5 has it ignored as an
unknown field. JSON tolerance is a decoder property, not a protocol guarantee:
a decoder that discards unknown fields (as connect-go's default codec does)
ignores a stray `billing_ref` inside `requester`, but a strict `protojson`
decoder rejects the whole message — endpoints that hand-roll `protojson`
decoding should set `DiscardUnknown: true` if they want to keep accepting old
callers. For anyone who used the field: who pays is always the account minted
at `Register`, resolved from the request signature. For a cost-allocation
label, Broker callers use `RequestConstraints.budget_scope` on
`DiscoveryRequest` (a Broker-side spend-tracking key; it does not reach the
Exchange). Direct-to-Exchange callers who need to attach one use
`Requester.ext` — but do not name the key `billing_ref`: it is not an account
handle, and the Exchange will not read it as one.

**Agent account registration + status RPCs (additive).** `ExchangeService`
gains `Register(RegisterRequest) → RegisterResponse` and
`GetAccountStatus(GetAccountStatusRequest) → GetAccountStatusResponse` — the
agent-account front door the Web Bot Auth Registry epic needs. Registration
creates the agent's account with the Exchange and mints `billing_ref`, the
opaque, long-lived, per-Exchange account handle; the caller's identity is
derived from the verified request signature, never from the body, and the
operator-defined business payload rides in a flexible
`RegisterRequest.registration_data` (`google.protobuf.Struct`) that the
Exchange passes through uninspected. A repeat `Register` for the same agent
returns the same `billing_ref` (idempotent by design — no `idempotency_key`).
`GetAccountStatus` is the read-only "is my account active" check; its request
deliberately carries no identifying field. Refused registrations use the
pre-existing `ErrorDetail.registration_failure` / `RegistrationFailureReason`
path, which until now had no RPC front door. Pre-v1 additive change.

**Operator plane: new `fora.admin.v1` package with `AdminService` (additive).**
Two full-replace, idempotent setters for Exchange operators —
`SetTenantFeeRate(SetTenantFeeRateRequest) → SetTenantFeeRateResponse` and
`SetReportingPolicy(SetReportingPolicyRequest) → SetReportingPolicyResponse`.
Each request and response is a thin `{ver, <payload>}` envelope carrying a
required nested payload message: `TenantFeeRate` (fee rate in basis points,
`0 <= fee_rate_bps < 10000`, plus an optional operator note) and
`ReportingPolicy` (required report fields, quantity tolerance `0`–`1`, reporting
window ≤ 1 year). The field-level protovalidate constraints live on the two
payload messages — shared by request and response, so each rule is stated once
and the echoed read-back cannot drift from the write — and flow into the
generated Pydantic/Zod types export and the validation corpus; responses echo
the state as persisted. Deliberately a separate service/package from
`ExchangeService` — the operator plane is not part of the agent contract,
carries no `idempotency_key` (full-replace setters on an unsigned internal
plane have nothing to dedupe) and no `ext`/`ext_critical` maps, and is expected
to be network-isolated by deployments. `SetOfferPrice` and
`SetDeliveryWitnessMode` are deferred to follow-up work. The conformance
tooling (corpus generator, required-fields export, reachability and
doc-coverage guards, Zod/Pydantic types pipeline) now walks both contract
packages, and the corpus generator gained int32/double boundary mutants for the
payload messages' numeric rules.

**Biscuits removed; entitlement mechanism kept for JWT (breaking).** The Biscuit
token format leaves the protocol — JWT is the sole entitlement/capability token
format. The entitlement MECHANISM is unchanged and format-neutral: a capability
token rides a covered header (renamed `X-FORA-Entitlement-Biscuit` →
`X-Entitlement-Token`) whose signature-coverage the verifier enforces without
ever parsing the token, so it holds identically for JWT. Removed only the
biscuit-specific bits: the `token_format` value `"biscuit-v3"` (JWT stays the
default), and `DENIAL_REASON_ENTITLEMENT_STALE_ATTENUATION` (18) — attenuation is
a biscuit concept. The generic entitlement `DenialReason` family (12–17) stays.
Pre-v1 breaking change; `buf breaking` reports the deltas as expected.

**Protocol standardization — unified error/response contract + a Connect RPC for
every role (breaking).** Three threads land together:

- **Unified error model.** A typed `ErrorDetail` (plus its detail messages and
  `DenialReason`/`OfferAbsenceReason` reason enums) is carried out-of-band in the
  transport error; a failed action returns a transport error while a successful
  query — including a "no result" answer — returns in-body. Response messages are
  standardized: `ver` is field 1 on every request and response.
- **A Connect RPC for every role.** Added `BrokerService` with
  `Resolve(DiscoveryRequest) → DiscoveryResponse`, and
  `DiscoveryResponse.absence_reason` (field 16) for "the resolve ran but produced
  nothing licensable".
- **Idempotency.** A required `idempotency_key` (`min_len: 1`, `max_len: 255`,
  deduped per verified RFC 9421 signer) is added to every state-mutating RPC:
  `TransactionRequest`, `UsageReport`, and `DisputeRequest`. Broker `Resolve`
  (`DiscoveryRequest`) is pure discovery — it executes no transaction and takes
  no key.

Also: renamed `PushContent` → `PushResources`; removed `AccessPolicy` /
`ResourceAccessPolicy` and `DELIVERY_METHOD_INLINE`; removed in-body correlation
— the `request_id` fields and the residual `id` fields on
`ResourceQuery`/`DiscoveryRequest` — in favor of an `X-Request-ID` header;
extended `DenialReason` with
values 12–18 and added `OFFER_ABSENCE_REASON_BUDGET_EXCEEDED`. Accepted pre-v1
breaking change; `buf breaking` reports the deltas as expected.

Also: removed the vestigial `TransactionRequest.offer_id` (field 3). It was a
single-offer-era correlation scalar left stranded by the items-only migration —
never authoritative (the Exchange keys binding, billing, and audit off each
item's signature-verified `offer.offer_id`, never this scalar) and read by
nothing. A single-offer transaction is the degenerate one-element `items` list;
offer identity lives inside the signed Offer. Deleted outright with no reserved
(pre-v1); `buf breaking` reports the delta as expected.

**Money as an exact decimal string + field validation as standard constraints (breaking).**

- **Money is a decimal string, not a `double`.** `Pricing.rate`/`unit_cost`,
  `Cost.amount`/`unit_cost`, and `RequestConstraints.max_unit_cost` change from
  `double` to `string` carrying a decimal `string.pattern`
  (`^([0-9]+([.][0-9]+)?)?$`). Binary `double` cannot represent most decimal money
  values exactly, so it drifts and breaks settlement sums; a decimal string is exact
  and supports arbitrary sub-cent precision (e.g. `"0.0001234"`). Accepted pre-v1
  breaking change; `buf breaking` reports the five field-type deltas as expected.
- **Field-level validation moved to standard protovalidate constraints.** 18 of 25
  field-level rules moved from custom CEL to standard constraints (11 enum
  discriminators to `enum.not_in: [0]`, 7 formats to `string.pattern`) so they flow
  through JSON Schema into the generated Pydantic/Zod types export; the 7 genuine
  cross-field rules stay server-authoritative CEL.

**Wire is snake_case proto-JSON (breaking for the generated clients).** The generated
Pydantic/Zod clients and the shared conformance corpus use the proto field names
(snake_case) as the wire form (Go `protojson` with `UseProtoNames`), matching the
`.proto` and the docs. protojson still accepts the camelCase `json_name` on input, but
it is out of contract for the generated clients: they emit and accept snake_case only,
and — because JCS-canonicalized signing is over the JSON field names — snake_case is the
canonical form the signature bytes are computed over. Accepted pre-v1 breaking change.

**Discovery/offer response model (breaking).** The Agent-to-Broker discovery
messages are renamed and the response is re-modeled to carry offers rather than
a single transaction result:

- **Renamed** `FORARequest` to `DiscoveryRequest` and `FORAResponse` to
  `DiscoveryResponse` — the Agent-to-Broker request/response pair (Steps 1 and 6),
  the same pair carried by `BrokerService.Resolve`.
- **Re-modeled** `DiscoveryResponse` as discovery-only. Removed the
  per-transaction fields (`transaction_id`, `billing_id`, `exchange`,
  `resource_title`, `cost`, `delivery_method`, `reporting_obligation`,
  `expires_at`, `broker_fee`, `retrieval_endpoint`, `agent_identity_hash`) —
  these are carried solely by `TransactionResponse` — and added
  `repeated OfferGroup offer_groups`, one group per requested URI, as the sole
  offer representation. A group with no offers carries its `absence_reason`.
- **Added** `Offer.exchange` (field 8): the canonical domain of the issuing
  Exchange and the target for the execute call. It sits inside the signed Offer
  bytes, so a relaying Broker cannot redirect execution to a different Exchange
  without invalidating the signature.

This is an accepted breaking change pre-v1 freeze; `buf breaking` reports the
deltas as expected.

**WBA identity split — keys move to the WBA directory (breaking).** Identity keys
are split out of `fora.json` (`WellKnownManifest`) and into a pure WBA key
directory served at `{domain}/.well-known/http-message-signatures-directory`:

- **Added** `WBAFile` (the WBA directory body) carrying the role's
  attestation/identity JWKs (with their `not_before`/`not_after` bounds per
  RFC 7517 §5) and an optional `revocation_url`; removed `WellKnownManifest`'s
  `public_keys` and `invalidation_url`.
- **Keyed by thumbprint, no `kid`.** The RFC 9421 `keyid` is the key's RFC 7638
  JWK Thumbprint, computed locally; carrying a separate `kid` is gone. The
  attestation `keyid` field now holds the verifier key's thumbprint, resolved
  against the verifier's `WBAFile.keys`.
- **Added** `KeyRevocationList`, the snapshot body served at
  `WBAFile.revocation_url` — the complete set of revoked key thumbprints
  (RFC 7638, base64url-no-pad), polled on a 300s cadence — and the
  `RETRIEVAL_AUTH_FAILURE_REASON_KEYID_MISMATCH` / `_THUMBPRINT_MISMATCH`
  failure reasons.

This is an accepted breaking change pre-v1 freeze; `buf breaking` reports the
deltas as expected.

**CoMP re-baseline to canonical V1 (breaking).** `proto/comp/v1/comp.proto` is
re-aligned to be a 1:1 mirror of IAB Tech Lab Content Monetization Protocols
**CoMP V1** (finalized 2026-04-28,
[`CoMP-1.0.md`](https://github.com/IABTechLab/CoMP/blob/880238e0100b3d0d67d5afd7357a18fc21a97be5/CoMP-1.0.md)). Our
prior snapshot mirrored a pre-final draft. Changes:

- **Removed** the `License` message, the `LicenseUse` enum, and `Package.license`
  — canonical V1 has no separate `License` object.
- **Folded licensing into `Scope`**: added `ause` (new `AllowedUse` enum),
  `pricetype` (new `PriceType` enum), `pricetier`, `unitprice`, `cur`
  (default `"USD"`), `country` (`repeated int32`, ISO-3166 numeric), and
  `licensedur` (days).
- **Added** `Package.reporturl` (usage-reporting URL).
- **Added** per-media taxonomy fields `cattax` (default 9), `cat`
  (`repeated int32`), and `language` (`repeated int32`, ISO-639-1) to `Text`,
  `Video`, `Image`, and `Audio`.
- **Removed** the FORA-invented fields that were not part of canonical CoMP:
  `Text.authority`, `Text.originality`, `Image.alt`, `Image.caption`,
  `Video/Image/Audio.c2pa`, and `Retrieval.ratelmt`.
- **Added** `RETRIEVAL_AUTH_OTHER = 4` to the retrieval auth enum.

The request-side model (`AISystem`/`AISystemUse`, `Function`, `SubFunction`,
`AuthMethod`, `ScopeType`, `ContentType`) is unchanged. This is an accepted
breaking change pre-v1 freeze of the CoMP profile; `buf breaking` reports the
deltas as expected.

### Release contents

**Universal Licensing Core.** A resource carries `repeated LicenseTerm terms`
— the same shape at ingestion (`ResourceEntry.terms`) and emission
(`Offer.terms`) — replacing the hard-coded default pricing and the removed
`AccessRestrictions` / `Offer.restrictions`. A `LicenseTerm` bundles `License`
(`uri`, `id`, `name`, `immutable`), `TermSemantics` (`ENUMERATED` vs
`REFERENCE_ONLY`), `Restriction`s (function / geography / user-type axes),
`Quota`s, `Obligation`s (`scope_license`, `detail`), `Pricing` (required on
every term), Biscuit `scopes`, and `part_label`. `PricingModel` is the closed
charging structure (`FREE`, `PER_UNIT`, `FLAT`); the metering basis moved to
the open `Pricing.unit` vocabulary; `Pricing.metering` was added and
`revshare` / `REVENUE_SHARE` removed (settlement is off-protocol). Every
required enum carries `_UNSPECIFIED = 0` and is rejected if unset
(`PricingMetering` is the deliberate exception — `ONLINE = 0` is its real
default). The Offer JWS signs the entire canonical Offer, so `terms` and
`pricing` are tamper-evident.

**Proto-native vocabulary.** Every open vocabulary axis is defined in the proto
and tooled by buf — no side-car JSON registry. The `(fora.v1.vocab)` field
option (`FieldOptions` extension 50001) carries the registered bare tokens on
`Pricing.unit` and `Quota.metric`; the `(fora.v1.vocab_enum)` enum-value option
(`EnumValueOptions` extension 50002, both in `fora/v1/vocab.proto`) carries the
function / geography / user-type tokens on the `RESTRICTION_KIND_FUNCTION` /
`RESTRICTION_KIND_GEOGRAPHY` / `RESTRICTION_KIND_USER_TYPE` enum values. The
`protoc-gen-foravocab` buf plugin reads both options structurally and emits
typed Go constants, `All`, and `IsRegistered` per axis under `gen/go/vocab/`
(`pricingunits`, `quotametrics`, `functiontokens`, `geographytokens`,
`usertypes`). Geography registers only the non-ISO specials (`*`, `EU`, `EEA`);
ISO 3166-1 alpha-2 codes are structural. `protovalidate` carries the structural
field CELs (`Pricing.unit`, `Quota.metric`) and message-level CEL on `Pricing`
(`PER_UNIT ⇒ unit`, `FREE ⇒ rate 0`). Adding a token edits the option list only
— no message-shape change.

**Billing reference, not entitlement.** `Requester.license_id` was renamed
`billing_ref` and recast as an opaque handle into the operator's billing system.
It is not an authorization token: identity is the RFC 9421 request signature and
entitlement is scopes plus `Delegation`, so access is never gated on
`billing_ref`.

**DenialReason consolidation.** `INVALID_LICENSE` and `EXPIRED_LICENSE` collapse
into a single `DENIAL_REASON_BILLING_REF_INACTIVE`, and `DELEGATION_EXPIRED`
broadens to `DENIAL_REASON_DELEGATION_INVALID` (expiry is one of several ways a
token fails to authorize). The enum is contiguous, with no reused numbers.

**Delegation-claims profile.** The delegation token stays opaque on the wire;
`token_format` only selects the verifier. FORA defines a small registered
claim/fact vocabulary mapping the same named concepts across JWT registered
claims and Biscuit facts, so scope / expiry / spend caps mean the same thing to
every verifier regardless of format. All vocabulary entries are optional except
the mandatory subject/holder binding: the key that signs the RFC 9421 request
MUST equal the token's holder key, which is what makes a leaked token not
bearer-usable. Issuer-specific facts use a `vendor:` namespace; `fora_`-prefixed
names are reserved. Binding constraints are fail-closed (binding by default)
unless explicitly marked advisory.

**JWT-default delegation (holder-of-key).** `token_format` defaults to `"jwt"`:
the delegation token is a holder-bound JWT, with the grant tied to a key via the
RFC 7800 `cnf` claim (`cnf.jkt` = RFC 7638 thumbprint) and possession proven by
the RFC 9421 request signature. Delegation is a chain of `cnf`-linked JWTs
(each child signed by the key its parent named, scope ⊆ parent), verified offline
under the issuer's key alone. `"biscuit-v3"` remains a permitted **optional**
alternative for deployments wanting deep multi-hop in-place attenuation. This
makes JWT — already ubiquitous — the one delegation technology implementers must
support; Biscuit is opt-in.

**Scope matching.** One normative algorithm applies protocol-wide: scopes are
`":"`-separated segments; a grant covers a requirement only if each granted
segment equals the required segment or is `"*"`, with a terminal `"*"` matching
all remaining segments. There is no implicit prefix match and a grant narrower
than the requirement does not cover it. The same rule applies to
requester/`Delegation` scopes and to `LicenseTerm.scopes`; the Biscuit Datalog
authorizer is a conformant implementation that MUST produce identical results.

The reasoning behind the major design decisions is recorded in
[`docs/design-history.md`](../docs/design-history.md).
