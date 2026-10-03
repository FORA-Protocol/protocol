// The FORA client: the six verbs an agent needs, over the Connect-unary JSON transport.
//
// TS port of sdk/go/connect (Client + BrokerClient). The transports differ — Go keeps
// full connect-go, this speaks the unary JSON form — but that is an implementation
// difference, not an API difference: the verbs carry the same names and the same
// contracts, and the fail-closed offer verification is the SAME Verifier the core ships,
// never a second verification path.
//
// It owns NO state. The signer, the keys, the dialing seam, the endpoint resolver and the
// verification policy are all injected.

import type {
	DiscoveryResult,
	OfferGroupResult,
	VerifiedOffer,
	Verifier,
} from "../core/verifier.ts";
import type { z } from "zod";

import { clockWindow } from "../core/window.ts";
import { fromWireOffer } from "../core/wire-canon.ts";
import {
  signOfferAcceptance,
  signRequestAcceptance,
  ACCEPTANCE_SIGNATURE_ALGORITHM,
} from "../src/acceptance.ts";
import { registrationFailureDetail } from "../src/errordetail.ts";
import { checkAudience, hostOf } from "../src/hosts.ts";
import { generateIdempotencyKey } from "../src/idempotency.ts";
import { ProtocolVersion } from "../src/wire.ts";
import { thumbprint } from "../src/thumbprint.ts";
import {
	BrokerTransactionResponseSchema,
	DiscoveryRequestSchema,
	DiscoveryResponseSchema,
	DisputeRequestSchema,
	DisputeResponseSchema,
	GetAccountStatusRequestSchema,
	GetAccountStatusResponseSchema,
	PushResourcesRequestSchema,
	PushResourcesResponseSchema,
	RefreshCatalogRequestSchema,
	RefreshCatalogResponseSchema,
	RegisterRequestSchema,
	RegisterResponseSchema,
	RemoveResourcesRequestSchema,
	RemoveResourcesResponseSchema,
	ResourceQuerySchema,
	ResourceResponseSchema,
	TransactionRequestSchema,
	TransactionResponseSchema,
	UsageReportSchema,
	UsageReportResponseSchema,
} from "../../../gen/ts/wire/schemas.ts";
import { type Content, fetchContent } from "./content.ts";
import { type Delivery, verifyDelivery } from "./delivery.ts";
import { malformed, notSent, ForaCallError } from "./errors.ts";
import { checkRegistrationData } from "../src/regschema.ts";
import {
	ExchangeNotPermitted,
	ManifestNotExchange,
	ManifestUnusable,
	type RegistrationRequirements,
} from "../resolvers/index.ts";
import { call, resolve, type CallOptions, type ClientOptions, type Resolved } from "./options.ts";
import { RawBody, rawExchange, rawObject } from "./raw.ts";
import { isInvalidHostRefusal, vetExchangeEndpoint } from "./route.ts";
import {
	isRecord,
	requireRecipient,
	stampDiscovery,
	stampEnvelope,
	stampVer,
	stringField,
} from "./stamp.ts";
import { parseMessage, validateRequest } from "./transport.ts";

const EXCHANGE_SERVICE = "fora.v1.ExchangeService";
const BROKER_SERVICE = "fora.v1.BrokerService";
const CATALOG_SERVICE = "fora.v1.CatalogService";

/** How long a delivery-fetch proof stays valid, in seconds.
 *
 * Short on purpose, and deliberately NOT the signed URL's own expiry, which can be hours:
 * the proof covers only the method and the URL, so for as long as the window is open
 * anyone who observes the request can repeat it. */
export const DEFAULT_PROOF_WINDOW_SEC = 30;

/**
 * The response types, inferred from the generated schemas rather than restated.
 *
 * A verb returning `Record<string, unknown>` hands a caller no help exactly where it is
 * needed: `transaction_id`, `report_id` and the retrieval endpoint are the links of the
 * dispute chain, and every read of one was an unchecked index. Python's verbs return the
 * generated models, so the two faces were the same verb names over materially different
 * ergonomics.
 */
export type TransactionResponse = z.infer<typeof TransactionResponseSchema>;
/** The Broker's combined answer to a relayed purchase: one result item per request item
 * in request order (an Exchange's refusal of its whole sub-request rides on each affected
 * item as `refusal`), one outcome per Exchange contacted, and per-currency totals. */
export type BrokerTransactionResponse = z.infer<typeof BrokerTransactionResponseSchema>;
/** The answer to a usage report; carries the `report_id` a dispute is filed against. */
export type UsageReportResponse = z.infer<typeof UsageReportResponseSchema>;
/** The answer to a dispute. */
export type DisputeResponse = z.infer<typeof DisputeResponseSchema>;

/**
 * A purchase's answer together with the delivery URLs this client verified.
 *
 * `deliveries` has one entry per result item, in item order: the verified binding of the
 * item's retrieval_endpoint, or undefined for an item that carries none (denied,
 * refused, or not delivered by signed URL). It is defined non-enumerable, so the object
 * still serializes as the wire message; it is empty when nothing was verified — a raw
 * call, or `deliveryVerification: "off"`.
 */
export type ExecuteResult = TransactionResponse & {
	readonly deliveries: readonly (Delivery | undefined)[];
};
/** The Broker's combined answer with the delivery URLs this client verified; see
 * {@link ExecuteResult}. */
export type BrokerExecuteResult = BrokerTransactionResponse & {
	readonly deliveries: readonly (Delivery | undefined)[];
};

/**
 * The request types a verb accepts, inferred from the generated schemas: the shape a
 * caller writes, with every defaulted field optional. Each verb also takes a plain record
 * (the same object, untyped) and a RawBody. There is no `toWire`: an object of one of
 * these types already is the JSON the SDK sends.
 */
export type ResourceQuery = z.input<typeof ResourceQuerySchema>;
export type DiscoveryRequest = z.input<typeof DiscoveryRequestSchema>;
export type UsageReport = z.input<typeof UsageReportSchema>;
export type DisputeRequest = z.input<typeof DisputeRequestSchema>;
export type RegisterRequest = z.input<typeof RegisterRequestSchema>;
export type GetAccountStatusRequest = z.input<typeof GetAccountStatusRequestSchema>;
export type PushResourcesRequest = z.input<typeof PushResourcesRequestSchema>;
export type RemoveResourcesRequest = z.input<typeof RemoveResourcesRequestSchema>;
export type RefreshCatalogRequest = z.input<typeof RefreshCatalogRequestSchema>;

/** A request a verb accepts: its typed shape, the same object as a plain record, or a
 * RawBody sent as given. */
type Request<T> = T | Record<string, unknown> | RawBody;

/** Where fetch verifies a delivery URL. */
export interface FetchOptions {
	/** The Exchange that issued the URL. When set, the URL is verified against that
	 * Exchange's URL-signing key before anything is sent. */
	exchange?: string;
}

/** The agent-facing Exchange client. */
export interface Client {
	discover(query: Request<ResourceQuery>): Promise<DiscoveryResult>;
	/** Buy one offer, or several issued by ONE Exchange, in one request. Every retrieval
	 * URL in the answer is verified before it is returned. */
	execute(
		offer: VerifiedOffer | readonly VerifiedOffer[] | RawBody,
		opts?: CallOptions,
	): Promise<ExecuteResult>;
	reportUsage(report: Request<UsageReport>, opts?: CallOptions): Promise<UsageReportResponse>;
	dispute(request: Request<DisputeRequest>, opts?: CallOptions): Promise<DisputeResponse>;
	/** Create this agent's account at the Exchange the request names. Takes no
	 * CallOptions: the message carries no idempotency key, because registering again
	 * returns the same account handle. */
	register(request: Request<RegisterRequest>): Promise<RegisterResponse>;
	/** Read whether this agent's account at the named Exchange is active. An empty
	 * `billing_ref` is a NORMAL answer — no account there yet. */
	getAccountStatus(request: Request<GetAccountStatusRequest>): Promise<GetAccountStatusResponse>;
	/** Fetch what a delivery URL names. Given a Delivery, or a URL and the Exchange that
	 * issued it, the URL is verified first and the result carries the binding. */
	fetch(signedURL: string | Delivery, opts?: FetchOptions): Promise<Content>;
}

/** The Broker client. */
export interface BrokerClient {
	resolve(request: Request<DiscoveryRequest>): Promise<DiscoveryResult>;
	/** Buy offers from any number of Exchanges in one call; the Broker re-packages the
	 * purchase into one sub-request per Exchange (BrokerService.ExecuteTransaction).
	 * Every retrieval URL in the answer is verified against the Exchange that issued it. */
	execute(
		offers: readonly VerifiedOffer[] | RawBody,
		opts?: CallOptions,
	): Promise<BrokerExecuteResult>;
}

/**
 * createClient builds a client against baseURL — the agent's HOME Exchange, the one its
 * account lives on.
 *
 * Discovery and purchase go to baseURL. A usage report or a dispute does NOT: those reach
 * the Exchange that ISSUED the offer, resolved per call from that Exchange's own
 * manifest, over a separately guarded transport.
 */
export function createClient(baseURL: string, options: ClientOptions = {}): Client {
	const r = resolve(options);
	return {
		discover: (query) => discover(r, baseURL, query),
		execute: (offer, opts) => execute(r, baseURL, offer, opts ?? {}),
		reportUsage: (report, opts) => reportUsage(r, report, opts ?? {}),
		dispute: (request, opts) => dispute(r, request, opts ?? {}),
		register: (request) => register(r, request),
		getAccountStatus: (request) => getAccountStatus(r, request),
		fetch: (signedURL, opts) => fetchVerb(r, signedURL, opts ?? {}),
	};
}

/**
 * createBrokerClient builds a client against a Broker's base URL.
 *
 * A SEPARATE constructor rather than a second surface on the exchange client because the
 * two speak to different parties. A Broker is not an Exchange: it fans a query out across
 * Exchanges it knows and relays back what they offered, so its address is the Broker's,
 * not any Exchange's. Hanging both off one base URL would mean one of the two was always
 * pointed at the wrong party.
 *
 * It takes the same options, but only the ones a discovery call has any use for do
 * anything, and two need care. A single pinned offer key is the wrong shape here: Broker
 * fan-out returns offers minted by different Exchanges, so inject a resolver that
 * resolves each issuing Exchange's own key. And `requester` is REQUIRED, not optional: a
 * Broker resolves the calling agent from it and declines a request naming none, so
 * resolve and execute refuse locally rather than spending a round trip to be told.
 * execute also needs `signer` and `signatureAgent`: a relayed purchase carries
 * acceptances signed with the agent's key, and a Broker refuses a requester.domain that
 * does not name the directory the request is signed from.
 */
export function createBrokerClient(
	baseURL: string,
	options: ClientOptions = {},
): BrokerClient {
	const r = resolve(options);
	return {
		resolve: (request) => brokerResolve(r, baseURL, request),
		execute: (offers, opts) => brokerExecute(r, baseURL, offers, opts ?? {}),
	};
}

// ---------------------------------------------------------------------------
// The verbs
// ---------------------------------------------------------------------------

/**
 * discover issues DiscoverResources and returns one group per requested URI, each
 * carrying the fail-closed {verified, rejected} split.
 *
 * EVERY returned offer is verified against the exchange offer-signing key before it is
 * handed back. Neither an unverifiable nor a doctored offer is silently dropped — it
 * lands in `rejected` with a reason. A URI the responder GROUPED and left empty keeps its
 * group, carrying the typed reason, so a refusal is an answer rather than an absence.
 *
 * The query is CLONED before `ver` and the requester are filled in, so the message the
 * caller built stays untouched — it crossed a module boundary as an argument, not as a
 * buffer. Both are filled only when EMPTY: a value the caller set is theirs.
 *
 * `exchange` is NOT among them: the caller MUST set it to the bare host of the Exchange
 * being queried, because the contract requires every addressed request to name its
 * recipient. It is left to the caller rather than derived from the base URL on purpose —
 * the point of the field is to state whom the SENDER meant, and a value the transport
 * filled in from the address it was already dialling would restate the dial target
 * instead of checking it.
 */
async function discover(
	r: Resolved,
	baseURL: string,
	query: Request<ResourceQuery>,
): Promise<DiscoveryResult> {
	const op = "discover";
	let sent: Record<string, unknown>;
	let message: unknown;
	if (query instanceof RawBody) {
		// Only to attribute a flat answer to the URI asked about; never checked.
		sent = rawObject(query) ?? {};
		message = query;
	} else {
		sent = stampDiscovery(op, query, r.opts.requester);
		validateRequest(op, sent, ResourceQuerySchema, r.opts.validation ?? "strict");
		message = sent;
	}
	const raw = await call(
		r,
		op,
		baseURL,
		EXCHANGE_SERVICE,
		"DiscoverResources",
		message,
		false,
		"fora.v1.ResourceResponse",
	);
	const msg = parseMessage<Record<string, unknown>>(op, raw, ResourceResponseSchema);
	return {
		// The offers are read from the RAW answer, not the parsed one. A schema parse is
		// the GATE — it proves the answer is well formed and that its field names are
		// canonical — but it also NORMALIZES: Zod fills every declared default, which adds
		// keys the signer never covered and would make a genuine offer fail verification.
		// A signature covers what the responder sent.
		groups: await discoveredGroups(r.verifier, sent, isRecord(raw) ? raw : {}),
		exchange: typeof msg["exchange"] === "string" ? msg["exchange"] : "",
		...(isRecord(msg["rate_limit"]) ? { rateLimit: msg["rate_limit"] } : {}),
	};
}

/**
 * discoveredGroups folds a ResourceResponse's two offer representations into the per-URI
 * form.
 *
 * The message carries a grouped list AND a flat one, and the contract says a responder
 * populating groups SHOULD leave the flat list empty "to avoid ambiguity" — but a real
 * Exchange populates both, the flat list mirroring the grouped offers as a single-URI
 * convenience. So the two are read as ALTERNATIVES, never concatenated: concatenating
 * would double every offer against such a server, and deduplicating would silently accept
 * a responder whose two lists disagree, which is precisely the ambiguity the contract
 * forbids.
 *
 * Groups win when present. The flat fallback becomes a single group; it carries no URI of
 * its own, so it takes the query's only URI when the query named exactly one, and none
 * otherwise — the SDK does not invent an attribution the wire did not make.
 */
async function discoveredGroups(
	verifier: Verifier,
	query: Record<string, unknown>,
	msg: Record<string, unknown>,
): Promise<OfferGroupResult[]> {
	const groups = msg["offer_groups"];
	if (Array.isArray(groups) && groups.length > 0) {
		return verifier.sortGroups(groups.map(canonicalizeGroupOffers));
	}
	const flat = msg["offers"];
	if (!Array.isArray(flat) || flat.length === 0) return [];
	const uris = query["uris"];
	const uri =
		Array.isArray(uris) && uris.length === 1 && typeof uris[0] === "string"
			? uris[0]
			: "";
	return [
		{ uri, result: await verifier.sort(canonicalize(flat)), restrictionFilters: [] },
	];
}

/**
 * canonicalize inverts the wire emission of each offer before it is verified.
 *
 * A FORA Exchange serves proto-JSON with EmitUnpopulated, so a wire offer carries
 * zero-valued scalars, empty repeateds, null messages and *_UNSPECIFIED enums that the
 * SIGNED form does not — the signature covers the omit-unpopulated rendering. Verifying
 * the wire object as-is would fail every genuine offer, which is a fail-closed direction
 * but the wrong answer. fromWireOffer is the schema-aware inversion, byte-parity-pinned
 * against the Go oracle; a field newer than its pinned schema is kept verbatim, so an
 * offer this SDK cannot reconstruct still verifies FALSE rather than being waved through.
 *
 * The verified value is therefore the CANONICAL offer, which is what execute reflects
 * back: the Exchange verifies the presented bytes and re-renders them canonically either
 * way, so reflecting the canonical form is the same statement with none of the wire
 * emission's noise.
 */
function canonicalize(offers: unknown[]): unknown[] {
	return offers.map((offer) =>
		isRecord(offer) ? fromWireOffer(offer) : offer,
	);
}

/** canonicalizeGroupOffers applies the inversion to one group's offers, leaving the
 * group's own URI and typed reasons untouched. */
function canonicalizeGroupOffers(group: unknown): unknown {
	if (!isRecord(group)) return group;
	const offers = group["offers"];
	if (!Array.isArray(offers)) return group;
	return { ...group, offers: canonicalize(offers) };
}

/**
 * resolve runs discovery through the Broker, which fans out to the Exchanges it knows and
 * returns one group per requested URI.
 *
 * Every returned offer is verified through the SAME fail-closed Verifier discover uses —
 * not a second verification path. Broker-relayed offers are precisely the case that rule
 * exists for: the Broker forwards offers it did not mint, and an unverified relay can
 * steer an agent's selection with doctored terms that only fail later, at the purchase.
 *
 * A resolve that finds nothing is a SUCCESSFUL answer carrying a typed reason, not a
 * failure: the whole-call reason lands on the result and the per-URI ones on each group.
 *
 * It carries no idempotency key. Pure discovery buys nothing and changes nothing, so
 * there is nothing for a server to deduplicate — the request message has no such field.
 */
async function brokerResolve(
	r: Resolved,
	baseURL: string,
	request: Request<DiscoveryRequest>,
): Promise<DiscoveryResult> {
	const op = "resolve";
	let message: unknown = request;
	if (!(request instanceof RawBody)) {
		const sent = stampDiscovery(op, request, r.opts.requester);
		// Refused locally rather than sent: a Broker resolves the calling agent from the
		// requester and declines a request that names none, so this is a verdict the
		// client already knows, and naming the remedy beats relaying "requester required"
		// from a round trip away. execute refuses the same way.
		if (sent["requester"] === undefined) {
			throw malformed(
				op,
				new Error("no requester configured; a Broker resolves who is asking"),
			);
		}
		validateRequest(op, sent, DiscoveryRequestSchema, r.opts.validation ?? "strict");
		message = sent;
	}
	const raw = await call(
		r,
		op,
		baseURL,
		BROKER_SERVICE,
		"Resolve",
		message,
		false,
		"fora.v1.DiscoveryResponse",
	);
	const msg = parseMessage<Record<string, unknown>>(op, raw, DiscoveryResponseSchema);
	// Read from the RAW answer for the same reason discover does: a parse normalizes, and
	// a signature covers what the responder sent.
	const groups = isRecord(raw) ? raw["offer_groups"] : undefined;
	const absence = msg["absence_reason"];
	return {
		groups: await r.verifier.sortGroups(
			Array.isArray(groups) ? groups.map(canonicalizeGroupOffers) : [],
		),
		...(typeof absence === "string" ? { absenceReason: absence } : {}),
		// A DiscoveryResponse names no single Exchange and carries no rate-limit signal —
		// each offer carries its own issuing domain instead.
		exchange: "",
	};
}

/**
 * execute commits to one VERIFIED offer, or several issued by ONE Exchange, and returns
 * the transaction response.
 *
 * It accepts ONLY VerifiedOffer values — the brand is module-private to the core, so
 * passing a rejected offer or a raw parsed one is a COMPILE error. A per-call idempotency
 * key is minted fresh unless one is pinned. execute builds the whole TransactionRequest,
 * so it also stamps `ver` from ProtocolVersion — the caller neither supplies nor
 * overrides it.
 *
 * Items-only wire shape: a single offer is the degenerate 1-element items list. Several
 * offers must all name the same Exchange: a direct purchase goes to one Exchange, and an
 * Exchange refuses a request carrying an item addressed to anyone else, so a mixed set is
 * refused locally as malformed. Buying across Exchanges in one call is
 * BrokerClient.execute.
 */
async function execute(
	r: Resolved,
	baseURL: string,
	offer: VerifiedOffer | readonly VerifiedOffer[] | RawBody,
	opts: CallOptions,
): Promise<ExecuteResult> {
	const op = "execute";
	if (offer instanceof RawBody) {
		const raw = await call(r, op, baseURL, EXCHANGE_SERVICE, "ExecuteTransaction", offer, false, "fora.v1.TransactionResponse");
		return withDeliveries(parseMessage<TransactionResponse>(op, raw, TransactionResponseSchema), []);
	}
	const offers: readonly VerifiedOffer[] = isOfferList(offer) ? offer : [offer];
	requireOneExchange(op, offers);
	const request = await buildTransaction(r, op, offers, opts);
	validateRequest(op, request, TransactionRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		baseURL,
		EXCHANGE_SERVICE,
		"ExecuteTransaction",
		request,
		false,
		"fora.v1.TransactionResponse",
	);
	const msg = parseMessage<TransactionResponse>(op, raw, TransactionResponseSchema);
	const items = (msg.items ?? []) as ResultItem[];
	return withDeliveries(
		msg,
		await verifyDeliveries(r, op, offers, items, () => msg.agent_identity_hash ?? ""),
	);
}

/**
 * brokerExecute buys VERIFIED offers through the Broker in one call, however many
 * Exchanges issued them (BrokerService.ExecuteTransaction).
 *
 * The client builds the same TransactionRequest a direct purchase sends — every item with
 * the agent's detached AgentAcceptance, and one AgentRequestAcceptance over the complete
 * ordered set — and stamps `ver` and the configured requester. The Broker re-packages it:
 * it groups the items by each offer's exchange, sends one sub-request per Exchange signed
 * with its own key, and combines the answers. The acceptances travel in each sub-request
 * body, so every Exchange still verifies the agent's consent. The Broker forwards the
 * idempotency key unchanged to every Exchange, so a retry with the same key is answered
 * from each Exchange's stored result.
 *
 * Refused locally, with nothing sent: no requester, no offers, an unsigned offer, an
 * offer that names no exchange, and a requester.domain that is not the host of the
 * directory this client signs as (all malformed); no signer (not_signable). The last
 * mirrors the Broker's own check, which it refuses with request_auth_failure
 * SIGNATURE_INVALID.
 *
 * An Exchange that refused the Broker's whole sub-request is NOT an error here: the call
 * succeeds, and each affected item carries the refusal in `refusal` while the other
 * Exchanges' items come back unchanged. Only the Broker's own refusals throw, and then
 * nothing was bought.
 */
async function brokerExecute(
	r: Resolved,
	baseURL: string,
	offers: readonly VerifiedOffer[] | RawBody,
	opts: CallOptions,
): Promise<BrokerExecuteResult> {
	const op = "broker execute";
	if (offers instanceof RawBody) {
		const raw = await call(r, op, baseURL, BROKER_SERVICE, "ExecuteTransaction", offers, false, "fora.v1.BrokerTransactionResponse");
		return withDeliveries(
			parseMessage<BrokerTransactionResponse>(op, raw, BrokerTransactionResponseSchema),
			[],
		);
	}
	if (r.opts.requester === undefined) {
		throw malformed(
			op,
			new Error("no requester configured; a Broker resolves who is buying"),
		);
	}
	requireRoutable(op, offers);
	requireRequesterIsSigner(op, r.opts.requester, r.opts.signatureAgent ?? "");
	const request = await buildTransaction(r, op, offers, opts);
	validateRequest(op, request, TransactionRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		baseURL,
		BROKER_SERVICE,
		"ExecuteTransaction",
		request,
		false,
		"fora.v1.BrokerTransactionResponse",
	);
	const msg = parseMessage<BrokerTransactionResponse>(op, raw, BrokerTransactionResponseSchema);
	const items = (msg.items ?? []) as ResultItem[];
	// Each Exchange bound its own items, and states the binding on its own outcome.
	const outcomes = (msg.exchanges ?? []) as { exchange?: string; agent_identity_hash?: string }[];
	return withDeliveries(
		msg,
		await verifyDeliveries(r, op, offers, items, (exchange) =>
			outcomes.find((o) => o.exchange === exchange)?.agent_identity_hash ?? "",
		),
	);
}

/** The result-item members delivery verification reads. */
interface ResultItem {
	offer_id?: string;
	transaction_id?: string;
	retrieval_endpoint?: string;
	denial_reason?: string;
	refusal?: unknown;
}

/**
 * verifyDeliveries checks every retrieval_endpoint in a purchase answer against the
 * Exchange that issued the matching offer, and returns the verified bindings in item
 * order. Item i answers request item i; when the counts differ the item is matched to its
 * offer by offer_id instead. `stated` gives the agent_identity_hash the answer stated for
 * an Exchange.
 */
async function verifyDeliveries(
	r: Resolved,
	op: string,
	offers: readonly VerifiedOffer[],
	items: readonly ResultItem[],
	stated: (exchange: string) => string,
): Promise<(Delivery | undefined)[]> {
	if ((r.opts.deliveryVerification ?? "strict") === "off") return [];
	const agent = await agentThumbprint(r);
	const now = r.opts.now ?? (() => Date.now());
	const out: (Delivery | undefined)[] = [];
	for (const [i, item] of items.entries()) {
		const url = item.retrieval_endpoint;
		if (typeof url !== "string" || url === "" || item.denial_reason !== undefined || item.refusal !== undefined) {
			out.push(undefined);
			continue;
		}
		const matched =
			offers.length === items.length
				? offers[i]
				: offers.find((o) => stringField(offerRecord(o), "offer_id") === item.offer_id);
		const exchange = matched === undefined ? "" : stringField(offerRecord(matched), "exchange");
		out.push(
			await verifyDelivery(url, {
				op,
				subject: `item ${i} (transaction ${JSON.stringify(item.transaction_id ?? "")})`,
				exchange,
				agent,
				stated: stated(exchange),
				keys: r.deliveryKeys,
				now,
			}),
		);
	}
	return out;
}

/** This agent's identity as a delivery URL binds it: the thumbprint of the configured
 * public key, or the signer's keyid, which the protocol defines as that thumbprint. */
async function agentThumbprint(r: Resolved): Promise<string | undefined> {
	if (r.opts.agentPublicKey !== undefined) {
		const raw = new Uint8Array(await crypto.subtle.exportKey("raw", r.opts.agentPublicKey));
		return thumbprint(raw);
	}
	return r.opts.signer?.keyid;
}

/** Attach the verified bindings without making them part of the wire message. */
function withDeliveries<T extends object>(
	msg: T,
	deliveries: (Delivery | undefined)[],
): T & { readonly deliveries: readonly (Delivery | undefined)[] } {
	Object.defineProperty(msg, "deliveries", {
		value: Object.freeze(deliveries),
		enumerable: false,
	});
	return msg as T & { readonly deliveries: readonly (Delivery | undefined)[] };
}

function isOfferList(
	offer: VerifiedOffer | readonly VerifiedOffer[],
): offer is readonly VerifiedOffer[] {
	return Array.isArray(offer);
}

function offerRecord(offer: VerifiedOffer): Record<string, unknown> {
	return offer.offer as Record<string, unknown>;
}

/**
 * buildTransaction assembles and signs the TransactionRequest for a purchase. The verbs
 * that buy — execute and BrokerClient.execute — differ in which offers they admit and
 * where the request goes, never in how the request is built, so the building lives here
 * once.
 *
 * Each item reflects its signed Offer back exactly as received at discovery and carries
 * the agent's detached acceptance of that one offer. The request-level acceptance over
 * the complete ordered item set is attached when every offer names its Exchange; an item
 * without one cannot appear in that payload, which requires a recipient per item.
 *
 * Every acceptance covers the offer, the requester and the idempotency key, so a retry
 * that pins the same key reproduces byte-identical acceptance bytes. That is the
 * deliberate-replay semantic, not an accident.
 */
async function buildTransaction(
	r: Resolved,
	op: string,
	offers: readonly VerifiedOffer[],
	opts: CallOptions,
): Promise<Record<string, unknown>> {
	if (r.opts.requester === undefined) {
		throw malformed(
			op,
			new Error("no requester configured; an Exchange resolves who is buying from it"),
		);
	}
	if (r.opts.signer === undefined) {
		// not_signable, matching what fetch answers for the same missing holder: a caller
		// branching on the kind sees one condition under one class, whichever verb met it
		// first.
		throw new ForaCallError({
			kind: "not_signable",
			op,
			cause: new Error(
				"no signer configured; a purchase carries a detached acceptance signed with the agent's own key",
			),
		});
	}
	if (offers.length === 0) {
		throw malformed(op, new Error("no offers to buy"));
	}
	const wires = offers.map(offerRecord);
	const requestItems = wires.map((wire, i) => {
		const offerSig = typeof wire["signature"] === "string" ? wire["signature"] : "";
		// An acceptance floating free of a concrete offer is meaningless, and an unsigned
		// offer is reachable here: verification "off" and RejectedOffer.unsafe() both mint
		// a VerifiedOffer without a signature check.
		if (offerSig === "") {
			throw malformed(op, new Error(`cannot accept an unsigned offer (item ${i})`));
		}
		return { offerSig, exchange: stringField(wire, "exchange") };
	});
	// `??` would take an EMPTY pinned key as a value and send it, which fails the
	// message's own min(1). An empty string is the absence of a key, as Go and Python
	// both read it.
	const key =
		opts.idempotencyKey !== undefined && opts.idempotencyKey !== ""
			? opts.idempotencyKey
			: generateIdempotencyKey();
	const requester = r.opts.requester;
	const requesterId = stringField(requester, "id");
	const requesterDomain = stringField(requester, "domain");
	const privKey = r.opts.signer.privKey;
	let signatures: string[];
	let requestSignature: string | undefined;
	try {
		signatures = await Promise.all(
			requestItems.map((item) =>
				signOfferAcceptance(
					{
						offerSig: item.offerSig,
						requesterId,
						requesterDomain,
						idempotencyKey: key,
					},
					privKey,
				),
			),
		);
		if (requestItems.every((item) => item.exchange !== "")) {
			requestSignature = await signRequestAcceptance(
				{ items: requestItems, requesterId, requesterDomain, idempotencyKey: key },
				privKey,
			);
		}
	} catch (cause) {
		throw new ForaCallError({ kind: "not_signable", op, cause });
	}
	// The authoritative identity of each item is the reflected offer; the optional
	// top-level offer_id correlation scalar is left unset.
	return {
		ver: ProtocolVersion,
		idempotency_key: key,
		requester,
		items: wires.map((wire, i) => ({
			offer: wire,
			agent_acceptance: {
				signature: signatures[i],
				signature_algorithm: ACCEPTANCE_SIGNATURE_ALGORITHM,
			},
		})),
		...(requestSignature === undefined
			? {}
			: {
					agent_request_acceptance: {
						payload: {
							items: requestItems.map((item) => ({
								offer_sig: item.offerSig,
								exchange: item.exchange,
							})),
							requester_id: requesterId,
							requester_domain: requesterDomain,
							idempotency_key: key,
						},
						signature: requestSignature,
						signature_algorithm: ACCEPTANCE_SIGNATURE_ALGORITHM,
					},
				}),
	};
}

/** requireOneExchange refuses a direct purchase whose offers were issued by more than one
 * Exchange: that Exchange would refuse the item addressed to someone else. */
function requireOneExchange(op: string, offers: readonly VerifiedOffer[]): void {
	const first = offers[0];
	if (first === undefined) return;
	const want = stringField(offerRecord(first), "exchange");
	offers.forEach((offer, i) => {
		const got = stringField(offerRecord(offer), "exchange");
		if (got !== want) {
			throw malformed(
				op,
				new Error(
					`item ${i} is issued by ${JSON.stringify(got)} and item 0 by ${JSON.stringify(want)}; ` +
						"a direct purchase goes to one Exchange (buy across Exchanges with BrokerClient.execute)",
				),
			);
		}
	});
}

/** requireRoutable refuses a relayed purchase carrying an offer that names no Exchange: a
 * Broker routes each item to the Exchange its offer names. */
function requireRoutable(op: string, offers: readonly VerifiedOffer[]): void {
	offers.forEach((offer, i) => {
		if (stringField(offerRecord(offer), "exchange") === "") {
			throw malformed(
				op,
				new Error(
					`item ${i} names no exchange; a Broker routes each item to the Exchange its offer names`,
				),
			);
		}
	});
}

/**
 * requireRequesterIsSigner refuses a request whose requester.domain is not the host of the
 * WBA directory this client signs as. A Broker verifies the agent's signature against the
 * key it resolves from the covered Signature-Agent directory and requires
 * requester.domain to name that same directory, because every Exchange it relays to
 * resolves the agent's acceptance keys from requester.domain. It refuses a mismatch with
 * request_auth_failure SIGNATURE_INVALID; this client refuses it first, before sending.
 *
 * The comparison is the recipient-identity rule: exact, case-folded, an explicit :443
 * the same as no port. An unset Signature-Agent names no directory, so it fails too.
 */
function requireRequesterIsSigner(
	op: string,
	requester: Record<string, unknown>,
	signatureAgent: string,
): void {
	if (signatureAgent === "") {
		throw malformed(
			op,
			new Error(
				"no signatureAgent configured; a Broker checks that requester.domain names the " +
					"directory the request is signed from",
			),
		);
	}
	let host: string;
	try {
		host = hostOf(signatureAgent);
	} catch (cause) {
		throw malformed(op, cause);
	}
	let verdict: string;
	try {
		verdict = checkAudience(host, stringField(requester, "domain"));
	} catch (cause) {
		throw malformed(op, cause);
	}
	if (verdict !== "accepted") {
		throw malformed(
			op,
			new Error(
				`requester.domain ${JSON.stringify(stringField(requester, "domain"))} is not ` +
					`${JSON.stringify(host)}, the host of the directory this client signs as; ` +
					"a Broker refuses the request (request_auth_failure SIGNATURE_INVALID)",
			),
		);
	}
}

/**
 * reportUsage files a usage report with the Exchange that ISSUED the offer — never
 * through a Broker, and never to an address from configuration.
 *
 * The destination comes off the report itself: `exchange` carries the offer's signed
 * exchange domain, and the endpoint is then resolved from that Exchange's own well-known
 * manifest. Reading it off the message rather than taking it as an argument is what makes
 * the rule structural — there is no parameter a configured origin could be passed as, so
 * it cannot become the default by anyone's convenience.
 *
 * The report is CLONED before `ver` and the idempotency key are stamped, so the message
 * the caller built stays untouched. The key identifies the REPORT, not the attempt: a
 * fresh one is minted only when the caller supplied none, because an application that
 * mints its own key for its own dedup would otherwise have it silently discarded and see
 * every retry counted as a second report.
 */
async function reportUsage(
	r: Resolved,
	report: Request<UsageReport>,
	opts: CallOptions,
): Promise<UsageReportResponse> {
	const op = "report usage";
	if (report instanceof RawBody) {
		return routedRaw(r, op, "ReportUsage", report, "fora.v1.UsageReportResponse", UsageReportResponseSchema);
	}
	const sent = stampEnvelope(op, report, opts);
	// The address is vetted BEFORE the schema: an unroutable recipient is a refusal to
	// send, which is a different verdict from a message the server would reject, and the
	// caller acts on them differently.
	const endpoint = await vetExchangeEndpoint(
		r.opts.endpointResolver,
		stringField(sent, "exchange"),
		op,
	);
	validateRequest(op, sent, UsageReportSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		endpoint,
		EXCHANGE_SERVICE,
		"ReportUsage",
		sent,
		true,
		"fora.v1.UsageReportResponse",
	);
	return parseMessage(op, raw, UsageReportResponseSchema);
}

/**
 * dispute files a dispute with the Exchange that issued the offer, over the same vetted
 * routing a usage report takes.
 *
 * The destination comes off the request, exactly as it does for a usage report. A
 * parameter is something a configured origin can be passed as; reading the destination
 * off the signed message leaves no such seam.
 *
 * The dispute chain is a structural invariant: an agent must have filed a usage report
 * and received a report_id before it can dispute, so `report_id` and `transaction_id`
 * both name links the Exchange already holds.
 */
async function dispute(
	r: Resolved,
	request: Request<DisputeRequest>,
	opts: CallOptions,
): Promise<DisputeResponse> {
	const op = "dispute";
	if (request instanceof RawBody) {
		return routedRaw(r, op, "DisputeTransaction", request, "fora.v1.DisputeResponse", DisputeResponseSchema);
	}
	const sent = stampEnvelope(op, request, opts);
	const endpoint = await vetExchangeEndpoint(
		r.opts.endpointResolver,
		stringField(sent, "exchange"),
		op,
	);
	validateRequest(op, sent, DisputeRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(
		r,
		op,
		endpoint,
		EXCHANGE_SERVICE,
		"DisputeTransaction",
		sent,
		true,
		"fora.v1.DisputeResponse",
	);
	return parseMessage(op, raw, DisputeResponseSchema);
}

// ---------------------------------------------------------------------------
// The account-setup verbs
//
// They route like a usage report, not like discovery. An account is per-Exchange,
// and which Exchange is the agent's choice PER CALL: a target routinely arrives at
// runtime — a denial names where to register — rather than from configuration. So
// the destination is read off the request's own `exchange` field and resolved
// through that Exchange's own manifest, over the guarded leg.
//
// Neither message carries an idempotency key, so neither verb takes CallOptions.
// ---------------------------------------------------------------------------

/** The ErrorDetail domain for a refusal THIS CLIENT computed, before anything was
 * sent. It names the failing surface, which here is the client's own tier: the
 * Exchange never saw the request, so naming it would attribute a local verdict to a
 * party that reached none. The naming rule the value follows — a Service suffix for
 * an RPC service that exists in the contract, a bare noun for a tier that does not —
 * is recorded on the Go oracle's edgeErrorDomain, beside EDGE_ERROR_DOMAIN's twin. */
const CLIENT_ERROR_DOMAIN = "fora.v1.Client";

/**
 * register creates the calling agent's account at the Exchange the request names.
 *
 * The caller's identity is the request SIGNATURE. Nothing in the message says who is
 * registering, and the business payload is not an identity claim.
 *
 * Four bounds on `registration_data` are checked before anything is signed, in the order
 * the contract fixes, because a limit that exists to stop work belongs before the work it
 * would stop — including before the manifest read.
 *
 * `terms_digest` is filled only when the caller left it ABSENT, from a freshly fetched
 * manifest, and the payload is pre-checked against the schema that manifest publishes. A
 * caller that sets the field is managing its own requirements and gets neither.
 *
 * A schema this SDK refuses never becomes a local veto: refusing locally and declining to
 * send would turn a rule about reading a third party's document into a denial of service
 * against the caller's own user, so an unusable schema is skipped and the Exchange
 * decides. A usable schema the payload fails is the pre-check working, and that request is
 * refused here with the offending members named.
 */
async function register(
	r: Resolved,
	request: Request<RegisterRequest>,
): Promise<RegisterResponse> {
	const op = "register";
	if (request instanceof RawBody) {
		return routedRaw(r, op, "Register", request, "fora.v1.RegisterResponse", RegisterResponseSchema);
	}
	const sent = stampVer(op, request);
	requireRecipient(op, stringField(sent, "exchange"));
	// Narrowed rather than asserted. The bounds below are defined over an OBJECT, and
	// Object.keys on a string answers its character indices — so a cast let a string
	// payload be refused as "too many members", a verdict about a bound it never
	// reached and a member count it does not have. Go cannot express the state at all
	// (the field is a Struct) and Python narrows the same way, so this is the port
	// that had to say so.
	const verdict = checkRegistrationData(
		isRecord(sent.registration_data) ? sent.registration_data : null,
	);
	if (verdict !== "accepted") {
		throw malformed(op, new Error(`registration_data: ${verdict}`));
	}
	if (sent.terms_digest === undefined || sent.terms_digest === null) {
		await applyRegistrationRequirements(r, op, sent);
	}
	const endpoint = await vetExchangeEndpoint(
		r.opts.endpointResolver,
		stringField(sent, "exchange"),
		op,
	);
	validateRequest(op, sent, RegisterRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(r, op, endpoint, EXCHANGE_SERVICE, "Register", sent, true, "fora.v1.RegisterResponse");
	return parseMessage(op, raw, RegisterResponseSchema);
}

/**
 * getAccountStatus reports whether the calling agent's account at the named Exchange is
 * active.
 *
 * The request carries no field identifying the caller — the Exchange resolves the account
 * from the verified signature — so `exchange` is the only thing that says which account is
 * being asked about. An empty `billing_ref` in the answer is a NORMAL answer: no account
 * there yet.
 *
 * Safe to call in a loop. The request has no varying field, but every request signature
 * carries a fresh RFC 9421 nonce, so two calls to the same Exchange inside one wall-clock
 * second still sign different bytes and a peer screening replays on (key id, signature)
 * accepts both.
 */
async function getAccountStatus(
	r: Resolved,
	request: Request<GetAccountStatusRequest>,
): Promise<GetAccountStatusResponse> {
	const op = "get account status";
	if (request instanceof RawBody) {
		return routedRaw(r, op, "GetAccountStatus", request, "fora.v1.GetAccountStatusResponse", GetAccountStatusResponseSchema);
	}
	const sent = stampVer(op, request);
	requireRecipient(op, stringField(sent, "exchange"));
	const endpoint = await vetExchangeEndpoint(
		r.opts.endpointResolver,
		stringField(sent, "exchange"),
		op,
	);
	validateRequest(op, sent, GetAccountStatusRequestSchema, r.opts.validation ?? "strict");
	const raw = await call(r, op, endpoint, EXCHANGE_SERVICE, "GetAccountStatus", sent, true, "fora.v1.GetAccountStatusResponse");
	return parseMessage(op, raw, GetAccountStatusResponseSchema);
}

/**
 * routedRaw sends a RawBody on a verb that routes by the request's `exchange`. The
 * recipient is still read from the body and resolved through that Exchange's own
 * manifest, over the guarded leg: where a signed request goes is not part of the message
 * raw mode leaves alone. A body naming no usable recipient is refused as not_sent.
 */
async function routedRaw<T>(
	r: Resolved,
	op: string,
	method: string,
	body: RawBody,
	response: string,
	schema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
): Promise<T> {
	const endpoint = await vetExchangeEndpoint(r.opts.endpointResolver, rawExchange(body), op);
	const raw = await call(r, op, endpoint, EXCHANGE_SERVICE, method, body, true, response);
	return parseMessage<T>(op, raw, schema);
}

/**
 * applyRegistrationRequirements reads what the Exchange asks of a registration and applies
 * it to the request being built.
 *
 * A failed READ refuses the registration rather than sending without a digest. Guessing
 * here is not the cautious option: an Exchange that publishes a digest refuses a
 * registration that omits one, so sending anyway trades a local failure the caller can act
 * on for a remote one it cannot.
 */
async function applyRegistrationRequirements(
	r: Resolved,
	op: string,
	sent: Record<string, unknown>,
): Promise<void> {
	let reqs: RegistrationRequirements;
	try {
		reqs = await r.requirements.resolveRegistrationRequirements(
			stringField(sent, "exchange"),
		);
	} catch (err) {
		// A value this deployment or the Exchange refused is FINAL; anything else is a
		// transport failure worth retrying. The same split the routing tier makes, and
		// the same causes: a value that is not a host will not become one on a later
		// attempt either, and a document that arrived unusable arrives unusable again.
		// The SDK's own reader throws all three itself — the middle two for the document
		// it was handed, and ManifestUnusable for a version it cannot classify — and an
		// INJECTED reader stricter than it reaches the same three. Only the invalid-host
		// refusal is normally out of reach here, because the verb's own recipient check
		// runs that rule first. Classifying any of them as retryable would have a caller
		// retry a verdict.
		if (
			err instanceof ExchangeNotPermitted ||
			err instanceof ManifestNotExchange ||
			err instanceof ManifestUnusable ||
			isInvalidHostRefusal(err)
		) {
			throw notSent(op, err);
		}
		throw new ForaCallError({ kind: "unreachable", op, cause: err });
	}
	if (reqs.termsDigest !== undefined) {
		sent.terms_digest = reqs.termsDigest;
	}
	// A null validator means "nothing to enforce", which is the behaviour the contract
	// requires both when the Exchange publishes no schema and when it publishes one this
	// SDK refused. One branch, deliberately.
	const fails = reqs.schema?.validate(sent.registration_data ?? {}) ?? [];
	if (fails.length > 0) {
		// An empty path addresses the whole object, which is how a missing required
		// member and every other whole-object failure is reported. Rendering a bare
		// ": ..." there would read as a member with no name.
		const named = fails.map((f) => (f.path ? `${f.path}: ${f.error}` : f.error)).join("; ");
		// The failures travel as a typed detail, not only as prose. An Exchange attaches
		// this same list when it refuses the same payload, so a consumer that renders one
		// refusal renders both, and nothing has to parse the members back out of a
		// sentence.
		throw new ForaCallError({
			kind: "malformed",
			op,
			cause: new Error(
				`registration_data does not match the schema ${stringField(sent, "exchange")} publishes: ${named}`,
			),
			detail: registrationFailureDetail(
				CLIENT_ERROR_DOMAIN,
				"registration_data does not match the published data_schema",
				"REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA",
				fails,
			),
		});
	}
}

/**
 * fetch retrieves the content a signed delivery URL names, presenting proof of possession
 * of the agent key that URL is bound to.
 *
 * This is the LOW-TIER fetch: follow one signed URL, present the key, return the bytes. It
 * does not discover, select, buy or report — that orchestration is a separate, higher
 * tier.
 *
 * Given a Delivery — what execute verified — or a URL plus the Exchange that issued it,
 * the URL is verified before anything is sent: its signature against that Exchange's
 * URL-signing key, its binding to this agent, its expiry. A URL that does not verify is
 * refused as `malformed` with a retrieval_auth_failure detail, and the returned Content
 * carries the verified binding. A bare URL with no Exchange is fetched as given, with no
 * binding, as it is under `deliveryVerification: "off"`.
 *
 * It takes no CallOptions: a fetch is a GET against an already-issued URL, so there is no
 * idempotency key to pin — nothing on this path mutates state.
 */
async function fetchVerb(
	r: Resolved,
	target: string | Delivery,
	opts: FetchOptions,
): Promise<Content> {
	const op = "fetch content";
	const signedURL = typeof target === "string" ? target : target.url;
	const exchange = typeof target === "string" ? opts.exchange : target.exchange;
	if (r.opts.signer === undefined) {
		throw new ForaCallError({
			kind: "not_signable",
			op,
			cause: new Error(
				"no signer configured; a bound fetch proves possession of the agent key — " +
					"the same key the request is signed with",
			),
		});
	}
	if (r.opts.agentPublicKey === undefined) {
		throw new ForaCallError({
			kind: "not_signable",
			op,
			cause: new Error(
				"no agent public key configured; a bound fetch presents it alongside the " +
					"proof, and a non-extractable signing key cannot yield it",
			),
		});
	}
	let binding: Delivery | undefined;
	if (exchange !== undefined && (r.opts.deliveryVerification ?? "strict") === "strict") {
		binding = await verifyDelivery(signedURL, {
			op,
			subject: "the delivery URL",
			exchange,
			agent: await agentThumbprint(r),
			stated: undefined,
			keys: r.deliveryKeys,
			now: r.opts.now ?? (() => Date.now()),
		});
	}
	const content = await fetchContent(signedURL, {
		// One private key, held by the signer. The public half rides alongside because
		// custody keeps the private one and a CryptoKey cannot be asked for its pair.
		keyPair: { privateKey: r.opts.signer.privKey, publicKey: r.opts.agentPublicKey },
		// The proof window is the client's, not the signer's. core/sign.ts defaults to the
		// 10-minute TTL a server-side proof uses; a delivery proof is minted for one GET
		// and wants the short window instead, so the default is set here rather than
		// inherited.
		window: r.opts.proofWindow ?? clockWindow(() => Date.now() / 1000, DEFAULT_PROOF_WINDOW_SEC),
		...(r.opts.contentTimeoutMs !== undefined
			? { timeoutMs: r.opts.contentTimeoutMs }
			: {}),
		...(r.opts.maxContentBytes !== undefined
			? { maxBytes: r.opts.maxContentBytes }
			: {}),
		...(r.opts.requestId !== undefined ? { requestId: r.opts.requestId } : {}),
	});
	return binding === undefined ? content : { ...content, binding };
}

// ---------------------------------------------------------------------------
// Envelope stamping
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The agent's account: ExchangeService
// ---------------------------------------------------------------------------

/** The answer to a registration: the account handle this Exchange minted, and the terms
 * revision it recorded against it. */
export type RegisterResponse = z.infer<typeof RegisterResponseSchema>;

/** The answer to an account-status read. An empty account handle is a NORMAL answer: it
 * means this agent holds no account at that Exchange yet. */
export type GetAccountStatusResponse = z.infer<typeof GetAccountStatusResponseSchema>;

// ---------------------------------------------------------------------------
// The publisher's verbs: CatalogService
// ---------------------------------------------------------------------------

/** The answer to a catalog push: accepted/rejected counts and the warnings the accepted terms carry. */
export type PushResourcesResponse = z.infer<typeof PushResourcesResponseSchema>;
/** The answer to a catalog removal. */
export type RemoveResourcesResponse = z.infer<typeof RemoveResourcesResponseSchema>;
/** The answer to a catalog refresh request. */
export type RefreshCatalogResponse = z.infer<typeof RefreshCatalogResponseSchema>;

/** The publisher-facing Catalog client. */
export interface CatalogClient {
	pushResources(request: Request<PushResourcesRequest>): Promise<PushResourcesResponse>;
	removeResources(request: Request<RemoveResourcesRequest>): Promise<RemoveResourcesResponse>;
	refreshCatalog(request: Request<RefreshCatalogRequest>): Promise<RefreshCatalogResponse>;
}

/**
 * createCatalogClient builds a client against an Exchange's CATALOG endpoint — the
 * publisher role's face: push, remove and refresh the catalog entries a publisher, or a
 * contributor it authorised, supplies.
 *
 * A SEPARATE constructor, as the Broker's is, and for a related reason: the address is a
 * different one. An Exchange advertises CatalogService at its manifest's
 * `catalog_endpoint`, distinct from the ExchangeService endpoint the agent client dials,
 * and the caller is a different party holding a different key — a contributor's, named
 * by `caller_id`, never an agent's. Hanging the catalog verbs on the agent client would
 * carry every agent-only holder into a client that uses none of them, and point one of
 * the two roles at the wrong address.
 *
 * The publisher chose the Exchange, so the origin is configuration and the leg runs on
 * the plain send — the posture of the agent client's home Exchange, not of its
 * offer-derived leg. It takes the same options; `signer` is what a real push needs (an
 * Exchange refuses an unsigned catalog call), and the agent-only ones — the requester,
 * the agent key, the offer-key resolver, the endpoint resolver, the guarded send — are
 * inert here rather than errors, so one option set can build every face.
 */
export function createCatalogClient(baseURL: string, options: ClientOptions = {}): CatalogClient {
	const r = resolve(options);
	return {
		pushResources: (request) =>
			catalogCall(r, baseURL, "push resources", "PushResources", PushResourcesRequestSchema, PushResourcesResponseSchema, request, "fora.v1.PushResourcesResponse"),
		removeResources: (request) =>
			catalogCall(r, baseURL, "remove resources", "RemoveResources", RemoveResourcesRequestSchema, RemoveResourcesResponseSchema, request, "fora.v1.RemoveResourcesResponse"),
		refreshCatalog: (request) =>
			catalogCall(r, baseURL, "refresh catalog", "RefreshCatalog", RefreshCatalogRequestSchema, RefreshCatalogResponseSchema, request, "fora.v1.RefreshCatalogResponse"),
	};
}

/**
 * catalogCall is the one shape all three catalog verbs share. The request is CLONED
 * before `ver` is stamped (fill-when-empty; the caller's value is theirs); no
 * idempotency key is stamped, because the messages carry none — a catalog push is an
 * upsert and naturally idempotent, so a key there would be ceremony. `exchange` is the
 * caller's to set, the bare domain of the Exchange the call is meant for; a request
 * that names none, or names something that is not a bare domain, is refused before
 * anything is signed or sent — a refusal to send, the verdict a report with no
 * routable recipient gets, not a malformed message.
 */
async function catalogCall<T>(
	r: Resolved,
	baseURL: string,
	op: string,
	method: string,
	requestSchema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
	responseSchema: { safeParse: (v: unknown) => { success: boolean; data?: unknown } },
	request: Record<string, unknown> | RawBody,
	response: string,
): Promise<T> {
	let message: unknown = request;
	if (!(request instanceof RawBody)) {
		const sent = stampVer(op, request);
		requireRecipient(op, stringField(sent, "exchange"));
		validateRequest(op, sent, requestSchema, r.opts.validation ?? "strict");
		message = sent;
	}
	const raw = await call(r, op, baseURL, CATALOG_SERVICE, method, message, false, response);
	return parseMessage<T>(op, raw, responseSchema);
}

export { ForaCallError } from "./errors.ts";
export type { CallErrorKind } from "./errors.ts";
export type { Content } from "./content.ts";
export type { Delivery, DeliveryKeyResolver } from "./delivery.ts";
export type { EndpointResolver } from "./route.ts";
export type { CallOptions, ClientOptions, RegistrationRequirementsReader } from "./options.ts";
export { RawBody } from "./raw.ts";
export type {
	BeforeSign,
	UnaryRequest,
	UnaryResponse,
	UnarySend,
	Validation,
} from "./transport.ts";
export {
	DEFAULT_CALL_TIMEOUT_MS,
	DEFAULT_MAX_RPC_READ_BYTES,
	NOT_CANONICAL_WIRE_NAMING,
} from "./transport.ts";
export {
	DEFAULT_CONTENT_TIMEOUT_MS,
	DEFAULT_MAX_CONTENT_BYTES,
} from "./content.ts";
