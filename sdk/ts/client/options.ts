// What every client face is built from: the options, the resolved holders, and the one
// call every verb reaches the wire through. Shared by the exchange, Broker, catalog and
// admin faces so none of them can drift in how it signs, correlates, bounds, verifies or
// decodes.

import { createVerifier, type Mode, type Verifier } from "../core/verifier.ts";
import type { Window } from "../core/window.ts";
import {
	createWellKnownRequirementsReader,
	type RegistrationRequirements,
} from "../resolvers/index.ts";
import type { EndpointResolver } from "./route.ts";
import { createUnarySend } from "./send.ts";
import { refuseUnlessStrict } from "./strict.ts";
import {
	DEFAULT_CALL_TIMEOUT_MS,
	DEFAULT_MAX_RPC_READ_BYTES,
	unaryCall,
	type BeforeSign,
	type CallSigner,
	type UnarySend,
	type Validation,
} from "./transport.ts";

/** Reports what one Exchange asks of a registration.
 *
 * An interface for the same two reasons the endpoint seam is one: a test can drive a
 * registration without standing up a manifest server, and this module has no way to
 * accept a terms digest or a schema from configuration — the only way to skip the read
 * is to set `terms_digest` on the request, where the signature covers it.
 *
 * An implementation MUST NOT serve the answer from a cache. The contract requires a
 * registering client to read the digest from a freshly fetched manifest, so a cached one
 * breaks the rule the field exists to record.
 *
 * An implementation's FAILURE decides how a caller is told to react, so it is part of the
 * contract rather than an implementation detail. A failure that is a VERDICT — the domain
 * is unusable, the deployment excludes it, the document served is not an Exchange's, or it
 * is one this reader cannot use — MUST throw the resolver tier's ExchangeNotPermitted,
 * ManifestNotExchange or ManifestUnusable, or the invalid-host error raised for a
 * value that is not a bare domain;
 * those surface as `not_sent`, which tells the caller not to retry. Anything else is read
 * as a transport failure and reported as `unreachable`, i.e. worth retrying. An
 * implementation that throws a bare error for a refusal therefore has its final answer
 * retried indefinitely.
 *
 * ManifestUnusable is the seam's word for "the document arrived and cannot be read for
 * what a registration owes". The SDK's own reader reaches it for a document version it
 * cannot classify, and treats its other two disappointments as absence or as a transport
 * failure. An implementation STRICTER than that one — validating the whole document, or
 * applying a narrower version rule — reaches for the same word, and would otherwise hold
 * a final answer this seam reported as transient.
 *
 * Note which class that is NOT. ManifestVersionRefused belongs to the endpoint seam and
 * is absent from the list above on purpose: the two vocabularies are disjoint, one
 * answering whether an endpoint may be dialled and this one whether a document can be
 * read. An implementation that throws the endpoint class for a version refusal here has
 * its verdict read as a transport failure. */
export interface RegistrationRequirementsReader {
	resolveRegistrationRequirements(exchange: string): Promise<RegistrationRequirements>;
}

/** Everything a client is built from. Every field is injected; the client owns none of it. */
export interface ClientOptions {
	/** The RFC 9421 request signer. Custody stays with the application — the SDK receives
	 * a non-extractable CryptoKey and the keyid it signs under, never key bytes. */
	signer?: { privKey: CryptoKey; keyid: string };
	/** The PUBLIC half of the key `signer` signs with. A bound delivery fetch presents it
	 * in a header and derives the agent identity from it, and a non-extractable CryptoKey
	 * cannot yield it — custody keeps the private half, so the public half is supplied
	 * alongside. Without it the client can buy but cannot fetch what it bought.
	 *
	 * There is deliberately no option for a separate agent PRIVATE key. The protocol
	 * carries one agent identity: agent_identity_hash is the thumbprint of the agent's
	 * request-signing key, an Exchange verifies the detached acceptance against the key
	 * registered for the caller its request signature identified, and the delivery URL is
	 * bound to that same thumbprint. A second key would be refused at execute, and any URL
	 * it did produce could never be fetched. */
	agentPublicKey?: CryptoKey;
	/** The agent's own identity. A query and a purchase must name a requester, and a
	 * request without one is refused, so the client stamps it on every query that names
	 * none and on every purchase, where the detached acceptance also binds it. Under
	 * strict validation (the default) a query left with no requester is refused before it
	 * is sent. */
	requester?: Record<string, unknown>;
	/** Offer-verification strictness. Defaults to "strict" — fail-closed. */
	verification?: Mode;
	/** Whether an outbound request is checked against its generated schema first.
	 * Defaults to "strict", which is deliberately stricter than Go — see the Validation
	 * type for why. Orthogonal to `verification`: this one is about the message going
	 * out, that one about the offers coming back. */
	validation?: Validation;
	/** Resolves an exchange identity to its raw 32-byte Ed25519 offer-signing key.
	 * Injected: the client owns no key state. */
	resolveOfferKey?: (exchange: string) => Promise<Uint8Array<ArrayBuffer> | undefined>;
	/** Turns an offer's exchange domain into that Exchange's own advertised origin. Never
	 * configuration — a usage report and a dispute go where the signed offer says. */
	endpointResolver?: EndpointResolver;
	/** Reports what one Exchange asks of a registration — the terms revision submitting
	 * one accepts, and the schema its registration_data must match. Defaults to the
	 * well-known reader over the SSRF-guarded transport, built once with this client:
	 * the domain comes off the request rather than from configuration, so it is the
	 * request-derived provenance that takes the guarded default.
	 *
	 * The reader it takes holds no document cache, and that is the point rather than an
	 * implementation detail: the contract requires a registering client to read the terms
	 * digest from a FRESHLY fetched manifest, so an implementation serving it from a
	 * cache breaks the rule the field exists to record. There is deliberately no option
	 * to supply a digest or a schema directly — a caller managing its own requirements
	 * sets `terms_digest` on the request, which suppresses the read and says so on the
	 * message the signature covers. */
	registrationRequirements?: RegistrationRequirementsReader;
	/** The key-directory origin this client signs as, such as "https://agent.example" —
	 * the place a peer fetches to find the key that signed the request. Every outbound
	 * request signature, and every delivery-fetch proof, carries it as its own
	 * Signature-Agent dictionary member, sig1="<origin>", covered by the signature.
	 *
	 * Required to sign. A client with no directory refuses every signed call locally, as
	 * a `malformed` call, before anything is sent, and a value that is not an https
	 * origin is refused the same way. One value per client, because one client speaks
	 * for one agent; an application signing as several agents builds a client per agent,
	 * or composes createSigningTransport with a signerSource. */
	signatureAgent?: string;
	/** The RFC 9421 freshness window stamped on every outbound call. Not needed for
	 * uniqueness: every request signature carries a fresh nonce. */
	signWindow?: Window;
	/** The freshness window stamped on a delivery-fetch proof. */
	proofWindow?: Window;
	/** Mints the X-Request-ID correlation value. Absent sends no header. */
	requestId?: () => string;
	/** The dialing seam for the configured (home Exchange / Broker) leg. */
	send?: UnarySend;
	/** The dialing seam for the OFFER-DERIVED leg. Defaults to the SSRF-guarded send,
	 * because the caller names a domain, the manifest it serves names an endpoint, and a
	 * signed call then goes there. */
	guardedSend?: UnarySend;
	maxRPCReadBytes?: number;
	callTimeoutMs?: number;
	contentTimeoutMs?: number;
	maxContentBytes?: number;
	/** The clock the offer Verifier reads, in epoch milliseconds. */
	now?: () => number;
	/** Called with every RPC request just before it is signed; the request it returns is
	 * what gets signed and sent. See {@link BeforeSign}. */
	beforeSign?: BeforeSign;
	/** Refuse, as `malformed`, a success answer that carries a field its message does not
	 * declare or breaks one of the proto's cross-field rules. Checked against the published
	 * strict JSON Schemas, so the shape is the generator's. An error answer is checked too:
	 * the Connect envelope may carry only code, message and details, must name a known
	 * Connect code and carry well-formed details, and every ErrorDetail in it, binary
	 * `value` and `debug` projection alike, must pass the strict ErrorDetail schema and the
	 * cross-field rules; a refused envelope keeps `code` and `status` and carries no detail.
	 * Defaults to false: the generated schemas drop unknown fields, which keeps a client
	 * working against a newer Exchange. */
	strict?: boolean;
}

/** Tunes a single state-mutating call. */
export interface CallOptions {
	/**
	 * Pins the idempotency key for this call. Reusing a key makes the call a deliberate
	 * replay: the server dedupes on it (a fresh key is minted per call by default). The
	 * SDK never tracks keys — the server owns dedup.
	 *
	 * Hold the key and pass the same one back when retrying, on every verb that takes
	 * this option. The key identifies the ACTION, not the attempt: a fresh key on a retry
	 * reads to the server as a second purchase, a second report, a second dispute.
	 */
	idempotencyKey?: string;
}

// resolved holds what both faces are built from, so the exchange and broker clients
// cannot drift in how they sign, correlate, bound or verify.
export interface Resolved {
	opts: ClientOptions;
	verifier: Verifier;
	send: UnarySend;
	guardedSend: UnarySend;
	/** The SEAM, not the concrete reader: an injected one and the default are the
	 * same thing to every caller below here. Resolved alongside the transports
	 * because the default holds a dispatcher, so building it per call would open
	 * one per registration and close none. */
	requirements: RegistrationRequirementsReader;
	signer: CallSigner | undefined;
}

export function resolve(opts: ClientOptions): Resolved {
	const now = opts.now ?? (() => Date.now());
	const verifier = createVerifier(opts.verification ?? "strict", {
		// Fail-closed by default: with no resolver injected nothing resolves, so every
		// offer lands in `rejected` with a reason rather than being surfaced unchecked.
		resolve: opts.resolveOfferKey ?? (async () => undefined),
		now,
	});
	const signer: CallSigner | undefined =
		opts.signer === undefined
			? undefined
			: {
					privKey: opts.signer.privKey,
					keyid: opts.signer.keyid,
					...(opts.signatureAgent !== undefined
						? { signatureAgent: opts.signatureAgent }
						: {}),
					...(opts.signWindow !== undefined ? { window: opts.signWindow } : {}),
				};
	return {
		opts,
		verifier,
		send: opts.send ?? createUnarySend({ guarded: false }),
		guardedSend: opts.guardedSend ?? createUnarySend({ guarded: true }),
		requirements:
			opts.registrationRequirements ?? createWellKnownRequirementsReader(),
		signer,
	};
}

// call is the one place a verb reaches the wire, so every leg carries the same header
// set, the same bound, the same deadline and the same answer checks. `response` is the
// fully-qualified name of the message the answer is, which strict decoding validates.
export async function call(
	r: Resolved,
	op: string,
	baseURL: string,
	service: string,
	method: string,
	message: unknown,
	guarded: boolean,
	response: string,
): Promise<unknown> {
	const raw = await unaryCall({
		target: { baseURL, service, method },
		op,
		message,
		// The leg decides the dial AND the gate together, so the two cannot drift apart.
		send: guarded ? r.guardedSend : r.send,
		guarded,
		...(r.signer !== undefined ? { signer: r.signer } : {}),
		...(r.opts.requestId !== undefined ? { requestId: r.opts.requestId } : {}),
		...(r.opts.beforeSign !== undefined ? { beforeSign: r.opts.beforeSign } : {}),
		maxBytes: r.opts.maxRPCReadBytes ?? DEFAULT_MAX_RPC_READ_BYTES,
		timeoutMs: r.opts.callTimeoutMs ?? DEFAULT_CALL_TIMEOUT_MS,
		strict: r.opts.strict === true,
	});
	// Before any verb parses it: the strict check reads the answer as it arrived, and the
	// parse would already have dropped the unknown field it exists to find.
	if (r.opts.strict === true) refuseUnlessStrict(op, raw, response);
	return raw;
}
