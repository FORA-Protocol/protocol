// Envelope stamping and the request checks every verb shares. Each copies the caller's
// message before it changes anything, so the object a caller passed stays theirs.

import { redactUserinfo } from "../src/host-ref.ts";
import { isBareDomain } from "../src/hosts.ts";
import { generateIdempotencyKey } from "../src/idempotency.ts";
import { ProtocolVersion } from "../src/wire.ts";
import { malformed, notSent } from "./errors.ts";
import type { CallOptions } from "./options.ts";

/**
 * stampDiscovery fills the envelope a DISCOVERY call carries, which is the mutating
 * envelope minus the idempotency key: pure discovery buys nothing and changes nothing, so
 * there is no action for a key to identify.
 *
 * Both fills are only-when-empty. The caller's own value always wins — the message
 * crossed a module boundary as an argument, not as a buffer to fill in — and the
 * requester is filled because a query must name one, while the client already holds that
 * identity.
 */
export function stampDiscovery(
	op: string,
	message: Record<string, unknown>,
	requester: Record<string, unknown> | undefined,
): Record<string, unknown> {
	const sent = clone(op, message);
	if (sent["ver"] === undefined || sent["ver"] === "") sent["ver"] = ProtocolVersion;
	if (sent["requester"] === undefined && requester !== undefined) {
		sent["requester"] = requester;
	}
	return sent;
}

/**
 * stampEnvelope fills the two envelope fields the protocol requires on a state-mutating
 * call, WITHOUT overwriting what the caller already set.
 *
 * Fill-when-empty is the whole rule. `ver` has a single owner, so the SDK supplies it
 * rather than making every caller reach for the constant. The idempotency key is REQUIRED
 * and identifies the action rather than the attempt, so a value the caller put there is
 * theirs — discarding it would turn each of their retries into a fresh action, which is
 * the double-counting the field exists to prevent. A pinned key overrides both.
 */
export function stampEnvelope(
	op: string,
	message: Record<string, unknown>,
	opts: CallOptions,
): Record<string, unknown> {
	const sent = clone(op, message);
	if (sent["ver"] === undefined || sent["ver"] === "") sent["ver"] = ProtocolVersion;
	const onMessage = sent["idempotency_key"];
	// Each fallback is taken when the one before it is EMPTY, not merely absent: an empty
	// pinned key is no key, which is how Go and Python both read it.
	sent["idempotency_key"] =
		opts.idempotencyKey !== undefined && opts.idempotencyKey !== ""
			? opts.idempotencyKey
			: typeof onMessage === "string" && onMessage !== ""
				? onMessage
				: generateIdempotencyKey();
	return sent;
}

// clone copies a caller's message so the SDK can stamp its envelope without touching what
// the caller still holds. structuredClone is the runtime's own deep copy; a message that
// cannot survive it is one that cannot be serialized to the wire either.
export function clone(op: string, message: Record<string, unknown>): Record<string, unknown> {
	try {
		return structuredClone(message);
	} catch (cause) {
		throw malformed(op, cause);
	}
}

export function stringField(record: Record<string, unknown>, key: string): string {
	const value = record[key];
	return typeof value === "string" ? value : "";
}

export function isRecord(v: unknown): v is Record<string, unknown> {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function stampVer(op: string, message: Record<string, unknown>): Record<string, unknown> {
	const sent = clone(op, message);
	if (sent["ver"] === undefined || sent["ver"] === "") sent["ver"] = ProtocolVersion;
	return sent;
}

// Serves the catalog verbs and the two account verbs, and asks only the SHAPE question.
//
// The predicate is isBareDomain, the SHAPE rule, not the routing rule isBareHost. The
// only question it answers is whether the value is the form the contract admits, which
// is the protovalidate pattern `exchange` carries and the same rule the Exchange's own
// audience check applies on arrival. Whether the value can be DIALLED is a separate
// question with a separate answer: a catalog client is built against an address the
// publisher configured and never asks it, while the account verbs resolve this domain
// through its own manifest and ask it there, under the routing predicate. The routing
// predicate is deliberately wider: an underscore, a trailing root dot and a bracketed
// IPv6 literal are all usable hosts and none of them is a value this field may hold,
// so vetting with it would sign and send a request the recipient can only refuse.
//
// The refused value is redacted before it is named. A reference carrying userinfo is a
// verdict rather than a parse failure, so it reaches the message below verbatim; the
// routing check next door redacts for the same reason, and a tier that echoes is the
// drift redactUserinfo exists to prevent.
export function requireRecipient(op: string, exchange: string): void {
	if (exchange === "") {
		throw notSent(op, new Error("request names no recipient; set exchange to the Exchange's bare domain"));
	}
	if (!isBareDomain(exchange)) {
		throw notSent(op, new Error(`exchange ${JSON.stringify(redactUserinfo(exchange))} is not a bare domain`));
	}
}
