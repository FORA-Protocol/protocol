// Raw mode: a request body the caller supplies, sent exactly as given.
//
// A conformance harness has to send messages the SDK would refuse to build — a missing
// `ver`, a forged requester, a field the schema forbids — and still have them signed and
// the reply decoded by the same client that drives the rest of the run. Passing a RawBody
// in place of a verb's request does that. The body is not stamped, not validated and not
// checked locally; it is signed (when a signer is configured), handed to the pre-signing
// hook, sent under the read cap, and its answer is decoded into the verb's response
// schema, strict decoding included.

/**
 * RawBody wraps the bytes one call sends in place of the request a verb would build.
 *
 * A `Uint8Array` is sent verbatim, a `string` as its UTF-8 bytes, and any other value is
 * serialized once with `JSON.stringify`. Every verb accepts a RawBody where it takes its
 * request (`execute` takes it in place of the offers). Nothing is filled in — not `ver`,
 * not `idempotency_key`, not `requester` — and none of the local refusals about the
 * message run: the recipient shape, the requester and signer checks, the
 * registration-data bounds and the terms-digest read, the offer checks.
 *
 * A verb that routes by the request's `exchange` (reportUsage, dispute, register,
 * getAccountStatus) still reads it from the body, parsed as JSON, and resolves it through
 * that Exchange's manifest as usual: the destination of a signed request is not a property
 * of the message to waive. A body with no usable `exchange` is refused as `not_sent`,
 * because there is nothing to dial. `execute` in raw mode decodes the reply and verifies
 * no delivery URL: there are no verified offers to tie them to.
 */
export class RawBody {
	constructor(readonly body: Uint8Array | string | unknown) {}
}

/** The bytes a RawBody sends. */
export function rawBytes(raw: RawBody): Uint8Array<ArrayBuffer> {
	const body = raw.body;
	if (body instanceof Uint8Array) return new Uint8Array(body) as Uint8Array<ArrayBuffer>;
	const text = typeof body === "string" ? body : JSON.stringify(body ?? null);
	return new TextEncoder().encode(text) as Uint8Array<ArrayBuffer>;
}

/**
 * The body read as a JSON object, or undefined when it is not one. Used only where a verb
 * must learn something from the body to send it at all — the recipient a routed verb dials,
 * the URIs a discovery answer is attributed to — never to check it.
 */
export function rawObject(raw: RawBody): Record<string, unknown> | undefined {
	let value: unknown = raw.body;
	if (value instanceof Uint8Array || typeof value === "string") {
		try {
			value = JSON.parse(typeof value === "string" ? value : new TextDecoder().decode(value));
		} catch {
			return undefined;
		}
	}
	return typeof value === "object" && value !== null && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: undefined;
}

/** The body's `exchange` member, or "" when it carries none. */
export function rawExchange(raw: RawBody): string {
	const exchange = rawObject(raw)?.["exchange"];
	return typeof exchange === "string" ? exchange : "";
}
