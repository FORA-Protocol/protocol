// The binary form of fora.v1.ErrorDetail, read without a protobuf runtime.
//
// A Connect error carries its typed reason as `details[].value`: the binary protobuf
// encoding of the ErrorDetail, base64-encoded. That is the authoritative copy — the
// `debug` projection beside it is an optional rendering for JSON readers. This SDK has no
// protobuf codec, so it reads `value` with the small table-driven decoder below, which
// covers the ErrorDetail subtree only: the ErrorDetail message, its eight reason messages,
// RegistrationFieldError, and the enums they use. The output is canonical proto-JSON
// under the proto field names, which the generated ErrorDetailSchema then parses.
//
// The tables are a second statement of the shape, so they are held to the first: the
// shared corpus sdk/go/connect/testdata/error-detail-wire-vectors.json carries the same
// tables read from the compiled descriptor, and the suite requires these to be EQUAL to
// them. A field added to the proto fails the suite until it is added here.
//
// Decoding follows protobuf: an unknown field is skipped by its wire type, and so is a
// known field arriving with a wire type that does not fit its kind; a singular field
// written twice keeps the last value, a singular message written twice merges; a repeated
// enum is read packed or unpacked; of the ErrorDetail reason oneof, only the member seen
// last survives. A truncated buffer, a group wire type, a varint past ten bytes or a
// string that is not UTF-8 makes the value undecodable.
//
// A caller that must know about the skipped fields passes an array as `unknown`: each one
// is recorded there, by the message it appeared in and its field number. Strict decoding
// does, because it refuses an ErrorDetail carrying a field the contract does not define,
// which is what Go's decoder reports for the same bytes.

/** One field of a message, in the shape the shared corpus records it. */
export interface WireField {
	name: string;
	number: number;
	kind: string;
	type?: string;
	repeated?: boolean;
	map_key?: string;
	map_value?: string;
}

const reasonEnum = (number: number, name: string, type: string): WireField => ({
	name,
	number,
	kind: "enum",
	type,
});

/** The ErrorDetail subtree's messages, keyed by fully-qualified name. */
export const ERROR_DETAIL_WIRE_MESSAGES: Readonly<Record<string, readonly WireField[]>> = {
	"fora.v1.CatalogRejection": [
		reasonEnum(1, "reason", "fora.v1.CatalogRejectionReason"),
		{ name: "rejected_paths", number: 2, kind: "string", repeated: true },
	],
	"fora.v1.DisputeFailure": [reasonEnum(1, "reason", "fora.v1.DisputeFailureReason")],
	"fora.v1.DomainVerificationFailure": [
		reasonEnum(1, "reason", "fora.v1.DomainVerificationFailureReason"),
	],
	"fora.v1.ErrorDetail": [
		{ name: "message", number: 1, kind: "string" },
		{ name: "domain", number: 2, kind: "string" },
		{ name: "metadata", number: 3, kind: "map", map_key: "string", map_value: "string" },
		{ name: "transaction_denial", number: 10, kind: "message", type: "fora.v1.TransactionDenial" },
		{ name: "catalog_rejection", number: 11, kind: "message", type: "fora.v1.CatalogRejection" },
		{ name: "registration_failure", number: 12, kind: "message", type: "fora.v1.RegistrationFailure" },
		{ name: "dispute_failure", number: 13, kind: "message", type: "fora.v1.DisputeFailure" },
		{
			name: "domain_verification_failure",
			number: 14,
			kind: "message",
			type: "fora.v1.DomainVerificationFailure",
		},
		{ name: "retrieval_auth_failure", number: 15, kind: "message", type: "fora.v1.RetrievalAuthFailure" },
		{ name: "usage_report_rejection", number: 16, kind: "message", type: "fora.v1.UsageReportRejection" },
		{ name: "request_auth_failure", number: 17, kind: "message", type: "fora.v1.RequestAuthFailure" },
	],
	"fora.v1.RegistrationFailure": [
		reasonEnum(1, "reason", "fora.v1.RegistrationFailureReason"),
		{
			name: "field_errors",
			number: 2,
			kind: "message",
			type: "fora.v1.RegistrationFieldError",
			repeated: true,
		},
	],
	"fora.v1.RegistrationFieldError": [
		{ name: "path", number: 1, kind: "string" },
		{ name: "error", number: 2, kind: "string" },
	],
	"fora.v1.RequestAuthFailure": [reasonEnum(1, "reason", "fora.v1.RequestAuthFailureReason")],
	"fora.v1.RetrievalAuthFailure": [reasonEnum(1, "reason", "fora.v1.RetrievalAuthFailureReason")],
	"fora.v1.TransactionDenial": [
		reasonEnum(1, "reason", "fora.v1.DenialReason"),
		{
			name: "restriction_mismatches",
			number: 2,
			kind: "enum",
			type: "fora.v1.RestrictionKind",
			repeated: true,
		},
		{ name: "offer_id", number: 3, kind: "string" },
		{ name: "exchange", number: 4, kind: "string" },
	],
	"fora.v1.UsageReportRejection": [
		reasonEnum(1, "reason", "fora.v1.UsageReportRejectionReason"),
	],
};

/** Value names from 0, in number order: the tables are contiguous from zero. */
function enumOf(names: readonly string[]): Record<string, string> {
	const out: Record<string, string> = {};
	names.forEach((name, i) => {
		out[String(i)] = name;
	});
	return out;
}

const prefixed = (prefix: string, names: readonly string[]) =>
	enumOf(names.map((n) => `${prefix}_${n}`));

/** The ErrorDetail subtree's enums: number (as a decimal string) to value name. */
export const ERROR_DETAIL_WIRE_ENUMS: Readonly<Record<string, Readonly<Record<string, string>>>> = {
	"fora.v1.CatalogRejectionReason": prefixed("CATALOG_REJECTION_REASON", [
		"UNSPECIFIED",
		"NOT_CATALOG_CONTRIBUTOR",
		"TENANT_MISMATCH",
		"DOMAIN_NOT_VERIFIED",
		"SIGNATURE_INVALID",
		"MALFORMED_ENTRY",
		"UNKNOWN_VOCAB_TOKEN",
		"QUOTA_EXCEEDED",
		"TERMS_LIMIT_EXCEEDED",
		"URI_UNAVAILABLE",
		"UNKNOWN_CRITICAL_EXTENSION",
	]),
	"fora.v1.DenialReason": prefixed("DENIAL_REASON", [
		"UNSPECIFIED",
		"ACCOUNT_INACTIVE",
		"INSUFFICIENT_BALANCE",
		"RATE_LIMITED",
		"CONTENT_UNAVAILABLE",
		"RESTRICTION_NOT_SATISFIED",
		"REPORTING_OVERDUE",
		"OFFER_EXPIRED",
		"SIGNATURE_INVALID",
		"QUOTA_EXCEEDED",
		"DELEGATION_INVALID",
		"SCOPE_INSUFFICIENT",
		"ENTITLEMENT_MISSING",
		"ENTITLEMENT_MALFORMED",
		"ENTITLEMENT_EXPIRED",
		"ENTITLEMENT_WRONG_BUYER",
		"SUBSCRIPTION_LAPSED",
		"ENTITLEMENT_NOT_GRANTED",
		"ACCOUNT_NOT_REGISTERED",
		"RELAY_NOT_ACCEPTED",
		"UNKNOWN_CRITICAL_EXTENSION",
	]),
	"fora.v1.DisputeFailureReason": prefixed("DISPUTE_FAILURE_REASON", [
		"UNSPECIFIED",
		"TRANSACTION_NOT_FOUND",
		"REPORT_NOT_FILED",
		"WINDOW_EXPIRED",
		"DUPLICATE",
		"INELIGIBLE",
	]),
	"fora.v1.DomainVerificationFailureReason": prefixed("DOMAIN_VERIFICATION_FAILURE_REASON", [
		"UNSPECIFIED",
		"CHALLENGE_NOT_FOUND",
		"CHALLENGE_MISMATCH",
		"CHALLENGE_EXPIRED",
		"FETCH_FAILED",
		"EXCHANGE_NOT_AUTHORIZED",
		"KEY_REGISTRATION_FAILED",
	]),
	"fora.v1.RegistrationFailureReason": prefixed("REGISTRATION_FAILURE_REASON", [
		"UNSPECIFIED",
		"DOMAIN_NOT_VERIFIED",
		"INVALID_KEY",
		"SIGNATURE_INVALID",
		"ALREADY_REGISTERED",
		"QUOTA_EXCEEDED",
		"INVALID_REGISTRATION_DATA",
		"TERMS_DIGEST_STALE",
	]),
	"fora.v1.RequestAuthFailureReason": prefixed("REQUEST_AUTH_FAILURE_REASON", [
		"UNSPECIFIED",
		"SIGNATURE_MISSING",
		"SIGNATURE_INVALID",
		"SIGNATURE_STALE",
	]),
	"fora.v1.RestrictionKind": prefixed("RESTRICTION_KIND", [
		"UNSPECIFIED",
		"FUNCTION",
		"GEOGRAPHY",
		"USER_TYPE",
		"OTHER",
	]),
	"fora.v1.RetrievalAuthFailureReason": prefixed("RETRIEVAL_AUTH_FAILURE_REASON", [
		"UNSPECIFIED",
		"URL_EXPIRED",
		"URL_SIGNATURE_MISSING",
		"URL_EXPIRY_MISSING",
		"URL_SIGNATURE_MISMATCH",
		"AGENT_KEY_MISSING",
		"PROOF_SIGNATURE_MISSING",
		"KEYID_MISMATCH",
		"THUMBPRINT_MISMATCH",
		"PROOF_CREATED_MISSING",
		"PROOF_EXPIRY_MISSING",
		"PROOF_EXPIRED",
		"PROOF_SIGNATURE_INVALID",
	]),
	"fora.v1.UsageReportRejectionReason": prefixed("USAGE_REPORT_REJECTION_REASON", [
		"UNSPECIFIED",
		"TRANSACTION_NOT_FOUND",
		"DUPLICATE",
		"WINDOW_EXPIRED",
		"MISSING_REQUIRED_FIELDS",
		"MALFORMED",
		"UNKNOWN_CRITICAL_EXTENSION",
	]),
};

/** Thrown for a value that is not a decodable ErrorDetail. Module-private: the reader
 * turns it into "no detail from this entry". */
class Undecodable extends Error {}

const VARINT = 0;
const FIXED64 = 1;
const LEN = 2;
const FIXED32 = 5;

/** The wire type each kind is written with when it is not packed. */
function wireTypeOf(field: WireField): number {
	return field.kind === "enum" ? VARINT : LEN;
}

class Reader {
	pos = 0;
	constructor(readonly buf: Uint8Array) {}

	done(): boolean {
		return this.pos >= this.buf.length;
	}

	varint(): bigint {
		let result = 0n;
		for (let shift = 0n; shift < 70n; shift += 7n) {
			if (this.pos >= this.buf.length) throw new Undecodable("truncated varint");
			const byte = this.buf[this.pos++] as number;
			result |= BigInt(byte & 0x7f) << shift;
			if ((byte & 0x80) === 0) return BigInt.asUintN(64, result);
		}
		throw new Undecodable("varint longer than ten bytes");
	}

	take(n: number): Uint8Array {
		if (n < 0 || this.pos + n > this.buf.length) throw new Undecodable("truncated field");
		const out = this.buf.subarray(this.pos, this.pos + n);
		this.pos += n;
		return out;
	}

	bytes(): Uint8Array {
		const n = this.varint();
		if (n > BigInt(this.buf.length)) throw new Undecodable("length past the buffer");
		return this.take(Number(n));
	}

	skip(wireType: number): void {
		switch (wireType) {
			case VARINT:
				this.varint();
				return;
			case FIXED64:
				this.take(8);
				return;
			case LEN:
				this.bytes();
				return;
			case FIXED32:
				this.take(4);
				return;
			default:
				// 3 and 4 are the deprecated groups, 6 and 7 are not wire types at all.
				throw new Undecodable(`wire type ${wireType} is not decodable here`);
		}
	}
}

const utf8 = new TextDecoder("utf-8", { fatal: true });

function decodeString(bytes: Uint8Array): string {
	try {
		return utf8.decode(bytes);
	} catch {
		throw new Undecodable("string is not UTF-8");
	}
}

function enumName(type: string, raw: bigint): string | number {
	// An enum is an int32 on the wire, sign-extended to ten bytes when negative.
	const n = Number(BigInt.asIntN(32, raw));
	const name = ERROR_DETAIL_WIRE_ENUMS[type]?.[String(n)];
	// A number with no name stays a number, which is how proto-JSON renders it.
	return name ?? n;
}

type Message = Record<string, unknown>;

function defineMember(target: Message, name: string, value: unknown): void {
	Object.defineProperty(target, name, { value, enumerable: true, writable: true, configurable: true });
}

function decodeInto(
	buf: Uint8Array,
	type: string,
	target: Message,
	oneof: ReadonlySet<string>,
	unknown: string[] | undefined,
): void {
	const fields = ERROR_DETAIL_WIRE_MESSAGES[type];
	if (fields === undefined) throw new Undecodable(`no table for ${type}`);
	const reader = new Reader(buf);
	while (!reader.done()) {
		const tag = reader.varint();
		const number = Number(tag >> 3n);
		const wireType = Number(tag & 7n);
		if (number === 0) throw new Undecodable("field number zero");
		const field = fields.find((f) => f.number === number);
		const packed = field?.kind === "enum" && field.repeated === true && wireType === LEN;
		if (field === undefined || (!packed && wireType !== wireTypeOf(field))) {
			reader.skip(wireType);
			unknown?.push(`${type} field ${number}`);
			continue;
		}
		if (oneof.has(field.name)) {
			for (const member of oneof) if (member !== field.name) delete target[member];
		}
		readField(reader, field, target, packed, unknown);
	}
}

function readField(
	reader: Reader,
	field: WireField,
	target: Message,
	packed: boolean,
	unknown: string[] | undefined,
): void {
	switch (field.kind) {
		case "string": {
			const value = decodeString(reader.bytes());
			if (field.repeated) appendTo(target, field.name, value);
			else defineMember(target, field.name, value);
			return;
		}
		case "enum": {
			const type = field.type ?? "";
			if (packed) {
				const inner = new Reader(reader.bytes());
				while (!inner.done()) appendTo(target, field.name, enumName(type, inner.varint()));
				return;
			}
			const value = enumName(type, reader.varint());
			if (field.repeated) appendTo(target, field.name, value);
			else defineMember(target, field.name, value);
			return;
		}
		case "message": {
			const bytes = reader.bytes();
			const type = field.type ?? "";
			if (field.repeated) {
				const item: Message = {};
				decodeInto(bytes, type, item, NO_ONEOF, unknown);
				appendTo(target, field.name, finish(item, type));
				return;
			}
			// A singular message written twice merges: decode the second occurrence onto the
			// first rather than replacing it.
			const existing = target[field.name];
			const into: Message = isMessage(existing) ? existing : {};
			decodeInto(bytes, type, into, NO_ONEOF, unknown);
			defineMember(target, field.name, finish(into, type));
			return;
		}
		case "map": {
			const entry = new Reader(reader.bytes());
			let key = "";
			let value = "";
			while (!entry.done()) {
				const tag = entry.varint();
				const number = Number(tag >> 3n);
				const wireType = Number(tag & 7n);
				if ((number === 1 || number === 2) && wireType === LEN) {
					const s = decodeString(entry.bytes());
					if (number === 1) key = s;
					else value = s;
				} else {
					entry.skip(wireType);
				}
			}
			const map = isMessage(target[field.name]) ? (target[field.name] as Message) : {};
			defineMember(map, key, value);
			defineMember(target, field.name, map);
			return;
		}
		default:
			throw new Undecodable(`kind ${field.kind} is not in this decoder`);
	}
}

const NO_ONEOF: ReadonlySet<string> = new Set();

function appendTo(target: Message, name: string, value: unknown): void {
	const list = Array.isArray(target[name]) ? (target[name] as unknown[]) : [];
	list.push(value);
	defineMember(target, name, list);
}

function isMessage(v: unknown): v is Message {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Drop the singular scalars at their zero value, which proto-JSON leaves out. */
function finish(message: Message, type: string): Message {
	for (const field of ERROR_DETAIL_WIRE_MESSAGES[type] ?? []) {
		if (field.repeated || field.kind === "message" || field.kind === "map") continue;
		const value = message[field.name];
		if (value === "" || value === 0) delete message[field.name];
	}
	return message;
}

/** Standard or URL alphabet, padded or not; undefined for anything else. */
function decodeBase64(value: string): Uint8Array | undefined {
	const normalized = value.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
	if (!/^[A-Za-z0-9+/]*$/.test(normalized) || normalized.length % 4 === 1) return undefined;
	const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
	try {
		const binary = atob(padded);
		const out = new Uint8Array(binary.length);
		for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
		return out;
	} catch {
		return undefined;
	}
}

/**
 * Decode a binary fora.v1.ErrorDetail to canonical proto-JSON under the proto field
 * names. `oneof` names the members of the reason oneof, of which only the last seen
 * survives. Returns undefined for a value that does not decode. Each field skipped as
 * unknown, or as a known field with the wrong wire type, is pushed to `unknown` when it
 * is given.
 */
export function decodeErrorDetailBinary(
	bytes: Uint8Array,
	oneof: readonly string[],
	unknown?: string[],
): Record<string, unknown> | undefined {
	try {
		const out: Message = {};
		decodeInto(bytes, "fora.v1.ErrorDetail", out, new Set(oneof), unknown);
		return finish(out, "fora.v1.ErrorDetail");
	} catch (cause) {
		if (cause instanceof Undecodable) return undefined;
		throw cause;
	}
}

/** Decode a details[].value: base64, then {@link decodeErrorDetailBinary}. */
export function decodeErrorDetailValue(
	value: string,
	oneof: readonly string[],
	unknown?: string[],
): Record<string, unknown> | undefined {
	const bytes = decodeBase64(value);
	return bytes === undefined ? undefined : decodeErrorDetailBinary(bytes, oneof, unknown);
}

/** Whether a details[].value is base64 this reader accepts: standard or URL alphabet,
 * padded or not. */
export function isDetailValueBase64(value: string): boolean {
	return decodeBase64(value) !== undefined;
}
