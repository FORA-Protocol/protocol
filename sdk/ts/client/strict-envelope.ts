// Strict decoding of an error answer: the Connect envelope, and every ErrorDetail in it.
//
// A lenient reader takes what it can from a Connect error: it ignores a member it does
// not know, and skips a detail that does not decode. With `strict: true` both are
// findings, so the envelope is checked before it is read. The checks are the ones the Go
// and Python clients make, so one envelope gets one verdict in all three:
//
//   - a JSON error body is an object whose members are code, message and details, and
//     nothing else. A null member reads as absent, as proto-JSON reads it;
//   - code is present and is one of the sixteen Connect codes; message is a string;
//   - details is an array of objects whose members are type, value and debug. type is a
//     non-empty string, value is base64 (standard or URL alphabet, padded or not), and an
//     entry carries a value, a debug projection or both;
//   - for an entry of type fora.v1.ErrorDetail, the value decodes as an ErrorDetail with
//     no field the contract does not define, and so does the debug projection when
//     present; each then passes the published strict ErrorDetail schema and the
//     cross-field rules, and sets at most one member of the reason oneof.
//
// A body that is empty or not JSON is not an envelope: it is a gateway or a proxy
// answering for the service, and its status classifies it in either mode. The caller
// decides that before it gets here.

import { decodeErrorDetailValue, isDetailValueBase64 } from "../src/errordetail-wire.ts";
import { ERROR_DETAIL_TYPE, REASON_FIELDS, toProtoNames } from "../src/errordetail.ts";
import { ForaCallError } from "./errors.ts";
import { strictViolation } from "./strict.ts";

const ENVELOPE_MEMBERS = new Set(["code", "message", "details"]);
const ENTRY_MEMBERS = new Set(["type", "value", "debug"]);

/** The codes a Connect error envelope may name. */
export const CONNECT_CODES: ReadonlySet<string> = new Set([
	"canceled",
	"unknown",
	"invalid_argument",
	"deadline_exceeded",
	"not_found",
	"already_exists",
	"permission_denied",
	"resource_exhausted",
	"failed_precondition",
	"aborted",
	"out_of_range",
	"unimplemented",
	"internal",
	"unavailable",
	"data_loss",
	"unauthenticated",
]);

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** A member, with null read as absent. */
function member(obj: Obj, name: string): unknown {
	const v = obj[name];
	return v === null ? undefined : v;
}

/** The first member, in sorted order, that `known` does not name. */
function firstUnknown(obj: Obj, known: ReadonlySet<string>): string | undefined {
	return Object.keys(obj)
		.filter((k) => !known.has(k))
		.sort()[0];
}

/**
 * checkStrictEnvelope refuses an error answer whose envelope the strict contract does not
 * accept, as `malformed` naming the first failure. The refusal keeps `status` and `code`,
 * the Connect code the lenient read reports, and carries no detail: the detail is part
 * of what was refused.
 */
export function checkStrictEnvelope(
	op: string,
	status: number,
	payload: unknown,
	code: string | undefined,
): void {
	const problem = envelopeViolation(payload);
	if (problem === undefined) return;
	throw new ForaCallError({
		kind: "malformed",
		op,
		status,
		cause: new Error(`strict decoding refused the error answer: ${problem}`),
		...(code !== undefined ? { code } : {}),
	});
}

/** Why `payload` is not a Connect error envelope the contract accepts; undefined if it is. */
export function envelopeViolation(payload: unknown): string | undefined {
	if (!isObj(payload)) return "error body is JSON but not a Connect error envelope object";
	const name = firstUnknown(payload, ENVELOPE_MEMBERS);
	if (name !== undefined) {
		return `error envelope carries ${JSON.stringify(name)}, a member the Connect protocol does not define`;
	}
	return codeViolation(payload) ?? messageViolation(payload) ?? detailsViolation(payload);
}

function codeViolation(envelope: Obj): string | undefined {
	const code = member(envelope, "code");
	if (code === undefined) return "error envelope names no code";
	if (typeof code !== "string") return "error envelope code is not a string";
	if (!CONNECT_CODES.has(code)) return `error envelope code ${JSON.stringify(code)} is not a Connect code`;
	return undefined;
}

function messageViolation(envelope: Obj): string | undefined {
	const message = member(envelope, "message");
	if (message !== undefined && typeof message !== "string") {
		return "error envelope message is not a string";
	}
	return undefined;
}

function detailsViolation(envelope: Obj): string | undefined {
	const details = member(envelope, "details");
	if (details === undefined) return undefined;
	if (!Array.isArray(details)) return "error envelope details is not an array";
	for (const [i, entry] of details.entries()) {
		const problem = entryViolation(i, entry);
		if (problem !== undefined) return problem;
	}
	return undefined;
}

function entryViolation(i: number, entry: unknown): string | undefined {
	if (!isObj(entry)) return `details[${i}] is not an object`;
	const problem = entryShapeViolation(i, entry);
	if (problem !== undefined || entry["type"] !== ERROR_DETAIL_TYPE) return problem;
	return valueViolation(i, member(entry, "value")) ?? debugViolation(i, member(entry, "debug"));
}

/** The entry's own members, whatever type of detail it carries. */
function entryShapeViolation(i: number, entry: Obj): string | undefined {
	const name = firstUnknown(entry, ENTRY_MEMBERS);
	if (name !== undefined) {
		return `details[${i}] carries ${JSON.stringify(name)}, a member the Connect protocol does not define`;
	}
	const kind = member(entry, "type");
	if (typeof kind !== "string" || kind === "") return `details[${i}] names no type`;
	const value = member(entry, "value");
	const debug = member(entry, "debug");
	if (value !== undefined && (typeof value !== "string" || !isDetailValueBase64(value))) {
		return `details[${i}].value is not base64`;
	}
	if (value === undefined && debug === undefined) {
		return `details[${i}] carries neither a value nor a debug projection`;
	}
	return undefined;
}

/** The binary ErrorDetail: it decodes, defines every field it carries, and passes. */
function valueViolation(i: number, value: unknown): string | undefined {
	if (typeof value !== "string") return undefined;
	const unknown: string[] = [];
	const decoded = decodeErrorDetailValue(value, REASON_FIELDS, unknown);
	if (decoded === undefined) return `details[${i}].value does not decode as ${ERROR_DETAIL_TYPE}`;
	if (unknown.length > 0) {
		return `details[${i}].value carries a field the contract does not define (${unknown[0]})`;
	}
	const problem = detailViolation(decoded);
	return problem === undefined ? undefined : `details[${i}].value: ${problem}`;
}

/** The debug projection, read under the proto field names like the lenient reader. */
function debugViolation(i: number, debug: unknown): string | undefined {
	if (debug === undefined) return undefined;
	if (!isObj(debug)) return `details[${i}].debug is not an object`;
	const normalized = toProtoNames(debug);
	if (!isObj(normalized)) return `details[${i}].debug nests too deep`;
	const problem = detailViolation(normalized);
	return problem === undefined ? undefined : `details[${i}].debug: ${problem}`;
}

/**
 * An ErrorDetail as proto-JSON: one reason at most, then the strict schema and the
 * cross-field rules. The schemas do not express oneof exclusivity, so it is checked
 * here; a proto-JSON parser refuses the same object.
 */
function detailViolation(detail: Obj): string | undefined {
	const reasons = REASON_FIELDS.filter((f) => detail[f] !== undefined && detail[f] !== null);
	if (reasons.length > 1) return `sets more than one member of the reason oneof: ${reasons.join(", ")}`;
	return strictViolation(detail, ERROR_DETAIL_TYPE);
}
