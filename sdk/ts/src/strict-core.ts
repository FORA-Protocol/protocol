// The strict check's engine: null-normalization, the cross-field rules, and the refusal
// type. It imports no validator compiler, so a program that checks one message with its
// precompiled validator (gen/ts/strict/<message>.ts) carries that message and nothing
// else. ./strict.ts is the check by message name, built on this module; the description
// of what the strict check is lives there.

import type { StrictMessage, StrictValidator } from "../../../gen/ts/strict/types.ts";
import { crossFieldRuleIds, hasCrossFieldRules } from "./crossfield.ts";

export type { StrictMessage, StrictValidator } from "../../../gen/ts/strict/types.ts";

type Node = Record<string, unknown>;

function isNode(v: unknown): v is Node {
	return typeof v === "object" && v !== null && !Array.isArray(v);
}

const DEFS_PREFIX = "#/$defs/";

/** One message instance the cross-field rules are checked on. */
interface Found {
	message: string;
	path: string;
	value: Node;
}

/**
 * normalize returns a copy of `instance` with null members of message objects removed,
 * guided by the schema, and collects every message instance whose type carries
 * cross-field rules. A key the schema does not declare is kept, so the schema refuses it.
 */
function normalize(
	instance: unknown,
	node: unknown,
	defs: Node,
	path: string,
	found: Found[],
): unknown {
	if (!isNode(node)) return instance;
	const ref = node["$ref"];
	if (typeof ref === "string" && ref.startsWith(DEFS_PREFIX)) {
		const name = ref.slice(DEFS_PREFIX.length);
		return normalizeMessage(instance, defs[name], defs, path, found, name);
	}
	if (Array.isArray(instance) && node["items"] !== undefined) {
		return instance.map((item, i) => normalize(item, node["items"], defs, `${path}/${i}`, found));
	}
	const properties = node["properties"];
	if (isNode(properties)) return normalizeMessage(instance, node, defs, path, found, undefined);
	const values = node["additionalProperties"];
	if (isNode(instance) && isNode(values)) {
		const out: Node = {};
		for (const [k, v] of Object.entries(instance)) {
			setMember(out, k, normalize(v, values, defs, `${path}/${k}`, found));
		}
		return out;
	}
	// A Struct, a Value, a scalar or an enum: left exactly as it arrived.
	return instance;
}

function normalizeMessage(
	instance: unknown,
	node: unknown,
	defs: Node,
	path: string,
	found: Found[],
	name: string | undefined,
): unknown {
	if (!isNode(instance) || !isNode(node)) return instance;
	const properties = isNode(node["properties"]) ? node["properties"] : {};
	const out: Node = {};
	for (const [k, v] of Object.entries(instance)) {
		if (v === null && Object.prototype.hasOwnProperty.call(properties, k)) continue;
		setMember(out, k, normalize(v, properties[k], defs, `${path}/${k}`, found));
	}
	if (name !== undefined) {
		const bare = name.slice(name.lastIndexOf(".") + 1);
		if (hasCrossFieldRules(bare)) found.push({ message: bare, path, value: out });
	}
	return out;
}

function setMember(target: Node, name: string, value: unknown): void {
	Object.defineProperty(target, name, { value, enumerable: true, writable: true, configurable: true });
}

/** A message the strict contract does not accept. Peer of Go helpers.ErrStrictViolation
 * and Python StrictViolationError. */
export class StrictViolation extends Error {
	/** The fully-qualified name of the message the payload was checked as. */
	readonly messageName: string;
	/** Why it was refused: the location and the schema's complaint, or the cross-field
	 * rules it breaks. */
	readonly violation: string;

	constructor(messageName: string, violation: string, options?: { cause?: unknown }) {
		super(`${messageName} is refused by the strict contract: ${violation}`, options);
		this.name = "StrictViolation";
		this.messageName = messageName;
		this.violation = violation;
	}
}

/**
 * violationOf says why `raw` is not a `message` the strict contract accepts, checked with
 * `validate`, a validator compiled from `schema`: the location and the schema's
 * complaint, or the cross-field rules it breaks. Undefined when it is accepted. Null
 * members of message objects are removed first, guided by `schema`.
 */
export function violationOf(
	raw: unknown,
	message: string,
	schema: Readonly<Record<string, unknown>>,
	validate: StrictValidator,
): string | undefined {
	const defs = isNode(schema["$defs"]) ? schema["$defs"] : {};
	const found: Found[] = [];
	const normalized = normalizeMessage(raw, schema, defs, "", found, message);
	if (!validate(normalized)) {
		const first = validate.errors?.[0];
		const where = first?.instancePath === "" || first === undefined ? "(root)" : first.instancePath;
		const extra =
			first?.keyword === "additionalProperties"
				? ` (${JSON.stringify((first.params as { additionalProperty?: string }).additionalProperty)})`
				: "";
		return `${where} ${first?.message ?? "does not match"}${extra}`;
	}
	for (const f of found) {
		const violated = crossFieldRuleIds(f.message, f.value);
		if (violated.length > 0) {
			return `${f.path === "" ? "(root)" : f.path} violates cross-field rule(s) ${violated.join(", ")}`;
		}
	}
	return undefined;
}

/** strictViolationOf is violationOf with a message's precompiled check. */
export function strictViolationOf(raw: unknown, strict: StrictMessage): string | undefined {
	return violationOf(raw, strict.message, strict.schema, strict.validate);
}

/** checkStrictOf throws StrictViolation unless `payload` passes `strict`, a message's
 * precompiled check. */
export function checkStrictOf(payload: unknown, strict: StrictMessage): void {
	const problem = strictViolationOf(payload, strict);
	if (problem !== undefined) throw new StrictViolation(strict.message, problem);
}
