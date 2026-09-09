// sdk/ts/core — the wire→canonical offer inversion (the from-wire canonicalizer).
// Companion to the Verifier's canonicalOfferPayload: that face clears the two
// signature fields and JCS-es an ALREADY-canonical offer; THIS face reconstructs
// the canonical form from the FORA Connect WIRE offer (proto3-JSON with
// EmitUnpopulated — zero-valued scalars, empty repeateds, null messages, and
// *_UNSPECIFIED enums all present). Every TS client verifying a wire offer must
// invert the wire emission BEFORE canonicalOfferPayload, never call it on raw wire.
//
// Mirror of sdk/python fora_sdk.wire_canon.from_wire_offer. Its presence rules are
// SCHEMA-AWARE, driven by the generated gen/ts OfferSchema exactly as the Python
// side reads them from the gen/python model field defaults:
//
//   .optional()  → proto3 presence-tracked → a set-but-zero scalar is KEPT
//                  (an optional string deliberately "" survives, e.g. pricing.unit).
//   .default("")/.default(0)/bare-required → non-optional → the zero value is DROPPED.
//   z.object     → message: recurse (a set-but-empty {} stays, a null message drops).
//   z.array      → repeated: drop when empty, else canonicalize each element.
//   z.record     → map/Struct: keep VERBATIM (keys are data, never pruned or cased),
//                  drop only when empty.
//   *_UNSPECIFIED enum values are zero values and drop.
//
// Byte-parity with the Go oracle is pinned by tests/wire-canonical.parity.test.ts
// over the shared sdk/go/helpers/testdata/wire-canonical-vectors.json corpus.
//
// FAIL-CLOSED: a wire field newer than the pinned OfferSchema is kept verbatim, so a
// signature covering bytes this pin cannot reconstruct verifies FALSE (rejected),
// never silently accepted.

import { OfferSchema } from "../../../gen/ts/wire/schemas.ts";

// A structural view of the pieces of a Zod schema this inversion reads — enough to
// walk the generated OfferSchema tree without coupling to the zod value import.
// Both Zod majors are read: Zod 3 names the kind in `typeName` ("ZodOptional") and
// Zod 4 in `type` ("optional"), where `type` is the array ELEMENT in Zod 3. A
// refinement is a ZodEffects wrapper in Zod 3 and the same object in Zod 4; a
// transform is ZodEffects in Zod 3 and a pipe in Zod 4.
interface ZodDef {
	readonly typeName?: string; // Zod 3 kind
	readonly type?: AnyZod | string; // Zod 3: array element or branded inner; Zod 4: kind
	readonly innerType?: AnyZod; // optional/default/nullable, both majors
	readonly schema?: AnyZod; // Zod 3 effects
	readonly element?: AnyZod; // Zod 4 array
	readonly in?: AnyZod; // Zod 4 pipe
}
interface AnyZod {
	readonly _def: ZodDef;
}

// Sentinel: this field is omitted entirely by the canonical marshal.
const OMIT: unique symbol = Symbol("fora.core.wire-canon.omit");

const CAMEL_BOUNDARY = /([a-z0-9])([A-Z])/g;
const UNSPECIFIED_ENUM = /^[A-Z][A-Z0-9_]*_UNSPECIFIED$/;

// Wrapper node types that decorate a field without changing its wire identity.
const WRAPPERS = new Set(["ZodOptional", "ZodDefault", "ZodNullable", "ZodBranded", "ZodEffects", "ZodPipe"]);

function zdef(schema: AnyZod): ZodDef {
	return schema._def;
}

// kindOf reads the node kind in Zod 3 spelling for both majors: Zod 4's "optional"
// becomes "ZodOptional", so one vocabulary drives the walk.
function kindOf(schema: AnyZod): string {
	const d = zdef(schema);
	if (d.typeName !== undefined) return d.typeName;
	const t = typeof d.type === "string" ? d.type : "";
	return `Zod${t.charAt(0).toUpperCase()}${t.slice(1)}`;
}

// innerOf peels one wrapper: ZodOptional/ZodDefault/ZodNullable expose `innerType`,
// Zod 3 ZodArray/ZodBranded expose `type`, Zod 3 ZodEffects exposes `schema`, Zod 4
// arrays expose `element` and Zod 4 pipes `in` — mutually exclusive.
function innerOf(schema: AnyZod): AnyZod {
	const d = zdef(schema);
	const inner = d.innerType ?? d.schema ?? d.element ?? d.in ?? (typeof d.type === "object" ? d.type : undefined);
	if (inner === undefined) throw new Error("fora/core: zod wrapper has no inner type");
	return inner;
}

function shapeOf(schema: AnyZod): Record<string, AnyZod> {
	return (schema as unknown as { shape: Record<string, AnyZod> }).shape;
}

// coreType strips presence/decoration wrappers to the underlying kind (ZodObject,
// ZodArray, ZodRecord, or a scalar). It STOPS at ZodArray so a repeated field is
// still detectable as repeated (the element is unwrapped separately).
function coreType(schema: AnyZod): AnyZod {
	let s = schema;
	while (WRAPPERS.has(kindOf(s))) s = innerOf(s);
	return s;
}

// isPresenceTracked mirrors Python's `field.default is None`: a `.optional()` field
// is proto3 presence-tracked (keep its zero value); `.default(...)` or a bare
// required field is non-optional (drop its zero value).
function isPresenceTracked(schema: AnyZod): boolean {
	const t = kindOf(schema);
	if (t === "ZodOptional") return true;
	if (t === "ZodDefault") return false;
	if (t === "ZodNullable" || t === "ZodBranded" || t === "ZodEffects" || t === "ZodPipe") {
		return isPresenceTracked(innerOf(schema));
	}
	return false;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

// snake inverts protojson's lowerCamel json_name back to the proto name. It is
// idempotent on already-snake keys (the shared corpus is snake_case wire).
function snake(key: string): string {
	return key.replace(CAMEL_BOUNDARY, "$1_$2").toLowerCase();
}

function canonScalar(value: unknown, presence: boolean): unknown {
	if (presence) return value; // set (on the wire) → part of the signed bytes
	const zeroish = value === "" || value === false || (typeof value === "number" && value === 0);
	if (zeroish) return OMIT;
	if (typeof value === "string" && UNSPECIFIED_ENUM.test(value)) return OMIT;
	return value;
}

function canonField(field: AnyZod, value: unknown): unknown {
	if (value === null) return OMIT; // unset message/Struct (EmitUnpopulated renders null)
	const core = coreType(field);
	const kind = kindOf(core);
	if (Array.isArray(value)) {
		const elem = kind === "ZodArray" ? coreType(innerOf(core)) : undefined;
		const elemIsMessage = elem !== undefined && kindOf(elem) === "ZodObject";
		const items = value.map((v) =>
			elemIsMessage && elem !== undefined && isPlainObject(v) ? canonMessage(elem, v) : v,
		);
		return items.length > 0 ? items : OMIT; // canonical omits empty repeated
	}
	if (isPlainObject(value)) {
		if (kind === "ZodObject") return canonMessage(core, value); // set-but-empty {} stays
		if (kind === "ZodRecord") return Object.keys(value).length > 0 ? value : OMIT; // map keys verbatim
		return value;
	}
	return canonScalar(value, isPresenceTracked(field));
}

// keep writes a member the canonical form must carry, including one whose name is an
// inherited property of every object. A plain assignment to "__proto__" replaces the
// object's prototype and creates no member; defineProperty creates the member, which is
// what JSON.stringify — and therefore JCS, and therefore the signature — reads.
function keep(out: Record<string, unknown>, name: string, value: unknown): void {
	Object.defineProperty(out, name, {
		value,
		enumerable: true,
		writable: true,
		configurable: true,
	});
}

function canonMessage(objectSchema: AnyZod, wire: Record<string, unknown>): Record<string, unknown> {
	const shape = shapeOf(objectSchema);
	const out: Record<string, unknown> = {};
	for (const [key, value] of Object.entries(wire)) {
		const name = snake(key);
		// hasOwn on the READ, and defineProperty on the WRITE. Both are the same key: a
		// wire name like "__proto__" or "constructor" resolves to an inherited member of
		// Object.prototype, so a truthiness test hands the walk an object with no _def,
		// and a plain assignment invokes the prototype SETTER instead of creating a
		// member. An offer comes from a peer, so the key is attacker-chosen, and the
		// second half was the dangerous one: the member vanished from the canonical form
		// while the object silently inherited whatever the attacker put there. The signed
		// bytes were unaffected, so an offer carrying an appended __proto__ still VERIFIED
		// — the one member name that could be added to a signed offer for free — and the
		// caller then read attacker-chosen values off a VerifiedOffer.
		const field = Object.hasOwn(shape, name) ? shape[name] : undefined;
		if (field === undefined) {
			// Newer-than-pin field: keep it so verification fails CLOSED (the signature
			// covered bytes this pin cannot reconstruct).
			keep(out, name, value);
			continue;
		}
		const canon = canonField(field, value);
		if (canon !== OMIT) keep(out, name, canon);
	}
	return out;
}

/**
 * fromWireOffer reconstructs the canonical (signed) offer object from the WIRE
 * offer object, mirroring sdk/python from_wire_offer. Feed its result to
 * canonicalOfferPayload (or RFC 8785 JCS directly) to reproduce the exact bytes the
 * offer signature covers.
 */
export function fromWireOffer(offerWire: Record<string, unknown>): Record<string, unknown> {
	return canonMessage(OfferSchema as unknown as AnyZod, offerWire);
}
