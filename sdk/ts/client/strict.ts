// Strict response decoding: refuse an answer the contract does not describe exactly.
//
// The generated schemas the client parses answers with are forward-compatible on purpose:
// they drop a field they do not know, so a newer Exchange does not break an older client.
// A conformance harness wants the opposite — an unknown or misspelled field is the defect
// it is looking for — and it wants the cross-field rules the proto states, which no
// per-field schema can express. With `strict: true` every RPC success answer is checked,
// before it is parsed, against:
//
//   - the published STRICT JSON Schema of its message (gen/jsonschema, additionalProperties
//     false on every message object at every depth), so the shape is the one the
//     generator emitted rather than a second definition kept here;
//   - the cross-field rules, through crossFieldRuleIds, on the answer itself and on every
//     nested message that carries any.
//
// A null member of a message object is removed first: proto-JSON reads null as "absent",
// and an Exchange rendering unpopulated fields emits one for every unset message field.
// Nothing inside a google.protobuf.Struct is touched, because there a null is data.

import Ajv2020Module, { type ValidateFunction } from "ajv/dist/2020.js";

import { crossFieldRuleIds, hasCrossFieldRules } from "../src/crossfield.ts";
import { malformed } from "./errors.ts";

import setReportingPolicyResponse from "../../../gen/jsonschema/fora.admin.v1.SetReportingPolicyResponse.schema.strict.json" with { type: "json" };
import setTenantFeeRateResponse from "../../../gen/jsonschema/fora.admin.v1.SetTenantFeeRateResponse.schema.strict.json" with { type: "json" };
import brokerTransactionResponse from "../../../gen/jsonschema/fora.v1.BrokerTransactionResponse.schema.strict.json" with { type: "json" };
import discoveryResponse from "../../../gen/jsonschema/fora.v1.DiscoveryResponse.schema.strict.json" with { type: "json" };
import disputeResponse from "../../../gen/jsonschema/fora.v1.DisputeResponse.schema.strict.json" with { type: "json" };
import domainVerificationChallenge from "../../../gen/jsonschema/fora.v1.DomainVerificationChallenge.schema.strict.json" with { type: "json" };
import domainVerificationResult from "../../../gen/jsonschema/fora.v1.DomainVerificationResult.schema.strict.json" with { type: "json" };
import getAccountStatusResponse from "../../../gen/jsonschema/fora.v1.GetAccountStatusResponse.schema.strict.json" with { type: "json" };
import pushResourcesResponse from "../../../gen/jsonschema/fora.v1.PushResourcesResponse.schema.strict.json" with { type: "json" };
import refreshCatalogResponse from "../../../gen/jsonschema/fora.v1.RefreshCatalogResponse.schema.strict.json" with { type: "json" };
import registerResponse from "../../../gen/jsonschema/fora.v1.RegisterResponse.schema.strict.json" with { type: "json" };
import removeResourcesResponse from "../../../gen/jsonschema/fora.v1.RemoveResourcesResponse.schema.strict.json" with { type: "json" };
import resourceResponse from "../../../gen/jsonschema/fora.v1.ResourceResponse.schema.strict.json" with { type: "json" };
import transactionResponse from "../../../gen/jsonschema/fora.v1.TransactionResponse.schema.strict.json" with { type: "json" };
import usageReportResponse from "../../../gen/jsonschema/fora.v1.UsageReportResponse.schema.strict.json" with { type: "json" };

/** The strict schema of every message a client verb decodes, by fully-qualified name. */
const STRICT_SCHEMAS: Readonly<Record<string, object>> = {
	"fora.admin.v1.SetReportingPolicyResponse": setReportingPolicyResponse,
	"fora.admin.v1.SetTenantFeeRateResponse": setTenantFeeRateResponse,
	"fora.v1.BrokerTransactionResponse": brokerTransactionResponse,
	"fora.v1.DiscoveryResponse": discoveryResponse,
	"fora.v1.DisputeResponse": disputeResponse,
	"fora.v1.DomainVerificationChallenge": domainVerificationChallenge,
	"fora.v1.DomainVerificationResult": domainVerificationResult,
	"fora.v1.GetAccountStatusResponse": getAccountStatusResponse,
	"fora.v1.PushResourcesResponse": pushResourcesResponse,
	"fora.v1.RefreshCatalogResponse": refreshCatalogResponse,
	"fora.v1.RegisterResponse": registerResponse,
	"fora.v1.RemoveResourcesResponse": removeResourcesResponse,
	"fora.v1.ResourceResponse": resourceResponse,
	"fora.v1.TransactionResponse": transactionResponse,
	"fora.v1.UsageReportResponse": usageReportResponse,
};

// Ajv is CommonJS. Node hands an ESM importer its module.exports, which is the class; a
// bundler may hand over the namespace, whose `default` is. Read whichever arrived, typed
// by the one method used, so the declaration holds under either module resolution.
interface AjvEngine {
	compile(schema: object): ValidateFunction;
}
type AjvConstructor = new (options: { strict: boolean; validateFormats: boolean }) => AjvEngine;
const Ajv2020 = ((Ajv2020Module as unknown as { default?: unknown }).default ??
	Ajv2020Module) as unknown as AjvConstructor;

// One engine for the process, schemas compiled on first use. `format` stays an annotation,
// as the schemas' README says: a validator asserting `duration` needs ajv-formats.
let engine: AjvEngine | undefined;
const compiled = new Map<string, ValidateFunction>();

function validatorFor(message: string): ValidateFunction {
	let validate = compiled.get(message);
	if (validate === undefined) {
		const schema = STRICT_SCHEMAS[message];
		if (schema === undefined) throw new Error(`no strict schema for ${message}`);
		engine ??= new Ajv2020({ strict: true, validateFormats: false });
		validate = engine.compile(schema);
		compiled.set(message, validate);
	}
	return validate;
}

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

/**
 * checkStrict refuses, as `malformed`, an answer that fails the strict schema of
 * `message` (fully-qualified, e.g. "fora.v1.ResourceResponse") or one of the cross-field
 * rules. Called on a success answer only; error envelopes are not messages of this type.
 */
export function checkStrict(op: string, raw: unknown, message: string): void {
	const schema = STRICT_SCHEMAS[message] as Node | undefined;
	if (schema === undefined) throw new Error(`no strict schema for ${message}`);
	const defs = isNode(schema["$defs"]) ? schema["$defs"] : {};
	const found: Found[] = [];
	const normalized = normalizeMessage(raw, schema, defs, "", found, message);
	const validate = validatorFor(message);
	if (!validate(normalized)) {
		const first = validate.errors?.[0];
		const where = first?.instancePath === "" || first === undefined ? "(root)" : first.instancePath;
		const extra =
			first?.keyword === "additionalProperties"
				? ` (${JSON.stringify((first.params as { additionalProperty?: string }).additionalProperty)})`
				: "";
		throw malformed(
			op,
			new Error(`strict decoding: ${where} ${first?.message ?? "does not match"}${extra}`),
		);
	}
	for (const f of found) {
		const violated = crossFieldRuleIds(f.message, f.value);
		if (violated.length > 0) {
			throw malformed(
				op,
				new Error(
					`strict decoding: ${f.path === "" ? "(root)" : f.path} violates cross-field rule(s) ${violated.join(", ")}`,
				),
			);
		}
	}
}
