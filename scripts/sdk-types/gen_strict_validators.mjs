// Generate the precompiled strict validators the TypeScript SDK checks a message with,
// into gen/ts/strict/: one module per message, plus types.ts and index.ts.
//
// The strict check validates a payload against the published STRICT JSON Schema of its
// message (gen/jsonschema/<message>.schema.strict.json). Compiling that schema with ajv at
// run time builds the validator from strings, which an edge runtime refuses: Cloudflare
// Workers throws "EvalError: Code generation from strings disallowed for this context".
// So the validators are compiled HERE, with ajv's standalone code generation, and
// committed as plain modules. No code is generated at run time on any runtime.
//
// Each module is self-contained: ajv's one runtime helper the schemas need, ucs2length
// (a string's length in code points, the unit JSON Schema's minLength/maxLength count
// in), is written into the module instead of required from ajv. Any other runtime
// helper fails the generation, so a schema change that needs one is noticed here rather
// than at run time.
//
// The schema compiled is the strict schema without its annotations (description, title,
// $comment, examples), which validation never reads. The same reduced schema is exported
// beside the validator: the SDK's null-normalization walks it, and it keeps a reader that
// imports one message from carrying every description of the message graph.
//
// One module per message, so a bundler keeps only the messages a program checks.
//
//   node gen_strict_validators.mjs <gen/jsonschema dir> <out dir>   (run from the dir
//   whose node_modules has the pinned ajv, as gen_zod.mjs is)
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(path.join(process.cwd(), "package.json"));
const Ajv2020 = require("ajv/dist/2020").default;
const standaloneCode = require("ajv/dist/standalone").default;
const ajvVersion = require("ajv/package.json").version;

// The messages the SDK checks by name: what a client verb decodes, the ErrorDetail an
// error answer carries, and the four documents the readers fetch. This list is the one
// copy; sdk/ts/src/strict.ts reads it through the generated index.
const MESSAGES = [
  "fora.admin.v1.SetReportingPolicyResponse",
  "fora.admin.v1.SetTenantFeeRateResponse",
  "fora.v1.BrokerTransactionResponse",
  "fora.v1.DiscoveryResponse",
  "fora.v1.DisputeResponse",
  "fora.v1.DomainVerificationChallenge",
  "fora.v1.DomainVerificationResult",
  "fora.v1.ErrorDetail",
  "fora.v1.GetAccountStatusResponse",
  "fora.v1.KeyRevocationList",
  "fora.v1.License",
  "fora.v1.PushResourcesResponse",
  "fora.v1.RefreshCatalogResponse",
  "fora.v1.RegisterResponse",
  "fora.v1.RemoveResourcesResponse",
  "fora.v1.ResourceResponse",
  "fora.v1.TransactionResponse",
  "fora.v1.UsageReportResponse",
  "fora.v1.WBAFile",
  "fora.v1.WellKnownManifest",
];

const [, , schemaDir, outDir] = process.argv;
if (!schemaDir || !outDir) {
  console.error("usage: node gen_strict_validators.mjs <gen/jsonschema dir> <out dir>");
  process.exit(2);
}

const ANNOTATIONS = new Set(["description", "title", "$comment", "examples"]);
// Keywords whose value maps a name to a schema: the names are data, the values schemas.
const SCHEMA_MAPS = new Set(["properties", "$defs", "patternProperties", "dependentSchemas"]);
// Keywords whose value is one schema, or a list of schemas.
const SCHEMA_ONE = new Set([
  "items", "additionalProperties", "not", "if", "then", "else", "contains",
  "propertyNames", "unevaluatedProperties", "unevaluatedItems",
]);
const SCHEMA_LIST = new Set(["anyOf", "allOf", "oneOf", "prefixItems"]);

// withoutAnnotations returns `node` with the annotation keywords removed from every
// schema in it. A property NAMED "description" is data and is kept.
function withoutAnnotations(node) {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return node;
  const out = {};
  for (const [k, v] of Object.entries(node)) {
    if (ANNOTATIONS.has(k)) continue;
    if (SCHEMA_MAPS.has(k) && v !== null && typeof v === "object") {
      out[k] = Object.fromEntries(Object.entries(v).map(([name, s]) => [name, withoutAnnotations(s)]));
    } else if (SCHEMA_ONE.has(k)) {
      out[k] = withoutAnnotations(v);
    } else if (SCHEMA_LIST.has(k) && Array.isArray(v)) {
      out[k] = v.map(withoutAnnotations);
    } else {
      out[k] = v;
    }
  }
  return out;
}

const UCS2LENGTH = `// ucs2length is ajv's runtime helper, written in: a string's length in code points.
function ucs2length(str) {
  const len = str.length;
  let length = 0;
  let pos = 0;
  let value;
  while (pos < len) {
    length++;
    value = str.charCodeAt(pos++);
    if (value >= 0xd800 && value <= 0xdbff && pos < len) {
      value = str.charCodeAt(pos);
      if ((value & 0xfc00) === 0xdc00) pos++;
    }
  }
  return length;
}
`;

function moduleFor(message) {
  const source = path.join(schemaDir, `${message}.schema.strict.json`);
  const schema = withoutAnnotations(JSON.parse(fs.readFileSync(source, "utf8")));
  // The options the run-time compile used: strict, `format` an annotation, and no
  // registration under $id.
  const ajv = new Ajv2020({
    strict: true,
    validateFormats: false,
    addUsedSchema: false,
    code: { source: true, esm: true },
  });
  let code = standaloneCode(ajv, ajv.compile(schema));

  // ajv opens with these exports; the module exports one typed value instead.
  const head = /^"use strict";export const validate = (validate\d+);export default \1;const (schema\d+) = /;
  const m = code.match(head);
  if (m === null) throw new Error(`${message}: ajv's standalone output no longer starts as expected`);
  const [, validateName, schemaName] = m;
  code = code.replace(head, `const ${schemaName} = `);

  let helpers = "";
  code = code.replace(/require\("ajv\/dist\/runtime\/ucs2length"\)\.default/g, () => {
    helpers = UCS2LENGTH;
    return "ucs2length";
  });
  const leftover = code.match(/require\([^)]*\)/);
  if (leftover !== null) throw new Error(`${message}: needs ajv runtime helper ${leftover[0]}, which is not written in`);

  return `// Code generated by scripts/sdk-types/gen_strict_validators.mjs from
// gen/jsonschema/${message}.schema.strict.json, with ajv ${ajvVersion} standalone. DO NOT EDIT.
// Regenerate: scripts/gen-sdk-types.sh
// @ts-nocheck
import type { StrictMessage } from "./types.ts";

${code}

${helpers}
/** The precompiled strict check of ${message}. */
export const strict: StrictMessage = { message: "${message}", validate: ${validateName}, schema: ${schemaName} };
`;
}

const TYPES = `// Code generated by scripts/sdk-types/gen_strict_validators.mjs. DO NOT EDIT.
// Regenerate: scripts/gen-sdk-types.sh

/** One reason a precompiled strict validator refused a value, as ajv reports it. */
export interface StrictValidationError {
	instancePath: string;
	schemaPath: string;
	keyword: string;
	params: Record<string, unknown>;
	message?: string;
}

/** A precompiled strict validator: true when \`data\` passes, otherwise false with
 * \`errors\` saying why. */
export interface StrictValidator {
	(data: unknown): boolean;
	errors?: StrictValidationError[] | null;
}

/** One message's precompiled strict check: its fully-qualified name, the validator, and
 * the strict schema it was compiled from, without annotations. */
export interface StrictMessage {
	readonly message: string;
	readonly validate: StrictValidator;
	readonly schema: Readonly<Record<string, unknown>>;
}
`;

function indexModule() {
  const lines = [
    "// Code generated by scripts/sdk-types/gen_strict_validators.mjs. DO NOT EDIT.",
    "// Regenerate: scripts/gen-sdk-types.sh",
    "",
    'import type { StrictMessage } from "./types.ts";',
  ];
  MESSAGES.forEach((m, i) => lines.push(`import { strict as m${i} } from "./${m}.ts";`));
  lines.push(
    "",
    "/** The precompiled strict check of every message the SDK checks by name. Importing this",
    " * module carries all of them; a program that checks one message imports its module. */",
    "export const STRICT_MESSAGES: Readonly<Record<string, StrictMessage>> = {",
  );
  MESSAGES.forEach((m, i) => lines.push(`\t"${m}": m${i},`));
  lines.push("};", "");
  return lines.join("\n");
}

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "types.ts"), TYPES);
for (const m of MESSAGES) fs.writeFileSync(path.join(outDir, `${m}.ts`), moduleFor(m));
fs.writeFileSync(path.join(outDir, "index.ts"), indexModule());
console.log(`wrote ${MESSAGES.length} strict validators to ${outDir}`);
