// The published JSON Schemas (gen/jsonschema/), reached the way an npm consumer reaches
// them and validated with Ajv's draft 2020-12 engine.
//
// The subpath `./jsonschema/*` is resolved by Node's own resolver through the repo-root
// manifest, the map a git-dependency consumer installs (sdk/ts/scripts/build.mjs copies
// the same subpath into the published @fora-protocol/sdk manifest, and
// scripts/release/smoke-npm.sh resolves it from the built tarball). Then:
//   - the strict variant refuses an unknown field, nested ones included; the default
//     variant accepts it;
//   - google.protobuf.Struct (`ext`) stays open in the strict variant;
//   - a buf.validate violation fails the schema;
//   - both variants reach Go protovalidate's verdict on every case of the conformance
//     corpus, as the Python suite asserts with the jsonschema library.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020";
import { afterAll, describe, expect, it } from "vitest";

import cases from "../../../conformance/corpus/cases.json";

const repo = fileURLToPath(new URL("../../../", import.meta.url));
const pkgName = (JSON.parse(readFileSync(join(repo, "package.json"), "utf8")) as { name: string }).name;

// A consumer project with the repo installed as its dependency, as `npm install
// <git url>` lays it out.
const consumer = mkdtempSync(join(tmpdir(), "fora-jsonschema-"));
mkdirSync(join(consumer, "node_modules", ...pkgName.split("/").slice(0, -1)), { recursive: true });
symlinkSync(repo, join(consumer, "node_modules", pkgName), "dir");
const consumerRequire = createRequire(join(consumer, "index.js"));
afterAll(() => rmSync(consumer, { recursive: true, force: true }));

function resolveSchema(name: string, strict: boolean): string {
	const file = `${name}.schema${strict ? ".strict" : ""}.json`;
	return consumerRequire.resolve(`${pkgName}/jsonschema/${file}`);
}

// Strict mode refuses any keyword Ajv does not know, so the schemas must be standard.
// `format` is an annotation in draft 2020-12; validateFormats: false keeps it one, as the
// schemas' README states, instead of failing on `duration`, which Ajv only knows with
// ajv-formats installed.
const ajv = new Ajv2020({ strict: true, validateFormats: false });
const compiled = new Map<string, ValidateFunction>();
function validator(name: string, strict: boolean): ValidateFunction {
	const key = `${name}:${strict}`;
	let v = compiled.get(key);
	if (v === undefined) {
		v = ajv.compile(JSON.parse(readFileSync(resolveSchema(name, strict), "utf8")) as object);
		compiled.set(key, v);
	}
	return v;
}
const accepts = (name: string, instance: unknown, strict: boolean) => validator(name, strict)(instance) === true;

type Case = { id: string; message: string; valid: boolean; json: Record<string, unknown> };
const corpus = cases as Case[];
const offer = corpus.find((c) => c.id === "Offer/valid")?.json;
if (offer === undefined) throw new Error("the corpus has no Offer/valid case");
const response = { exchange: "exchange.example", offers: [offer] };
const RR = "fora.v1.ResourceResponse";

describe("the published JSON Schemas", () => {
	it("resolve through the package export path", () => {
		expect(resolveSchema(RR, true)).toBe(join(repo, "gen/jsonschema", `${RR}.schema.strict.json`));
		expect(() => resolveSchema("fora.v1.NoSuchMessage", true)).toThrow();
	});

	it("accept a valid message in both variants", () => {
		expect(accepts(RR, response, false)).toBe(true);
		expect(accepts(RR, response, true)).toBe(true);
	});

	it.each([
		["top-level", { ...response, unknown_field: 1 }],
		["nested", { ...response, offers: [{ ...offer, unknown_field: 1 }] }],
		["camelCase alias", { ...response, offerGroups: [] }],
	])("strict refuses an unknown field (%s), default accepts it", (_, body) => {
		expect(accepts(RR, body, true)).toBe(false);
		expect(accepts(RR, body, false)).toBe(true);
	});

	it("strict keeps google.protobuf.Struct open at any depth", () => {
		const ext = { vendor: { nested: { deeper: [1, "two"] } }, flag: true };
		expect(accepts(RR, { ...response, ext, offers: [{ ...offer, ext }] }, true)).toBe(true);
	});

	it.each([false, true])("a buf.validate violation fails the schema (strict: %s)", (strict) => {
		expect(accepts(RR, { exchange: "" }, strict)).toBe(false);
		expect(accepts(RR, {}, strict)).toBe(false);
		const quota = { metric: "accesses", window: "QUOTA_WINDOW_DAILY" };
		expect(accepts("fora.v1.Quota", { ...quota, limit: "1" }, strict)).toBe(true);
		expect(accepts("fora.v1.Quota", { ...quota, limit: 1 }, strict)).toBe(true);
		expect(accepts("fora.v1.Quota", { ...quota, limit: "0" }, strict)).toBe(false);
		expect(accepts("fora.v1.Quota", { ...quota, limit: 0 }, strict)).toBe(false);
	});

	const names = new Map<string, string>();
	for (const c of corpus) {
		if (names.has(c.message)) continue;
		for (const pkg of ["fora.v1", "fora.admin.v1"]) {
			try {
				resolveSchema(`${pkg}.${c.message}`, false);
				names.set(c.message, `${pkg}.${c.message}`);
				break;
			} catch {
				// not in this package
			}
		}
	}

	it.each(corpus.flatMap((c) => [false, true].map((strict) => [c.id, strict, c] as const)))(
		"%s (strict: %s) matches the Go verdict",
		(_, strict, c) => {
			const name = names.get(c.message);
			expect(name, `no published schema for ${c.message}`).toBeDefined();
			expect(accepts(name as string, c.json, strict)).toBe(c.valid);
		},
	);
});
