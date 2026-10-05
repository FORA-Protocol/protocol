// A Worker that imports part of the edge entry carries only that part.
//
// Bundled the way a Worker is (esbuild, platform neutral, the workerd/worker/browser
// conditions, minified), importing one constant from the edge entry used to carry about
// 0.9 MB: ajv and every strict schema, and every generated Zod schema. The packages are
// now marked side-effect free, the strict validators are compiled per message at build
// time, and each Zod schema is built in a call a bundler may drop. This guard bundles
// three programs and checks what each one carries.

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const esbuild = require("esbuild") as typeof import("esbuild");

const here = (p: string): string => fileURLToPath(new URL(p, import.meta.url));
const EDGE = JSON.stringify(here("../resolvers/edge.ts"));

interface Bundle {
	bytes: number;
	inputs: string[];
}

async function bundle(program: string): Promise<Bundle> {
	const out = await esbuild.build({
		stdin: { contents: program, resolveDir: here("."), loader: "ts" },
		bundle: true,
		write: false,
		format: "esm",
		platform: "neutral",
		conditions: ["workerd", "worker", "browser"],
		mainFields: ["module", "main"],
		minify: true,
		metafile: true,
		// Zod is the program's own dependency, a peer of the SDK; what is measured is the
		// SDK's share.
		external: ["zod"],
		logLevel: "silent",
	});
	const file = out.outputFiles[0];
	const output = Object.values(out.metafile.outputs)[0];
	if (file === undefined || output === undefined) throw new Error("esbuild produced no output");
	return {
		bytes: file.contents.byteLength,
		inputs: Object.entries(output.inputs)
			.filter(([, v]) => v.bytesInOutput > 0)
			.map(([k]) => k),
	};
}

const carries = (b: Bundle, fragment: string): boolean => b.inputs.some((i) => i.includes(fragment));

describe("the edge entry is tree-shakeable", () => {
	it("a program that imports one constant carries almost nothing", async () => {
		const b = await bundle(`import { WBA_DIRECTORY_PATH } from ${EDGE}; console.log(WBA_DIRECTORY_PATH);`);
		expect(b.bytes).toBeLessThan(1024);
		expect(carries(b, "node_modules/ajv")).toBe(false);
		expect(carries(b, "gen/ts/strict")).toBe(false);
		expect(carries(b, "gen/ts/wire/schemas.ts")).toBe(false);
	});

	it("a strict reader carries its own message's validator and no compiler", async () => {
		const b = await bundle(`import { readManifest } from ${EDGE}; console.log(readManifest);`);
		expect(carries(b, "node_modules/ajv")).toBe(false);
		expect(carries(b, "gen/ts/strict/fora.v1.WellKnownManifest.ts")).toBe(true);
		expect(carries(b, "gen/ts/strict/fora.v1.TransactionResponse.ts")).toBe(false);
		expect(carries(b, "gen/ts/strict/index.ts")).toBe(false);
	});

	it("the WBA key resolver carries no strict validator and only the Zod schemas it parses", async () => {
		const b = await bundle(`import { createWBAKeyResolver } from ${EDGE}; console.log(createWBAKeyResolver);`);
		expect(carries(b, "node_modules/ajv")).toBe(false);
		expect(carries(b, "gen/ts/strict")).toBe(false);
		// Every generated Zod schema in the bundle was about 0.75 MB; the two the resolver
		// parses with are a small part of that.
		expect(b.bytes).toBeLessThan(100 * 1024);
	});
});
