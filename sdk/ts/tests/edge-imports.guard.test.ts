import { readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { bundleSource, FASTLY_GLOBAL_NAMES, WORKERS_CONDITIONS } from "./edge-sandbox.ts";

// Structural guard for the edge-safe surface.
//
// An edge runtime (Cloudflare Workers, Fastly Compute, Deno) has no undici and no Node
// built-in modules. The edge-safe surface is the edge resolvers entry
// (resolvers/edge.ts) and the pure trees src/, core/ and hono/. This guard walks the
// import graph from every one of those files, following each relative import and
// re-export to the module it names, and fails on any import of undici or of a Node
// built-in, whether spelled with the node: prefix or bare ("crypto", "dns/promises"),
// and on any use of a Node global no import names (Buffer, process, require,
// __dirname). The Workers types declare Buffer and process as `any`, so the workers
// typecheck (tsconfig.workers.json) cannot catch those two; this guard does.
//
// The workers typecheck admits every global the Workers types declare, and Fastly
// Compute's JavaScript runtime lacks most of them: AbortController, AbortSignal and
// DOMException among others. On Fastly each is a ReferenceError. So the guard also bundles
// the surface with each such global marked, wherever the code reaches it (by name, typeof,
// instanceof, an alias, globalThis or self), and fails on any mark left in the bundle. Code
// the bundle drops, such as an export nothing reaches, cannot run on Fastly and is not
// counted. The one use it admits is the feature-detected form the document read builds its
// AbortController with: typeof AbortController === "function" ? new AbortController() :
// undefined.
//
// The meta-tests feed the detectors synthetic source, and one walks the Node entry
// (resolvers/index.ts), which must reach undici, to show the walk follows re-exports at
// all.

const root = fileURLToPath(new URL("../", import.meta.url));

const NODE_BUILTINS = new Set(builtinModules);

// Every module specifier a source file names: static imports and re-exports
// (`from "x"`), side-effect imports (`import "x"`), dynamic imports and require calls.
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)["']([^"']+)["']/g;

function specifiers(source: string): string[] {
	return [...source.matchAll(SPECIFIER)].map((m) => m[1] as string);
}

// The Node globals an edge runtime lacks, used in code (comments are stripped first).
const NODE_GLOBAL = /\b(Buffer|process|require|__dirname|__filename)\s*[.(]/;

function stripComments(source: string): string {
	return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

// usesNodeGlobal reports whether code (not a comment) touches a Node-only global.
function usesNodeGlobal(source: string): boolean {
	return NODE_GLOBAL.test(stripComments(source));
}

// isNodeOnly reports whether a bare specifier names a module an edge runtime lacks.
function isNodeOnly(spec: string): boolean {
	if (spec === "undici" || spec.startsWith("undici/") || spec.startsWith("node:")) return true;
	return NODE_BUILTINS.has(spec) || NODE_BUILTINS.has(spec.split("/")[0] as string);
}

// walk returns every Node-only import reachable from `entry`, as "file -> specifier",
// and every reachable file that uses a Node global.
function walk(entry: string): string[] {
	const offenders: string[] = [];
	const seen = new Set<string>();
	const queue = [resolve(root, entry)];
	while (queue.length > 0) {
		const file = queue.pop() as string;
		if (seen.has(file)) continue;
		seen.add(file);
		const source = readFileSync(file, "utf8");
		if (usesNodeGlobal(source)) offenders.push(`${relative(root, file)} -> a Node global`);
		for (const spec of specifiers(source)) {
			if (spec.startsWith(".")) {
				// JSON modules carry data, not imports.
				if (!spec.endsWith(".json")) queue.push(resolve(dirname(file), spec));
			} else if (isNodeOnly(spec)) {
				offenders.push(`${relative(root, file)} -> ${spec}`);
			}
		}
	}
	return offenders;
}

function tsFilesUnder(dir: string): string[] {
	const out: string[] = [];
	for (const e of readdirSync(join(root, dir), { withFileTypes: true })) {
		if (e.isDirectory()) out.push(...tsFilesUnder(`${dir}/${e.name}`));
		else if (e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts")) out.push(`${dir}/${e.name}`);
	}
	return out;
}

// The globals the Workers types declare, which the workers typecheck admits in the
// edge-safe surface, less those Fastly Compute's JavaScript runtime declares.
const WORKERS_TYPES = readFileSync(join(root, "node_modules/@cloudflare/workers-types/index.d.ts"), "utf8");
const FASTLY_ABSENT = [
	...new Set(
		[...WORKERS_TYPES.matchAll(/^declare (?:var|let|const|function|class|abstract class|namespace) ([A-Za-z_$][\w$]*)/gm)].map(
			(m) => m[1] as string,
		),
	),
]
	.filter((name) => !FASTLY_GLOBAL_NAMES.includes(name))
	.sort();

// Each of those globals becomes one marked identifier in the bundle, however the code
// reaches it: esbuild's define replaces a reference to the global and leaves a binding that
// shadows it, a member of another object and a string alone.
const MARK = "__FASTLY_ABSENT__";
const DEFINE = Object.fromEntries(
	FASTLY_ABSENT.flatMap((name) => [name, `globalThis.${name}`, `self.${name}`].map((ref) => [ref, `${MARK}${name}`])),
);
const MARKED = new RegExp(`${MARK}(\\w+)`, "g");

// The one use admitted: a global built only where the runtime has it, as the document read
// builds its AbortController. esbuild prints `undefined` as `void 0`.
const FEATURE_DETECTED = new RegExp(`typeof (${MARK}\\w+) === "function" \\? new \\1\\(\\) : void 0`, "g");

// fastlyAbsentGlobals returns every global Fastly Compute lacks that `source` reaches once
// bundled, other than in the feature-detected form.
async function fastlyAbsentGlobals(source: string): Promise<string[]> {
	const bundle = await bundleSource(source, {
		conditions: WORKERS_CONDITIONS,
		format: "esm",
		define: DEFINE,
		external: ["zod", "hono", "hono/*"],
	});
	return [...new Set([...bundle.replace(FEATURE_DETECTED, "").matchAll(MARKED)].map((m) => m[1] as string))].sort();
}

// The edge-safe surface as one module: the edge entry and every file of the pure trees, each
// re-exported whole so nothing in it is shaken out.
function edgeSafeSurface(): string {
	const files = ["resolvers/edge.ts", ...["src", "core", "hono"].flatMap(tsFilesUnder)];
	return files.map((file, i) => `export * as m${i} from ${JSON.stringify(join(root, file))};`).join("\n");
}

describe("edge-safe import graph", () => {
	it("the edge resolvers entry reaches no undici, Node built-in or Node global", () => {
		expect(walk("resolvers/edge.ts")).toEqual([]);
	});

	for (const dir of ["src", "core", "hono"]) {
		it(`no file under ${dir}/ reaches undici, a Node built-in or a Node global`, () => {
			const files = tsFilesUnder(dir);
			expect(files.length).toBeGreaterThan(0);
			expect(files.flatMap(walk)).toEqual([]);
		});
	}

	it("the edge-safe surface reaches no global Fastly Compute lacks, unless it checks for it first", async () => {
		expect(await fastlyAbsentGlobals(edgeSafeSurface())).toEqual([]);
	}, 60_000);

	it("the edge entry is published as ./resolvers/edge", () => {
		const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { exports: Record<string, string> };
		expect(pkg.exports["./resolvers/edge"]).toBe("./resolvers/edge.ts");
	});

	// --- meta-tests -------------------------------------------------------------
	it("[meta positive] flags undici and Node built-ins in every import spelling", () => {
		for (const src of [
			'import { request } from "undici";',
			'import { createHash } from "node:crypto";',
			'import { lookup } from "dns/promises";',
			'import "node:fs";',
			'const m = await import("crypto");',
			'const m = require("node:net");',
			'export { lookup } from "node:dns/promises";',
		]) {
			expect(specifiers(src).some(isNodeOnly), src).toBe(true);
		}
	});

	it("[meta positive] flags a Node global used in code", () => {
		for (const src of ['const b = Buffer.from("x");', "const v = process.env.X;", 'const m = require("x");']) {
			expect(usesNodeGlobal(src), src).toBe(true);
		}
	});

	it("[meta negative] passes a Node global named only in a comment or as a word", () => {
		for (const src of [
			"// decodes as Buffer.toString does",
			"/* process.env is not read */ const x = 1;",
			"const processed = 1; const BufferSource = 2;",
		]) {
			expect(usesNodeGlobal(src), src).toBe(false);
		}
	});

	it("[meta negative] passes relative imports and edge-safe packages", () => {
		for (const src of ['import { z } from "zod";', 'import canonicalize from "canonicalize";', 'import { x } from "./x.ts";']) {
			expect(specifiers(src).some(isNodeOnly), src).toBe(false);
		}
	});

	it("[meta] the marked globals are the Workers globals Fastly Compute lacks, and none it has", () => {
		expect(FASTLY_ABSENT).toEqual(expect.arrayContaining(["AbortController", "AbortSignal", "DOMException", "HTMLRewriter"]));
		for (const name of ["Response", "fetch", "crypto", "setTimeout", "ReadableStream", "TextDecoder"]) {
			expect(FASTLY_ABSENT, name).not.toContain(name);
		}
	});

	it("[meta positive] flags a global Fastly Compute lacks, however the code reaches it", async () => {
		for (const src of [
			"export const c = new AbortController();",
			"export const isSignal = (x: unknown): boolean => x instanceof AbortSignal;",
			"const C = AbortController; export const c = new C();",
			"export const c = new globalThis.AbortController();",
			"export const c = new self.AbortController();",
			"export const s = AbortSignal.timeout(5);",
			'export const c = typeof AbortSignal === "function" ? new AbortController() : undefined;',
		]) {
			expect(await fastlyAbsentGlobals(src), src).not.toEqual([]);
		}
	});

	it("[meta negative] passes the feature-detected form, a shadowing binding, a member and a string", async () => {
		for (const src of [
			'export const c = typeof AbortController === "function" ? new AbortController() : undefined;',
			"export const f = (AbortController: new () => object): object => new AbortController();",
			"export const f = (o: { AbortController?: unknown }): unknown => o.AbortController;",
			'export const s = "AbortController";',
			"export const r = (): unknown[] => [new Response(null), setTimeout, crypto];",
		]) {
			expect(await fastlyAbsentGlobals(src), src).toEqual([]);
		}
	});

	it("[meta would-be-missed] the walk follows re-exports: the Node entry reaches undici", () => {
		const reached = walk("resolvers/index.ts");
		expect(reached.some((o) => o.endsWith("-> undici"))).toBe(true);
		expect(reached.some((o) => o.endsWith("-> node:dns/promises"))).toBe(true);
	});
});
