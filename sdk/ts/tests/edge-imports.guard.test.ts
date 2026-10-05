import { readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

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
// The meta-tests feed the detector synthetic source, and the last one walks the Node
// entry (resolvers/index.ts), which must reach undici, to show the walk follows
// re-exports at all.

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

	it("[meta would-be-missed] the walk follows re-exports: the Node entry reaches undici", () => {
		const reached = walk("resolvers/index.ts");
		expect(reached.some((o) => o.endsWith("-> undici"))).toBe(true);
		expect(reached.some((o) => o.endsWith("-> node:dns/promises"))).toBe(true);
	});
});
