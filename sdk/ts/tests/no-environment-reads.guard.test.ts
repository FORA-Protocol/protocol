// Structural guard: the TypeScript SDK's library code reads no environment variable.
//
// An SDK that reads an environment variable lets whoever controls the process environment
// change what the library does, and the variables this repository inherited (SKIP_SSRF and
// ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md forbids any switch a test
// could use to relax a check; a caller that needs different behavior injects its own
// transport.
//
// The rule, the same in all three SDKs: every source file under the SDK's root is
// parsed, except a path the exemption table names with its reason, and a finding is
// any occurrence in code of a name in the language's set of environment readers: as an
// identifier, as a member of any receiver, as an imported name, or as a string literal
// whose whole value is the name. The receiver does not matter, so a reader reached
// through an alias, a reflective lookup or a string key is refused like a direct call,
// and so is an unrelated name that happens to match; rename it. Comments are not code.
// A name assembled at run time, for example by joining strings, is not caught. An
// exemption that matches no file fails the guard.
//
// In TypeScript the SDK's root is sdk/ts, every file with a TypeScript or JavaScript
// extension (.ts, .tsx, .mts, .cts, .js, .jsx, .mjs, .cjs) is read with the TypeScript
// compiler API, and the set is `env`, `homedir` and `tmpdir`: the member that holds the
// environment on `process`, `Deno`, `Bun` and `import.meta`, and the node:os functions
// that read HOME or TMPDIR. A name counts as any identifier (a member name, a binding, an
// import or export specifier, a property or parameter name) and any string literal or
// plain template literal. The Go and Python SDKs hold the same rule with their own
// parsers.

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../", import.meta.url));
const READERS: ReadonlySet<string> = new Set(["env", "homedir", "tmpdir"]);
const SOURCE = /\.(?:[mc]?[jt]s|[jt]sx)$/;

/** The guard's config: each path under the SDK's root it does not read, as a regular
 * expression over the slash-separated relative path, and the reason. */
const EXEMPTIONS: ReadonlyArray<{ pattern: RegExp; reason: string }> = [
	{
		pattern: /^tests\//,
		reason: "the suite applies the SDK, and stubs the retired variables on purpose to prove nothing reads them",
	},
	{ pattern: /(?:^|\/)node_modules\//, reason: "installed third-party packages, not this SDK's code" },
];

/** The exemption that covers `path` (a directory path ends with "/"), or undefined. */
function exemptionOf(path: string): RegExp | undefined {
	return EXEMPTIONS.find(({ pattern }) => pattern.test(path))?.pattern;
}

/** The source files under `dir` the guard reads; each exemption that covered a path is
 * added to `used`. */
function sourceFiles(dir: string, used: Set<RegExp>): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = join(dir, entry.name);
		const rel = relative(root, path).split("\\").join("/") + (entry.isDirectory() ? "/" : "");
		const exemption = exemptionOf(rel);
		if (exemption !== undefined) {
			used.add(exemption);
			return [];
		}
		if (entry.isDirectory()) return sourceFiles(path, used);
		return SOURCE.test(entry.name) ? [path] : [];
	});
}

/** The name `node` writes in code, if the rule counts its form. */
function nameOf(node: ts.Node): string | undefined {
	if (ts.isIdentifier(node)) return node.text;
	if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
	return undefined;
}

/** Each environment reader `source` names, as "line:column name". `fileName` picks the
 * parser's dialect from its extension. */
function environmentReaders(source: string, fileName = "guarded.ts"): string[] {
	const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true);
	const found: string[] = [];
	const visit = (node: ts.Node): void => {
		const name = nameOf(node);
		if (name !== undefined && READERS.has(name)) {
			const { line, character } = file.getLineAndCharacterOfPosition(node.getStart(file));
			found.push(`${line + 1}:${character + 1} ${name}`);
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return found;
}

describe("no SDK library file reads the environment", () => {
	it("holds for every source file outside the exemptions", () => {
		const used = new Set<RegExp>();
		const files = sourceFiles(root, used);
		expect(files.length).toBeGreaterThan(0);
		const offenders = files
			.map((path) => [relative(root, path), environmentReaders(readFileSync(path, "utf8"), path)] as const)
			.filter(([, reads]) => reads.length > 0);
		expect(offenders, "pass the value in through the API instead").toEqual([]);
		const unused = EXEMPTIONS.filter(({ pattern }) => !used.has(pattern)).map(({ pattern }) => String(pattern));
		expect(unused, "an exemption matches no file; remove it").toEqual([]);
	});

	it("reads every TypeScript and JavaScript extension", () => {
		for (const ext of ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"]) {
			expect(SOURCE.test(`file.${ext}`), ext).toBe(true);
			expect(environmentReaders("const x = process.env;", `file.${ext}`), ext).toHaveLength(1);
		}
		expect(SOURCE.test("file.json")).toBe(false);
	});

	it.each([
		["const x = process.env.X;", 1],
		['const x = process["env"];', 1],
		["const x = globalThis.process.env;", 1],
		['const x = globalThis["process"].env;', 1],
		["const p = process; const x = p.env;", 1],
		["const x = (process as any).env;", 1],
		['const x = Reflect.get(process, "env");', 1],
		["const x = Deno.env.get('X');", 1],
		["const x = Bun.env.X;", 1],
		["const x = import.meta.env.X;", 1],
		["const { env } = process;", 1],
		["const { env: e } = globalThis.process;", 1],
		['import { env } from "node:process";', 1],
		['import { env as e } from "process";', 1],
		['const { env } = await import("node:process");', 1],
		['const x = (await import("node:process")).default.env;', 1],
		['const x = require("process").env;', 1],
		["const key = `env`; const x = process[key];", 1],
		['import { homedir, tmpdir } from "node:os";', 2],
		["const x = os.homedir() + os.tmpdir();", 2],
		["const config = { env: 1 };", 1],
		['const s = "a // b # c"; const x = process.env.X;', 1],
	])("catches %s", (source, count) => {
		expect(environmentReaders(source)).toHaveLength(count);
	});

	it.each([
		"// process.env is not read\nconst x = 1;",
		"/* Deno.env */ const x = 1;",
		'const s = "process.env";',
		"const processEnv = 1; const x = processEnv;",
		'import { argv } from "node:process";',
		'const x = process["e" + "nv"];',
	])("does not count %s", (source) => {
		expect(environmentReaders(source)).toEqual([]);
	});

	it("covers exactly the exempted paths", () => {
		expect(exemptionOf("tests/client.test.ts")).toBeDefined();
		expect(exemptionOf("node_modules/undici/index.js")).toBeDefined();
		expect(exemptionOf("resolvers/http.ts")).toBeUndefined();
		expect(exemptionOf("resolvers/tests.ts")).toBeUndefined();
	});
});
