// Structural guard: the TypeScript SDK's library code reads no environment variable.
//
// An SDK that reads an environment variable lets whoever controls the process environment
// change what the library does, and the variables this repository inherited (SKIP_SSRF and
// ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md forbids any switch a test
// could use to relax a check; a caller that needs different behavior injects its own
// transport.
//
// Every library file is parsed with the TypeScript compiler API, and the guard fails on:
//   - a member `env` read, by `.env` or `["env"]`, off `process`, `globalThis.process`,
//     `Deno`, `Bun`, `import.meta`, a `require("process")` call, or a name a file imports
//     the process module as (default or namespace import, or a require);
//   - `env` destructured from any of those (`const { env } = process`);
//   - `env` imported by name from "process" or "node:process", aliased or not.
// Comments and string literals are not code, so a mention there is not a read. The test
// files, the examples and the build scripts are not read. The Go and Python SDKs hold the
// same rule with their own parsers.

import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../", import.meta.url));
const SKIP_DIRS = new Set(["tests", "examples", "scripts", "node_modules"]);
const PROCESS_MODULES = new Set(["process", "node:process"]);
const ENV_HOSTS = new Set(["process", "Deno", "Bun"]);

function libraryFiles(dir: string): string[] {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) return SKIP_DIRS.has(entry.name) ? [] : libraryFiles(path);
		const library = entry.name.endsWith(".ts") && !entry.name.endsWith(".test.ts") && !entry.name.endsWith(".d.ts");
		return library ? [path] : [];
	});
}

function isRequireOfProcess(node: ts.Node): boolean {
	return (
		ts.isCallExpression(node) &&
		ts.isIdentifier(node.expression) &&
		node.expression.text === "require" &&
		node.arguments.length === 1 &&
		ts.isStringLiteralLike(node.arguments[0] as ts.Expression) &&
		PROCESS_MODULES.has((node.arguments[0] as ts.StringLiteralLike).text)
	);
}

// The names one import declaration binds the process module to: its default and
// namespace imports.
function importedProcessNames(node: ts.ImportDeclaration): string[] {
	const clause = node.importClause;
	if (!ts.isStringLiteral(node.moduleSpecifier) || !PROCESS_MODULES.has(node.moduleSpecifier.text) || !clause) {
		return [];
	}
	const names = clause.name ? [clause.name.text] : [];
	const bindings = clause.namedBindings;
	if (bindings && ts.isNamespaceImport(bindings)) names.push(bindings.name.text);
	return names;
}

// The names a file binds the process module to: default and namespace imports, and
// variables initialised with require("process").
function processAliases(file: ts.SourceFile): Set<string> {
	const aliases = new Set<string>();
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node)) for (const name of importedProcessNames(node)) aliases.add(name);
		const required = ts.isVariableDeclaration(node) && node.initializer && isRequireOfProcess(node.initializer);
		if (required && ts.isIdentifier(node.name)) aliases.add(node.name.text);
		ts.forEachChild(node, visit);
	};
	visit(file);
	return aliases;
}

// Whether expr names something whose `env` member is the environment.
function isEnvHost(expr: ts.Expression, aliases: Set<string>): boolean {
	if (ts.isIdentifier(expr)) return ENV_HOSTS.has(expr.text) || aliases.has(expr.text);
	if (ts.isMetaProperty(expr)) return expr.keywordToken === ts.SyntaxKind.ImportKeyword;
	if (ts.isPropertyAccessExpression(expr)) return expr.name.text === "process";
	if (ts.isParenthesizedExpression(expr)) return isEnvHost(expr.expression, aliases);
	return isRequireOfProcess(expr);
}

function readsEnvMember(node: ts.Node, aliases: Set<string>): boolean {
	if (ts.isPropertyAccessExpression(node)) return node.name.text === "env" && isEnvHost(node.expression, aliases);
	if (ts.isElementAccessExpression(node)) {
		const arg = node.argumentExpression;
		return ts.isStringLiteralLike(arg) && arg.text === "env" && isEnvHost(node.expression, aliases);
	}
	return false;
}

function destructuresEnv(node: ts.Node, aliases: Set<string>): boolean {
	if (!ts.isVariableDeclaration(node) || !ts.isObjectBindingPattern(node.name) || node.initializer === undefined) {
		return false;
	}
	if (!isEnvHost(node.initializer, aliases)) return false;
	return node.name.elements.some((el) => (el.propertyName ?? el.name).getText() === "env");
}

function importsEnv(node: ts.Node): boolean {
	if (!ts.isImportDeclaration(node) || !ts.isStringLiteral(node.moduleSpecifier)) return false;
	const bindings = node.importClause?.namedBindings;
	if (!PROCESS_MODULES.has(node.moduleSpecifier.text) || bindings === undefined || !ts.isNamedImports(bindings)) {
		return false;
	}
	return bindings.elements.some((el) => (el.propertyName ?? el.name).text === "env");
}

/** Each environment read in source, as the text of the node that reads it. */
function environmentReads(source: string): string[] {
	const file = ts.createSourceFile("guarded.ts", source, ts.ScriptTarget.Latest, true);
	const aliases = processAliases(file);
	const found: string[] = [];
	const visit = (node: ts.Node): void => {
		if (readsEnvMember(node, aliases) || destructuresEnv(node, aliases) || importsEnv(node)) {
			found.push(node.getText(file));
		}
		ts.forEachChild(node, visit);
	};
	visit(file);
	return found;
}

describe("no SDK library file reads the environment", () => {
	it("holds for every library file", () => {
		const files = libraryFiles(root);
		expect(files.length).toBeGreaterThan(0);
		const offenders = files
			.map((path) => [relative(root, path), environmentReads(readFileSync(path, "utf8"))] as const)
			.filter(([, reads]) => reads.length > 0);
		expect(offenders, "pass the value in through the API instead").toEqual([]);
	});

	it.each([
		"const x = process.env.X;",
		'const x = process["env"];',
		"const x = globalThis.process.env;",
		"const x = Deno.env.get('X');",
		"const x = Bun.env.X;",
		"const x = import.meta.env.X;",
		"const { env } = process;",
		"const { env: e } = globalThis.process;",
		'import { env } from "node:process";',
		'import { env as e } from "process";',
		'import p from "node:process"; const x = p.env;',
		'import * as p from "process"; const x = p.env;',
		'const p = require("node:process"); const x = p.env;',
		'const x = require("process").env;',
		'const s = "a // b # c"; const x = process.env.X;',
	])("catches %s", (source) => {
		expect(environmentReads(source)).toHaveLength(1);
	});

	it.each([
		"// process.env is not read\nconst x = 1;",
		"/* Deno.env */ const x = 1;",
		'const s = "process.env";',
		"const processEnv = 1; const x = processEnv;",
		"const x = config.env;",
		'import { argv } from "node:process";',
	])("does not count %s", (source) => {
		expect(environmentReads(source)).toEqual([]);
	});
});
