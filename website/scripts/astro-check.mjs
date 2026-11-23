// Type-check the site's Astro components with the checker `astro check` runs, and print
// what it finds as one JSON report, for the astro-check format of
// scripts/gates/ratchet.py. scripts/gates/gate-astro-types.sh runs it.
//
// The checker is @astrojs/language-server's AstroCheck, over the site's own project
// (tsconfig.json), with the TypeScript that package-lock.json pins. Only the .astro
// files are checked here: tsc reads the site's TypeScript and JavaScript in
// scripts/gates/gate-ts-types.sh, and does not read .astro files.
//
// The report is {"checked": [paths], "diagnostics": [{path, line, code, severity,
// message}]}, with paths relative to the repository root and 1-based lines. Every
// diagnostic is reported, whatever its severity. The script exits 0 when there is no
// diagnostic and 1 when there is one. It exits 3, after printing the diagnostics on
// stderr, when an import does not resolve (TS2307, TS2792, or TS7016 for a module with
// no types): the checker then reads the module as any, so the run did not check the
// components as written. It exits 3 too when the project holds no .astro file, so a
// misplaced project cannot read as a clean run. A crash exits 1 and prints no report,
// which the format refuses.
//
// Usage:  node website/scripts/astro-check.mjs

import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AstroCheck } from "@astrojs/language-server";

const UNRESOLVED = new Set([2307, 2792, 7016]);
const site = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repo = path.dirname(site);
const require = createRequire(import.meta.url);

/** @param {string} file @returns {string} the path relative to the repository root */
function relative(file) {
	return path.relative(repo, file).split(path.sep).join("/");
}

/**
 * @param {string} file
 * @param {import("@astrojs/language-server").Diagnostic} d
 */
function finding(file, d) {
	return {
		path: relative(file),
		line: d.range.start.line + 1,
		code: `${d.source ?? "astro"}(${d.code ?? "none"})`,
		severity: d.severity ?? 1,
		message: d.message,
	};
}

const checker = new AstroCheck(site, require.resolve("typescript"), path.join(site, "tsconfig.json"));
const files = checker.linter.getRootFileNames().filter((f) => f.endsWith(".astro"));
if (files.length === 0) {
	console.error("astro-check.mjs: the site's project holds no .astro file");
	process.exit(3);
}
const result = await checker.lint({ fileNames: files });
const diagnostics = result.fileResult.flatMap((r) => r.errors.map((d) => finding(fileURLToPath(r.fileUrl), d)));
const unresolved = diagnostics.filter((d) => d.code.startsWith("ts(") && UNRESOLVED.has(Number(d.code.slice(3, -1))));
if (unresolved.length > 0) {
	console.error(JSON.stringify(unresolved, null, 1));
	console.error("astro-check.mjs: an import does not resolve, so the checker read it as any");
	process.exit(3);
}
console.log(JSON.stringify({ checked: files.map(relative).sort(), diagnostics }));
process.exit(diagnostics.length > 0 ? 1 : 0);
