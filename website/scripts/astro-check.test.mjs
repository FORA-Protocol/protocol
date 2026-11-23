// Tests for astro-check.mjs, run as the type gate runs it: `node astro-check.mjs`, as a
// child process. Each test builds a throwaway site holding a copy of the script, the
// site's tsconfig.json, its installed packages (linked) and the components the test
// writes, because the script checks the site it sits in.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const site = path.dirname(here);

/**
 * Build a throwaway site with `components` (file name to text) under src/, run the
 * script there, and return its exit code, its report (or null) and its stderr.
 * @param {Record<string, string>} components
 */
function run(components) {
	const repo = mkdtempSync(path.join(tmpdir(), "astro-check-"));
	try {
		const root = path.join(repo, "website");
		mkdirSync(path.join(root, "scripts"), { recursive: true });
		mkdirSync(path.join(root, "src"));
		copyFileSync(path.join(here, "astro-check.mjs"), path.join(root, "scripts", "astro-check.mjs"));
		copyFileSync(path.join(site, "tsconfig.json"), path.join(root, "tsconfig.json"));
		writeFileSync(path.join(repo, "tsconfig.strict.json"), '{ "compilerOptions": { "strict": true } }\n');
		symlinkSync(path.join(site, "node_modules"), path.join(root, "node_modules"), "dir");
		for (const [name, text] of Object.entries(components)) {
			writeFileSync(path.join(root, "src", name), text);
		}
		const proc = spawnSync(process.execPath, [path.join(root, "scripts", "astro-check.mjs")], {
			encoding: "utf8",
		});
		return { code: proc.status, report: proc.stdout ? JSON.parse(proc.stdout) : null, stderr: proc.stderr };
	} finally {
		rmSync(repo, { recursive: true, force: true });
	}
}

test("a clean component is checked and reports nothing", () => {
	const { code, report } = run({ "Clean.astro": "---\nconst n: number = 1;\n---\n<p>{n}</p>\n" });
	assert.equal(code, 0);
	assert.deepEqual(report, { checked: ["website/src/Clean.astro"], diagnostics: [] });
});

test("a type error is reported with its path, line and code, and exits 1", () => {
	const { code, report } = run({ "Bad.astro": '---\nconst n: number = "one";\n---\n<p>{n}</p>\n' });
	assert.equal(code, 1);
	assert.equal(report.diagnostics.length, 1);
	const [d] = report.diagnostics;
	assert.deepEqual([d.path, d.line, d.code], ["website/src/Bad.astro", 2, "ts(2322)"]);
	assert.match(d.message, /'string' is not assignable to type 'number'/);
});

test("an import that does not resolve stops with exit 3 and no report", () => {
	const component = '---\nimport { x } from "no-such-package";\n---\n<p>{x}</p>\n';
	const { code, report, stderr } = run({ "Unresolved.astro": component });
	assert.equal(code, 3);
	assert.equal(report, null);
	assert.match(stderr, /an import does not resolve/);
	assert.match(stderr, /ts\(2307\)/);
});

test("a site with no component stops with exit 3", () => {
	const { code, report, stderr } = run({ "only.ts": "export const n = 1;\n" });
	assert.equal(code, 3);
	assert.equal(report, null);
	assert.match(stderr, /holds no \.astro file/);
});
