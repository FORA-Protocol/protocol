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
 * Return the report the script printed on `stdout`, or null when it printed none.
 * Output that is not one whole JSON report fails with its size, so a report that
 * arrived cut short says so.
 * @param {string} stdout
 */
function reportOf(stdout) {
	if (!stdout) {
		return null;
	}
	try {
		return JSON.parse(stdout);
	} catch (error) {
		assert.fail(`stdout (${Buffer.byteLength(stdout)} bytes) is not one JSON report: ${error}`);
	}
}

/**
 * Build a throwaway site with `components` (file name to text) under src/, run the
 * script there, and return its exit code, its stdout, its report (or null) and its
 * stderr.
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
			// Past maxBuffer Node kills the child and cuts its output short, which would
			// read as the script's own failure; this is far above any report a test writes.
			maxBuffer: 16 * 1024 * 1024,
		});
		assert.equal(proc.error, undefined, `the script did not run to its end: ${proc.error}`);
		return { code: proc.status, stdout: proc.stdout, report: reportOf(proc.stdout), stderr: proc.stderr };
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

// Enough failing lines that the report is far larger than a pipe or a socket takes in
// one write, so the script has to wait for its reader to take the rest before it exits.
const LINES = 5000;

test("a report larger than its reader takes at once arrives whole", () => {
	const body = Array.from({ length: LINES }, () => 'n = "x";').join("\n");
	const { code, stdout, report } = run({ "Many.astro": `---\nlet n: number = 0;\n${body}\n---\n<p>{n}</p>\n` });
	assert.equal(code, 1);
	const bytes = Buffer.byteLength(stdout);
	assert.ok(bytes >= 512 * 1024, `the report is only ${bytes} bytes, too small to need more than one write`);
	/** @type {number[]} */
	const lines = [];
	const kinds = new Set();
	for (const d of report.diagnostics) {
		lines.push(d.line);
		kinds.add(`${d.path} ${d.code}`);
	}
	assert.deepEqual([...kinds], ["website/src/Many.astro ts(2322)"]);
	// The checker lists them in no promised order; every planted line is there once.
	assert.deepEqual(
		lines.sort((a, b) => a - b),
		Array.from({ length: LINES }, (_, i) => i + 3),
	);
});
