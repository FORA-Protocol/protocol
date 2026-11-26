// Run API Extractor over every entry point of the TypeScript SDK, and print one JSON line
// per entry point: its export subpath, its source file, its report's path relative to the
// report folder, the report API Extractor generated, and the warnings and errors it
// reported. scripts/gates/api_diff.py runs it, for the tree and for the last release.
//
// The entry points are the export map of TREE/sdk/ts/package.json, the map the published
// package is built from. Each entry point's declarations are read from DTS, which mirrors
// TREE's layout (tsc writes them there). One TypeScript program is built for all of them
// and shared, so the declarations are parsed once. The report of `./core/sign` is
// `core/sign.api.md` under the report folder.
//
// check  compares each generated report with the committed one in REPORTS, and reports
//        each that is missing or differs (API Extractor's console-api-report-not-copied).
// write  writes each generated report into REPORTS.
//
// Only API Extractor's own console messages and the compiler's are reported; its
// documentation messages (a missing release tag, an undocumented member) are not this
// gate's subject, and are turned off. Imports from packages resolve against the
// TypeScript SDK's own node_modules in this checkout, for either tree.
//
// Usage:  node scripts/gates/api-extractor.mjs check|write TREE DTS REPORTS

import { mkdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CompilerState, Extractor, ExtractorConfig, ExtractorLogLevel } from "@microsoft/api-extractor";

const modules = resolve(dirname(fileURLToPath(import.meta.url)), "../../sdk/ts/node_modules");

/**
 * @param {string} dts
 * @param {string} entry
 */
const compilerOptions = (dts, entry) => ({
	compilerOptions: {
		module: "ESNext",
		moduleResolution: "Bundler",
		target: "ES2022",
		allowImportingTsExtensions: true,
		strict: true,
		skipLibCheck: true,
		lib: ["ES2023", "DOM"],
		types: ["node"],
		typeRoots: [join(modules, "@types")],
		paths: { "*": [join(modules, "*")] },
	},
	files: [join(dts, entry)],
});

const silent = { default: { logLevel: ExtractorLogLevel.None, addToApiReportFile: false } };

/**
 * One entry point's API Extractor configuration. In write mode its report folder is
 * created; a check never writes into the report folder.
 *
 * @param {{ mode: string, tree: string, dts: string, reports: string, temp: string }} dirs
 * @param {string} subpath
 * @param {string} target
 */
function configure(dirs, subpath, target) {
	const report = `${subpath.slice(2)}.api.md`;
	const entry = `sdk/ts/${target.slice(2).replace(/\.ts$/, ".d.ts")}`;
	const folder = dirname(join(dirs.reports, report));
	if (dirs.mode === "write") mkdirSync(folder, { recursive: true });
	const config = ExtractorConfig.prepare({
		configObject: {
			projectFolder: dirs.dts,
			newlineKind: "lf",
			mainEntryPointFilePath: join(dirs.dts, entry),
			compiler: { overrideTsconfig: compilerOptions(dirs.dts, entry) },
			apiReport: {
				enabled: true,
				reportFileName: report.split("/").pop() ?? report,
				reportFolder: folder,
				reportTempFolder: dirname(join(dirs.temp, report)),
			},
			docModel: { enabled: false },
			dtsRollup: { enabled: false },
			tsdocMetadata: { enabled: false },
			messages: {
				extractorMessageReporting: silent,
				tsdocMessageReporting: silent,
				compilerMessageReporting: { default: { logLevel: ExtractorLogLevel.Warning } },
			},
		},
		configObjectFullPath: join(dirs.dts, "api-extractor.json"),
		packageJsonFullPath: join(dirs.tree, "sdk/ts/package.json"),
	});
	return { subpath, source: `sdk/ts/${target.slice(2)}`, report, config };
}

/**
 * Run each entry point and print its JSON line.
 *
 * @param {{ mode: string, tree: string, dts: string, reports: string, temp: string }} dirs
 */
function main(dirs) {
	// A message names files by absolute path, under temporary directories; the tree's
	// and the declarations' prefixes are dropped, so a message reads the same every run.
	/** @param {string} text */
	const relative = (text) => text.replaceAll(`${dirs.dts}/`, "").replaceAll(`${dirs.tree}/`, "");
	/** @type {Record<string, string>} */
	const exportsMap = JSON.parse(readFileSync(join(dirs.tree, "sdk/ts/package.json"), "utf8")).exports;
	const entries = Object.entries(exportsMap).map(([subpath, target]) => configure(dirs, subpath, target));
	const first = entries[0];
	if (first === undefined) throw new Error(`${dirs.tree}/sdk/ts/package.json exports nothing`);
	const compilerState = CompilerState.create(first.config, {
		additionalEntryPoints: entries.map((e) => e.config.mainEntryPointFilePath),
	});
	for (const { subpath, source, report, config } of entries) {
		/** @type {{ id: string, level: string, category: string, text: string }[]} */
		const messages = [];
		Extractor.invoke(config, {
			compilerState,
			localBuild: dirs.mode === "write",
			messageCallback: (m) => {
				m.handled = true;
				if (m.logLevel === ExtractorLogLevel.Warning || m.logLevel === ExtractorLogLevel.Error)
					messages.push({ id: m.messageId, level: m.logLevel, category: m.category, text: relative(m.text) });
			},
		});
		const text = readFileSync(join(dirs.temp, report), "utf8");
		process.stdout.write(`${JSON.stringify({ entry: subpath, source, report, text, messages })}\n`);
	}
}

const [mode, tree, dts, reports] = process.argv.slice(2);
if ((mode !== "check" && mode !== "write") || !tree || !dts || !reports) {
	process.stderr.write("usage: node scripts/gates/api-extractor.mjs check|write TREE DTS REPORTS\n");
	process.exit(2);
}
main({ mode, tree, dts, reports, temp: join(dts, ".api-extractor") });
