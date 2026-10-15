// The edge entry as an edge runtime runs it: bundled the way that runtime's build bundles
// it, and run in a Node vm context that holds only the globals that runtime has.
// edge-no-eval.test.ts runs it as Cloudflare Workers does, where code generation from
// strings is refused; edge-fastly-globals.test.ts as Fastly Compute's JavaScript runtime,
// which has no AbortController and no AbortSignal. Each probe imports the modules it drives
// by absolute path (here) and leaves its entry points on globalThis. The edge-imports guard
// bundles the edge-safe surface through bundleSource to find the globals it reaches.

import { createRequire } from "node:module";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const esbuild = require("esbuild") as typeof import("esbuild");

/** The absolute path of `p`, relative to this directory: how a probe names its imports. */
export const here = (p: string): string => fileURLToPath(new URL(p, import.meta.url));

/** The package conditions a Cloudflare Workers build resolves. */
export const WORKERS_CONDITIONS = ["workerd", "worker", "browser"] as const;

/** The package conditions a Fastly Compute build resolves. */
export const FASTLY_CONDITIONS = ["fastly", "worker", "browser"] as const;

/** Every global Fastly Compute's JavaScript runtime declares (@fastly/js-compute 3.43.1,
 * types/globals.d.ts). AbortController and AbortSignal are not among them, and its
 * RequestInit takes no signal. */
export const FASTLY_GLOBAL_NAMES: readonly string[] = [
	"addEventListener",
	"atob",
	"Backend",
	"Blob",
	"btoa",
	"CacheOverride",
	"clearInterval",
	"clearTimeout",
	"CompressionStream",
	"ConfigStore",
	"console",
	"crypto",
	"Crypto",
	"CryptoKey",
	"DecompressionStream",
	"Dictionary",
	"Event",
	"EventTarget",
	"fastly",
	"fetch",
	"File",
	"FormData",
	"Headers",
	"KVStore",
	"location",
	"onfetch",
	"performance",
	"Performance",
	"queueMicrotask",
	"ReadableStream",
	"ReadableStreamDefaultController",
	"ReadableStreamDefaultReader",
	"Request",
	"Response",
	"self",
	"setInterval",
	"setTimeout",
	"structuredClone",
	"SubtleCrypto",
	"TextDecoder",
	"TextEncoder",
	"TransformStream",
	"TransformStreamDefaultController",
	"URL",
	"URLSearchParams",
	"WorkerLocation",
	"WritableStream",
	"WritableStreamDefaultController",
	"WritableStreamDefaultWriter",
];

/** How bundleSource bundles one in-memory module. */
export interface BundleOptions {
	/** The package conditions the runtime's build resolves. */
	conditions: readonly string[];
	/** "iife" for a probe a context runs, "esm" for a bundle that is only read. */
	format: "iife" | "esm";
	/** Globals replaced as esbuild's define replaces them. */
	define?: Record<string, string>;
	/** Packages left out of the bundle. */
	external?: string[];
}

/** bundleSource bundles `source`, a module whose imports name absolute paths, into one
 * script. */
export async function bundleSource(source: string, opts: BundleOptions): Promise<string> {
	const external = opts.external ?? [];
	const out = await esbuild.build({
		stdin: { contents: source, resolveDir: here("."), loader: "ts" },
		bundle: true,
		write: false,
		format: opts.format,
		platform: "neutral",
		conditions: [...opts.conditions],
		mainFields: ["module", "main"],
		// One zod for the bundle, the one this package installed (vitest.config.ts says why).
		// An alias names zod by path, which an external "zod" would no longer match, so a
		// bundle that leaves zod out takes no alias.
		...(external.includes("zod") ? {} : { alias: { zod: here("../node_modules/zod") } }),
		...(opts.define !== undefined ? { define: opts.define } : {}),
		external,
		logLevel: "silent",
	});
	const file = out.outputFiles[0];
	if (file === undefined) throw new Error("esbuild produced no output");
	return file.text;
}

/** bundleProbe bundles a probe into one script a context can run, as an esbuild build for
 * a runtime resolving `conditions` would. */
export const bundleProbe = (source: string, conditions: readonly string[]): Promise<string> =>
	bundleSource(source, { conditions, format: "iife" });

/** The globals a Worker has that the readers reach. There is no ReadableStream among them,
 * as the reader's bounds must not need one. Read at the call, so a context made after
 * vi.useFakeTimers() runs on the fake timers. */
export function workersGlobals(): Record<string, unknown> {
	return {
		Response,
		Headers,
		Request,
		URL,
		URLSearchParams,
		TextEncoder,
		TextDecoder,
		crypto,
		console,
		setTimeout,
		clearTimeout,
		AbortController,
		AbortSignal,
		atob,
		btoa,
		structuredClone,
		queueMicrotask,
	};
}

/** The globals of FASTLY_GLOBAL_NAMES that Node can supply, and no other. Read at the call,
 * as workersGlobals is. */
export function fastlyGlobals(): Record<string, unknown> {
	const host = globalThis as unknown as Record<string, unknown>;
	return Object.fromEntries(FASTLY_GLOBAL_NAMES.filter((name) => name in host).map((name) => [name, host[name]]));
}

/** sandbox is a context holding `globals` and nothing else. Code generation from strings is
 * refused, as Workers refuses it, which is at least as strict as either runtime. */
export function sandbox(globals: Record<string, unknown>): vm.Context {
	return vm.createContext(globals, { codeGeneration: { strings: false, wasm: false } });
}
