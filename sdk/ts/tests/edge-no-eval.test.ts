// The edge entry runs where code generation from strings is refused.
//
// Cloudflare Workers refuses eval and new Function: "EvalError: Code generation from
// strings disallowed for this context". A strict check that compiled its JSON Schema
// validator at run time failed there on every document, while the Workers vitest pool,
// which allows eval, passed. This test builds the edge entry the way a Worker is built
// (esbuild, platform neutral, the workerd/worker/browser conditions) and runs the readers
// in a Node vm context created with code generation from strings disabled, which refuses
// eval and new Function with the same EvalError. Every reader that runs the strict check
// is driven to an accepted document, and a refused one, and the check by message name is
// run too. The context has no global ReadableStream, as the reader's bounds must not
// need one: an over-cap body and an https-to-http redirect are refused there too.

import { createRequire } from "node:module";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const esbuild = require("esbuild") as typeof import("esbuild");

const here = (p: string): string => fileURLToPath(new URL(p, import.meta.url));

// The probe a Worker would run: each reader against a fetch answering one document.
const PROBE = `
import { readLicenseDocument, readManifest, readRevocationList, readWBADirectory, StrictViolation } from ${JSON.stringify(here("../resolvers/edge.ts"))};
import { checkStrict } from ${JSON.stringify(here("../src/strict.ts"))};

const serve = (body, contentType) => async () =>
	new Response(body, { status: 200, headers: contentType ? { "content-type": contentType } : {} });

async function outcome(run) {
	try {
		await run();
		return "ok";
	} catch (e) {
		return e instanceof StrictViolation ? "strict" : (e?.name ?? "error") + ": " + (e?.message ?? String(e));
	}
}

async function sha256(text) {
	const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
	return "sha256:" + Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

globalThis.probe = async () => {
	const manifest = JSON.stringify({
		ver: "1.0",
		role: "ROLE_PUBLISHER",
		domain: "pub.example",
		exchanges: [{ domain: "x.example", endpoint: "https://x.example", relationship: "PROVIDER_RELATIONSHIP_DIRECT" }],
	});
	const text = "Licensed for retrieval-augmented answers.\\n";
	return {
		manifest: await outcome(() => readManifest("pub.example", { fetch: serve(manifest, "application/json") })),
		manifestUnknownField: await outcome(() =>
			readManifest("pub.example", { fetch: serve(JSON.stringify({ ...JSON.parse(manifest), surplus: 1 }), "application/json") }),
		),
		directory: await outcome(() =>
			readWBADirectory("pub.example", { fetch: serve('{"keys":[]}', "application/http-message-signatures-directory+json") }),
		),
		directoryUnknownField: await outcome(() =>
			readWBADirectory("pub.example", {
				fetch: serve('{"keys":[],"surplus":1}', "application/http-message-signatures-directory+json"),
			}),
		),
		revocations: await outcome(() =>
			readRevocationList("https://pub.example/revoked.json", {
				fetch: serve('{"as_of":"2026-05-01T12:00:00Z","revoked":[]}'),
			}),
		),
		revocationsOverCap: await outcome(() =>
			readRevocationList("https://pub.example/revoked.json", { fetch: serve(new Uint8Array(1048577)) }),
		),
		revocationsDowngrade: await outcome(() =>
			readRevocationList("https://pub.example/revoked.json", {
				fetch: async () => new Response(null, { status: 302, headers: { location: "http://pub.example/revoked.json" } }),
			}),
		),
		license: await outcome(async () =>
			readLicenseDocument({ uri: "https://pub.example/terms.txt", uri_digest: await sha256(text) }, { fetch: serve(text) }),
		),
		byName: await outcome(async () => checkStrict("fora.v1.ErrorDetail", { surplus: 1 })),
	};
};
`;

async function buildProbe(): Promise<string> {
	const out = await esbuild.build({
		stdin: { contents: PROBE, resolveDir: here("."), loader: "ts" },
		bundle: true,
		write: false,
		format: "iife",
		platform: "neutral",
		conditions: ["workerd", "worker", "browser"],
		mainFields: ["module", "main"],
		// One zod for the bundle, the one this package installed (vitest.config.ts says why).
		alias: { zod: here("../node_modules/zod") },
		logLevel: "silent",
	});
	const file = out.outputFiles[0];
	if (file === undefined) throw new Error("esbuild produced no output");
	return file.text;
}

// noEvalContext is a context with the globals a Worker has and code generation from
// strings disabled.
function noEvalContext(): vm.Context {
	return vm.createContext(
		{
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
		},
		{ codeGeneration: { strings: false, wasm: false } },
	);
}

describe("the edge entry in a context that refuses code generation from strings", () => {
	it("refuses eval and new Function, as Workers does", () => {
		const context = noEvalContext();
		const refused = vm.runInContext(
			"(() => { try { new Function('return 1')(); return 'allowed'; } catch (e) { return e.name + ': ' + e.message; } })()",
			context,
		);
		expect(refused).toMatch(/^EvalError: Code generation from strings disallowed/);
	});

	it("runs every strict reader and the check by name without generating code", async () => {
		const context = noEvalContext();
		vm.runInContext(await buildProbe(), context);
		const results = await (context as { probe: () => Promise<Record<string, string>> }).probe();
		expect(results).toEqual({
			manifest: "ok",
			manifestUnknownField: "strict",
			directory: "ok",
			directoryUnknownField: "strict",
			revocations: "ok",
			revocationsOverCap: expect.stringMatching(/^DirectoryUnavailable: /),
			revocationsDowngrade: expect.stringMatching(/^DirectoryUnavailable: /),
			license: "ok",
			byName: "strict",
		});
	}, 60_000);
});
