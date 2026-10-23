// @fora-protocol/sdk/testing: acceptance signers that admit an empty requester.
//
// They must reproduce byte for byte what the shared corpora record for "a signer without
// the check", answer exactly as the signers they twin for every other input, produce
// nothing the SDK's verifiers accept, and stay out of the SDK: no source file imports
// them. Mirrors sdk/python/tests/test_testing_any_requester.py.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

import {
	acceptancePayload,
	requestAcceptancePayload,
	signOfferAcceptance,
	signRequestAcceptance,
	verifyOfferAcceptance,
	verifyRequestAcceptance,
} from "../src/acceptance.ts";
import {
	acceptancePayloadAnyRequester,
	requestAcceptancePayloadAnyRequester,
	signOfferAcceptanceAnyRequester,
	signRequestAcceptanceAnyRequester,
} from "../src/testing.ts";
import acceptanceVectors from "../../go/helpers/testdata/acceptance-vectors.json";
import requestVectors from "../../go/helpers/testdata/request-acceptance-vectors.json";

type Requester = { requester_id: string; requester_domain: string; idempotency_key: string };
type Signed = { canonical_jcs: string; signature_hex: string; pubkey_b64: string; seed_hex: string };
type OfferRow = Requester & Signed & { name: string; empty?: string; offer_sig: string };
type RequestRow = Requester &
	Signed & { name: string; empty?: string; items: { offer_sig: string; exchange: string }[] };

const offers = acceptanceVectors as { vectors: OfferRow[]; refused: OfferRow[] };
const requests = requestVectors as unknown as { vectors: RequestRow[]; refused: RequestRow[] };

const PKCS8_ED25519_PREFIX = Uint8Array.from([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
	return out;
}

async function signingKey(seedHex: string): Promise<CryptoKey> {
	const seed = hexToBytes(seedHex);
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + seed.length);
	pkcs8.set(PKCS8_ED25519_PREFIX, 0);
	pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
	return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

async function verifyingKey(pubB64: string): Promise<CryptoKey> {
	const raw = Uint8Array.from(atob(pubB64), (c) => c.charCodeAt(0));
	return crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
}

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

function offerInput(row: OfferRow) {
	return {
		offerSig: row.offer_sig,
		requesterId: row.requester_id,
		requesterDomain: row.requester_domain,
		idempotencyKey: row.idempotency_key,
	};
}

function requestInput(row: RequestRow) {
	return {
		items: row.items.map((i) => ({ offerSig: i.offer_sig, exchange: i.exchange })),
		requesterId: row.requester_id,
		requesterDomain: row.requester_domain,
		idempotencyKey: row.idempotency_key,
	};
}

// The row's signature verifies over its bytes, so a refusal of them is a refusal of the
// requester alone.
async function expectTheRecordedSignatureVerifies(row: Signed): Promise<void> {
	const ok = await crypto.subtle.verify(
		"Ed25519",
		await verifyingKey(row.pubkey_b64),
		hexToBytes(row.signature_hex),
		new TextEncoder().encode(row.canonical_jcs),
	);
	expect(ok).toBe(true);
}

describe("the refused rows are reproduced", () => {
	for (const row of offers.refused) {
		it(`offer acceptance ${row.name}`, async () => {
			const input = offerInput(row);
			expect(text(acceptancePayloadAnyRequester(input))).toBe(row.canonical_jcs);
			expect(await signOfferAcceptanceAnyRequester(input, await signingKey(row.seed_hex))).toBe(row.signature_hex);
			await expectTheRecordedSignatureVerifies(row);
			// The protocol's own canonicalizer and verifier refuse the same bytes.
			expect(() => acceptancePayload(input)).toThrow(/empty requester/);
			expect(await verifyOfferAcceptance(input, row.signature_hex, await verifyingKey(row.pubkey_b64))).toBe(false);
		});
	}
	for (const row of requests.refused) {
		it(`request acceptance ${row.name}`, async () => {
			const input = requestInput(row);
			expect(text(requestAcceptancePayloadAnyRequester(input))).toBe(row.canonical_jcs);
			expect(await signRequestAcceptanceAnyRequester(input, await signingKey(row.seed_hex))).toBe(row.signature_hex);
			await expectTheRecordedSignatureVerifies(row);
			expect(() => requestAcceptancePayload(input)).toThrow(/empty requester/);
			expect(await verifyRequestAcceptance(input, row.signature_hex, await verifyingKey(row.pubkey_b64))).toBe(false);
		});
	}

	it("cover both requester fields", () => {
		for (const doc of [offers, requests]) {
			expect(new Set(doc.refused.map((r) => r.empty))).toEqual(new Set(["requester_id", "requester_domain"]));
		}
	});
});

describe("on a named requester the twins are the signers", () => {
	for (const row of offers.vectors) {
		it(`offer acceptance ${row.name}`, async () => {
			const input = offerInput(row);
			const key = await signingKey(row.seed_hex);
			expect(text(acceptancePayloadAnyRequester(input))).toBe(text(acceptancePayload(input)));
			expect(await signOfferAcceptanceAnyRequester(input, key)).toBe(await signOfferAcceptance(input, key));
		});
	}
	for (const row of requests.vectors) {
		it(`request acceptance ${row.name}`, async () => {
			const input = requestInput(row);
			const key = await signingKey(row.seed_hex);
			expect(text(requestAcceptancePayloadAnyRequester(input))).toBe(text(requestAcceptancePayload(input)));
			expect(await signRequestAcceptanceAnyRequester(input, key)).toBe(await signRequestAcceptance(input, key));
		});
	}
});

describe("every other refusal is the signers'", () => {
	const named = { requesterId: "agent-1", requesterDomain: "agent.example", idempotencyKey: "i" };
	const errorOf = (run: () => unknown): string => {
		try {
			run();
		} catch (err) {
			return (err as Error).message;
		}
		throw new Error("expected a refusal");
	};
	for (const input of [
		{ ...named, offerSig: "" },
		// An unsigned offer is refused before the requester is looked at, by both.
		{ ...named, offerSig: "", requesterId: "" },
	]) {
		it(`offer acceptance ${JSON.stringify(input)}`, () => {
			expect(errorOf(() => acceptancePayloadAnyRequester(input))).toBe(errorOf(() => acceptancePayload(input)));
		});
	}
	for (const items of [
		[],
		[{ offerSig: "", exchange: "one.example" }],
		[{ offerSig: "sig", exchange: "" }],
		[
			{ offerSig: "sig", exchange: "one.example" },
			{ offerSig: "", exchange: "" },
		],
	]) {
		it(`request acceptance ${JSON.stringify(items)}`, () => {
			const input = { ...named, items };
			expect(errorOf(() => requestAcceptancePayloadAnyRequester(input))).toBe(
				errorOf(() => requestAcceptancePayload(input)),
			);
		});
	}
	it("past an empty requester, the next refusal is the signer's next", () => {
		expect(() => requestAcceptancePayloadAnyRequester({ ...named, requesterId: "", items: [] })).toThrow(
			new Error("fora/acceptance: request acceptance requires at least one item"),
		);
	});
});

describe("the test signers stay out of the SDK", () => {
	// An import is checked by the module it resolves to, the way the compiler resolves it
	// under this package's tsconfig, as the Go and Python guards read imports with their
	// languages' parsers. So an extensionless or .js specifier, the package's own name and
	// a literal import() are all caught, and a comment or a string that merely names the
	// module is not. Only an import() of a computed string is beyond a static check.
	const root = fileURLToPath(new URL("..", import.meta.url));
	const tsconfig = ts.parseJsonConfigFileContent(
		ts.readConfigFile(join(root, "tsconfig.json"), ts.sys.readFile).config,
		ts.sys,
		root,
	);
	const testing = join(root, "src", "testing.ts");
	const renderer = join(root, "src", "acceptance-render.ts");

	/** Whether source, written as file, imports module (an absolute path). */
	const imports = (file: string, source: string, module: string): boolean =>
		ts.preProcessFile(source, true, true).importedFiles.some(({ fileName }) => {
			const resolved = ts.resolveModuleName(fileName, file, tsconfig.options, ts.sys).resolvedModule;
			return resolved !== undefined && resolve(resolved.resolvedFileName) === module;
		});

	const sources = (dir: string): string[] =>
		readdirSync(join(root, dir)).flatMap((name) => {
			const path = join(root, dir, name);
			if (statSync(path).isDirectory()) return sources(relative(root, path));
			return name.endsWith(".ts") ? [relative(root, path)] : [];
		});
	const files = ["src", "core", "client", "resolvers", "hono"].flatMap(sources);
	const importsOf = (file: string, module: string): boolean =>
		imports(join(root, file), readFileSync(join(root, file), "utf8"), module);

	it("no source file imports ./testing", () => {
		expect(tsconfig.errors).toEqual([]);
		expect(files.length).toBeGreaterThan(0);
		expect(files.filter((f) => importsOf(f, testing))).toEqual([]);
	});

	it("only the two signers import the shared renderer", () => {
		expect(files.filter((f) => importsOf(f, renderer)).sort()).toEqual([
			join("src", "acceptance.ts"),
			join("src", "testing.ts"),
		]);
	});

	describe("the check itself", () => {
		const inSrc = join(root, "src", "probe.ts");
		const inClient = join(root, "client", "probe.ts");
		const bt = "`";

		it.each([
			["an extensionless specifier", inSrc, `import { a } from "./testing";`],
			["a .js specifier", inSrc, `import { a } from "./testing.js";`],
			["a .ts specifier", inSrc, `import { a } from "./testing.ts";`],
			["a path from another directory", inClient, `import { a } from "../src/testing";`],
			["a re-export", inSrc, `export * from "./testing.ts";`],
			["a side-effect import", inSrc, `import "./testing.ts";`],
			["a dynamic import", inSrc, `const m = await import("./testing.ts");`],
			["a dynamic import of a template literal", inSrc, `const m = await import(${bt}./testing.ts${bt});`],
			["a type-only import", inSrc, `import type { A } from "./testing.ts";`],
			["the package's own name", inSrc, `import { a } from "@fora-protocol/sdk-l1/testing";`],
		])("catches %s", (_, file, source) => {
			expect(imports(file, source, testing)).toBe(true);
		});

		it.each([
			["a line comment", `// import { a } from "./testing.ts";`],
			["a block comment", `/* import { a } from "./testing.ts"; */`],
			["a string", `const s = "./testing.ts";`],
			["the protocol's signers", `import { a } from "./acceptance.ts";`],
			["a dependency", `import { describe } from "vitest";`],
		])("ignores %s", (_, source) => {
			expect(imports(inSrc, source, testing)).toBe(false);
		});

		it("catches an extensionless import of the shared renderer", () => {
			expect(imports(inClient, `import { r } from "../src/acceptance-render";`, renderer)).toBe(true);
		});
	});
});
