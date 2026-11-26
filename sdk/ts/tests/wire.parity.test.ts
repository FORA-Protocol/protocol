// Wire-constants parity (TypeScript side): wire.ts exposes the eight wire
// constants with the exact values the Go oracle carries.
//
// sdk/ts `wire.ts` MUST expose the eight wire constants with the EXACT values the
// sdk/go oracle carries. The shared vectors at
// sdk/go/helpers/testdata/wire-constants-vectors.json carry {name, value},
// referenced from the real Go exported constants (never hand-typed). The Go
// layer splits RequestIDHeader across helpers/constants.go and core/requestid.go;
// the single TS wire module exposes all eight once.
//
// RED now purely because sdk/ts/src/wire.ts does not exist yet.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as generated from "../../../gen/ts/wire/version.ts";
import vectorsFile from "../../go/helpers/testdata/wire-constants-vectors.json";
import { acceptSignature } from "../core/sign-request.ts";
// RED: sdk/ts/src/wire.ts does not exist yet (TDD red — missing face).
import * as wire from "../src/wire.ts";

type WireVector = { name: string; value: string };
type WireVectorsFile = { vectors: WireVector[] };

const vectors = (vectorsFile as WireVectorsFile).vectors;

// The Go identifier → the TS export name (same PascalCase→SCREAMING or camel
// choice is the implementer's; here we assert the VALUE is present under a
// matching export). Map by Go name to the TS symbol the port must export.
const exportFor: Record<string, keyof typeof wire> = {
	ContentTypeProto: "ContentTypeProto",
	ContentTypeJSON: "ContentTypeJSON",
	ConnectProtocolVersionHeader: "ConnectProtocolVersionHeader",
	ConnectProtocolVersion: "ConnectProtocolVersion",
	ProtocolVersion: "ProtocolVersion",
	WellKnownManifestVersion: "WellKnownManifestVersion",
	RequestIDHeader: "RequestIDHeader",
	SignatureAgentHeader: "SignatureAgentHeader",
	AgentKeyHeader: "AgentKeyHeader",
	WellKnownPath: "WellKnownPath",
	ContentRulesHeader: "ContentRulesHeader",
	ExchangeHeader: "ExchangeHeader",
	WBATag: "WBATag",
	DirectoryResponseTag: "DirectoryResponseTag",
	AcceptSignatureHeader: "AcceptSignatureHeader",
};

// The two Accept-Signature values are not constants in any SDK: they are what
// acceptSignature(entitlement) renders, so the vector pins the function's output.
const computed: Record<string, string> = {
	AcceptSignature: acceptSignature(false),
	AcceptSignatureWithEntitlement: acceptSignature(true),
};

describe("sdk/ts wire constants match the sdk/go oracle vectors", () => {
	it("wire-constants vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	for (const v of vectors) {
		it(`wire.${v.name} === ${JSON.stringify(v.value)}`, () => {
			if (v.name in computed) {
				expect(computed[v.name]).toBe(v.value);
				return;
			}
			const sym = exportFor[v.name];
			expect(sym).toBeDefined();
			expect((wire as Record<string, unknown>)[sym as string]).toBe(v.value);
		});
	}
});

// declaresLiteral reports whether source gives name a string literal of its own,
// rather than reading the generated constant.
function declaresLiteral(source: string, name: string): boolean {
	return new RegExp(`export const ${name}\\s*(?::[^=]+)?=\\s*["'\`]`).test(source);
}

describe("the version constants re-export the generated values", () => {
	const source = readFileSync(new URL("../src/wire.ts", import.meta.url), "utf8");
	const versions = [
		["ProtocolVersion", wire.ProtocolVersion, generated.ProtocolVersion],
		["WellKnownManifestVersion", wire.WellKnownManifestVersion, generated.WellKnownManifestVersion],
	] as const;
	for (const [name, sdkValue, generatedValue] of versions) {
		it(`${name} is the generated constant, not a literal of the SDK's own`, () => {
			expect(declaresLiteral(source, name)).toBe(false);
			expect(source).toContain(`export const ${name} = generated.${name};`);
			expect(sdkValue).toBe(generatedValue);
		});
	}

	it("the literal check flags a literal and passes the re-export", () => {
		expect(declaresLiteral('export const ProtocolVersion = "1.0";', "ProtocolVersion")).toBe(true);
		expect(declaresLiteral("export const ProtocolVersion = generated.ProtocolVersion;", "ProtocolVersion")).toBe(false);
	});
});
