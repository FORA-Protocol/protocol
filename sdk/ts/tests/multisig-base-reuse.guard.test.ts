import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Structural guard for the "forked signature-base builder" disease.
//
// DISEASE: an RFC 9421 signature base is rendered by hand in a second place — a
// template of `"<component>": ${value}` lines ending in the @signature-params line. A
// fork is how a covered-component change silently drifts one path out of byte-parity
// with the Go oracle: the signer and the verifier, or the request path and the delivery
// proof, stop rebuilding the same bytes.
//
// The invariant: exactly one file under sdk/ts/core + sdk/ts/src renders the
// @signature-params line, core/sign-request.ts (buildSignatureBase), and every face
// that signs or verifies — the request signer and appender, both request verifiers, the
// delivery proof's signer and verifier, and the key-directory response signatures —
// composes it.
//
// The detector is REGEX-based and whitespace-tolerant on purpose (a formatter wrapping
// the template must not let a fork slip); the "would-be-missed" meta-test feeds a
// reformatted fork and asserts it is still caught.

const SRC_DIRS = ["core", "src"];
const CANONICAL_RENDERER = "core/sign-request.ts";
const COMPOSERS = [
	"core/sign.ts",
	"core/verify-request.ts",
	"core/directory-response.ts",
	"src/pop.ts",
];

const dirPath = (name: string): string => fileURLToPath(new URL(`../${name}`, import.meta.url));

// The fingerprint of a signature-base renderer: the @signature-params line written as a
// template.
const BASE_FINGERPRINT = /"@signature-params":\s*\$\{/;

// rendersBase is the pure predicate (extracted so the meta-tests can exercise it against
// synthetic source without touching the real files).
function rendersBase(source: string): boolean {
	return BASE_FINGERPRINT.test(source);
}

function tsFilesUnder(dir: string): string[] {
	return readdirSync(dirPath(dir), { withFileTypes: true })
		.filter((e) => e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts"))
		.map((e) => `${dir}/${e.name}`);
}

function baseRenderers(): string[] {
	const found: string[] = [];
	for (const dir of SRC_DIRS) {
		for (const rel of tsFilesUnder(dir)) {
			if (rendersBase(readFileSync(dirPath(rel), "utf8"))) found.push(rel);
		}
	}
	return found.sort();
}

describe("signature-base builder reuse structural guard", () => {
	it("the RFC 9421 signature base is rendered in exactly one file (no fork)", () => {
		expect(baseRenderers()).toEqual([CANONICAL_RENDERER]);
	});

	for (const rel of COMPOSERS) {
		it(`${rel} composes the shared builder, never a forked base`, () => {
			const src = readFileSync(dirPath(rel), "utf8");
			expect(rendersBase(src)).toBe(false);
			expect(/buildSignatureBase\(/.test(src)).toBe(true);
		});
	}

	it("the append face and the multisig verifier compose the shared helpers", () => {
		const sign = readFileSync(dirPath("core/sign-request.ts"), "utf8");
		const appendBody = sign.slice(sign.indexOf("function appendSignature"));
		expect(/buildSignatureBase\(/.test(appendBody)).toBe(true);
		const multisig = readFileSync(dirPath("core/verify-multisig-request.ts"), "utf8");
		expect(rendersBase(multisig)).toBe(false);
		expect(/verifyParsedSignature/.test(multisig)).toBe(true);
	});

	// --- meta-tests: exercise the detector against synthetic source ------------
	it("[meta positive] catches a forked base template", () => {
		const fork = [
			"const base = [",
			'  `"@method": ${m}`,',
			'  `"@target-uri": ${u}`,',
			'  `"@signature-params": ${p}`,',
			'].join("\\n");',
		].join("\n");
		expect(rendersBase(fork)).toBe(true);
	});

	it("[meta negative] does NOT flag a caller of the shared builder", () => {
		const caller = "const base = buildSignatureBase(covered, requestComponentValue(req), sig.rawInner);";
		expect(rendersBase(caller)).toBe(false);
	});

	it("[meta would-be-missed] catches a reformatted fork (extra whitespace) a naive substring would slip", () => {
		const reformatted = ["const lines = [", '  `"@signature-params":\t   ${rawParams}`,', "];"].join("\n");
		expect(rendersBase(reformatted)).toBe(true);
	});
});
