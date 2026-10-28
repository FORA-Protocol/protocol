// Scope-matching parity (TypeScript side).
//
// sdk/ts scopeCovers/scopesCover/scopesSubset MUST give the verdicts in
// sdk/go/helpers/testdata/scope-match-vectors.json, which is written by hand
// from the protocol's segment-wise scope-matching rule (Requester.scopes), not
// emitted by an implementation:
//   - covers:     {granted:string, required:string, expected:boolean}
//   - cover_sets: {granted:string[], required:string[], expected:boolean};
//                 the same row also pins scopesSubset(required, granted).
import { describe, it, expect } from "vitest";
import { scopeCovers, scopesCover, scopesSubset } from "../src/scopes.ts";
import vectorsFile from "../../go/helpers/testdata/scope-match-vectors.json";

type CoverVector = { name: string; granted: string; required: string; expected: boolean };
type CoverSetVector = { name: string; granted: string[]; required: string[]; expected: boolean };
type ScopeMatchVectorsFile = { covers: CoverVector[]; cover_sets: CoverSetVector[] };

const vectors = vectorsFile as ScopeMatchVectorsFile;

describe("sdk/ts scopeCovers matches the written scope-matching rule", () => {
	it("covers vector set is non-empty", () => {
		expect(vectors.covers.length).toBeGreaterThan(0);
	});
	for (const v of vectors.covers) {
		it(`scopeCovers(${v.name}) === ${v.expected}`, () => {
			expect(scopeCovers(v.granted, v.required)).toBe(v.expected);
		});
	}
});

describe("sdk/ts scopesCover and scopesSubset match the written rule", () => {
	it("cover_sets vector set is non-empty", () => {
		expect(vectors.cover_sets.length).toBeGreaterThan(0);
	});
	for (const v of vectors.cover_sets) {
		it(`scopesCover(${v.name}) === ${v.expected}`, () => {
			expect(scopesCover(v.granted, v.required)).toBe(v.expected);
			expect(scopesSubset(v.required, v.granted)).toBe(v.expected);
		});
	}
});
