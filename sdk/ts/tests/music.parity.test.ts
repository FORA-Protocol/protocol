// Music profile type (TypeScript side). The sdk/go type is the oracle, and the
// shared cases at sdk/go/profiles/music/testdata/music-cases.json name every field
// in their all_fields case.
//
// The field list below is typed Record<keyof Music, true>, so tsc fails when the
// interface gains or loses a field that the list does not. The test then checks the
// same list against the shared cases, so the interface and the Go type cannot drift
// apart without a failure.
import { describe, it, expect } from "vitest";
import { type Music, ProfileID } from "../src/music.ts";
import casesFile from "../../go/profiles/music/testdata/music-cases.json";

const MUSIC_FIELDS: Record<keyof Music, true> = {
	artist: true,
	isrc: true,
	genre: true,
	mood: true,
	instruments: true,
	suitable_for: true,
	energy: true,
	vocals: true,
	bpm: true,
	duration_seconds: true,
};

type Case = { name: string; input: Record<string, unknown>; output: Record<string, unknown> };

describe("sdk/ts Music matches the sdk/go type", () => {
	it("has exactly the fields of the shared all_fields case", () => {
		const all = (casesFile.cases as Case[]).find((c) => c.name === "all_fields");
		expect(all).toBeDefined();
		expect(Object.keys(MUSIC_FIELDS).sort()).toEqual(Object.keys(all!.input).sort());
	});

	it("uses the profile id fora-music-v1", () => {
		expect(ProfileID).toBe("fora-music-v1");
	});
});
