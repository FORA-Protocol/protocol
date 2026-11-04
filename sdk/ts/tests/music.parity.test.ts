// Music profile type (TypeScript side). The sdk/go type is the oracle, and the
// shared cases at sdk/go/profiles/music/testdata/music-cases.json name every field
// in their all_fields case.
//
// The field list below is typed Record<keyof Music, true>, so tsc fails when the
// interface gains or loses a field that the list does not. The test then checks the
// same list against the shared cases, so the interface and the Go type cannot drift
// apart without a failure.
import { describe, it, expect } from "vitest";
import { type Contributor, type Music, ProfileID } from "../src/music.ts";
import casesFile from "../../go/profiles/music/testdata/music-cases.json";

const MUSIC_FIELDS: Record<keyof Music, true> = {
	"music.artist": true,
	"music.title": true,
	"music.isrc": true,
	"music.genre": true,
	"music.subgenres": true,
	"music.themes": true,
	"music.mood": true,
	"music.instruments": true,
	"music.suitable_for": true,
	"music.energy": true,
	"music.vocals": true,
	"music.bpm": true,
	"music.duration_seconds": true,
	"music.version": true,
	"music.language": true,
	"music.parental_warning": true,
	"music.contains_ai": true,
	"music.release_title": true,
	"music.release_date": true,
	"music.label": true,
	"music.catalog_number": true,
	"music.upc": true,
	"music.grid": true,
	"music.iswc": true,
	"music.proprietary_ids": true,
	"music.p_line": true,
	"music.c_line": true,
	"music.contributors": true,
	"music.artwork_url": true,
};

// The one contributor of the all_fields case names every key of a contributor.
const CONTRIBUTOR_FIELDS: Record<keyof Contributor, true> = {
	name: true,
	role: true,
	instrument: true,
	isni: true,
};

type Case = { name: string; input: Record<string, unknown>; output: Record<string, unknown> };

function allFields(): Case {
	const all = (casesFile.cases as Case[]).find((c) => c.name === "all_fields");
	expect(all).toBeDefined();
	return all!;
}

describe("sdk/ts Music matches the sdk/go type", () => {
	it("has exactly the fields of the shared all_fields case", () => {
		expect(Object.keys(MUSIC_FIELDS).sort()).toEqual(Object.keys(allFields().input).sort());
	});

	it("has exactly the contributor keys of the shared all_fields case", () => {
		const contributors = allFields().input["music.contributors"] as Record<string, unknown>[];
		expect(contributors).toHaveLength(1);
		expect(Object.keys(CONTRIBUTOR_FIELDS).sort()).toEqual(Object.keys(contributors[0]!).sort());
	});

	it("uses the profile id fora-music-v1", () => {
		expect(ProfileID).toBe("fora-music-v1");
	});
});
