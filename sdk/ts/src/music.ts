// The typed view of the fora-music-v1 extension profile — TS mirror of the sdk/go
// type (profiles/music/music.go). The profile is a set of flat music.<field> keys
// in Offer.ext, for example "music.genre".
//
// Music is a type, not a validator: a value cast from JSON.parse is not checked.
// The profile's JSON Schema, music-v1.schema.json, defines the valid shape (label
// format, ISRC pattern, bpm and duration bounds). It is published at
// https://fora-protocol.org/protocol/ext-music/. Validate against it when the
// input is untrusted.
//
// Presence follows the profile: an absent key means unknown (an absent
// "music.vocals" is never false), and an empty array means known to be empty.
// Consumers ignore keys they do not know. A nested "music" object is not part of
// the profile.

/** The profile identifier an Exchange lists in WellKnownManifest.supported_profiles. */
export const ProfileID = "fora-music-v1";

/** The music.<field> keys of Offer.ext. Every key is optional. */
export interface Music {
	/** Display credit. Not a matching input. */
	"music.artist"?: string;
	/** ISRC of the source recording, also for an excerpt. Not a matching input. */
	"music.isrc"?: string;
	/** One primary genre label. */
	"music.genre"?: string;
	"music.mood"?: string[];
	"music.instruments"?: string[];
	/** Editorial suitability. It gives no permission to use the asset. */
	"music.suitable_for"?: string[];
	"music.energy"?: "low" | "medium" | "high";
	/** True when the delivered asset contains any audible human voice. */
	"music.vocals"?: boolean;
	/** Tempo in whole beats per minute. */
	"music.bpm"?: number;
	/** Duration of the delivered asset, not of the source recording. */
	"music.duration_seconds"?: number;
}
