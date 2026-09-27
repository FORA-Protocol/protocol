// The typed view of the fora-music-v1 extension profile — TS mirror of the sdk/go
// type (profiles/music/music.go). The profile is one nested JSON object at
// Offer.ext.music.
//
// Music is a type, not a validator: a value cast from JSON.parse is not checked.
// The profile's JSON Schema, music-v1.schema.json, defines the valid shape (label
// format, ISRC pattern, bpm and duration bounds). It is published at
// https://fora-protocol.org/protocol/ext-music/. Validate against it when the
// input is untrusted.
//
// Presence follows the profile: an absent field means unknown (an absent vocals is
// never false), and an empty array means known to be empty. Consumers ignore
// fields they do not know.

/** The profile identifier an Exchange lists in ExchangeManifest.supported_profiles. */
export const ProfileID = "fora-music-v1";

/** The Offer.ext.music object. Every field is optional. */
export interface Music {
	/** Display credit. Not a matching input. */
	artist?: string;
	/** ISRC of the source recording, also for an excerpt. Not a matching input. */
	isrc?: string;
	/** One primary genre label. */
	genre?: string;
	mood?: string[];
	instruments?: string[];
	/** Editorial suitability. It gives no permission to use the asset. */
	suitable_for?: string[];
	energy?: "low" | "medium" | "high";
	/** True when the delivered asset contains any audible human voice. */
	vocals?: boolean;
	/** Tempo in whole beats per minute. */
	bpm?: number;
	/** Duration of the delivered asset, not of the source recording. */
	duration_seconds?: number;
}
