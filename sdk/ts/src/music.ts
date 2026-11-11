// The typed view of the fora-music-v1 extension profile — TS mirror of the sdk/go
// type (profiles/music/music.go). The profile is a set of flat music.<field> keys
// in Offer.ext, for example "music.genre".
//
// Music is a type, not a validator: a value cast from JSON.parse is not checked.
// The profile's JSON Schema, music-v1.schema.json, defines the valid shape (label
// format, identifier patterns, the date form, the contributor object, bpm and
// duration bounds). It is published at
// https://fora-protocol.org/protocol/ext-music/. Validate against it when the
// input is untrusted.
//
// Presence follows the profile: an absent key means unknown (an absent
// "music.vocals" is never false), and an empty array means known to be empty.
// Consumers ignore keys they do not know. A nested "music" object is not part of
// the profile.

/** The profile identifier an Exchange lists in WellKnownManifest.supported_profiles. */
export const ProfileID = "fora-music-v1";

/** One entry of "music.contributors": one credit. */
export interface Contributor {
	/** Display name of the person or group. */
	name: string;
	/** What the contributor did, as a label, for example "composer". */
	role: string;
	/** The instrument a performer played, as a label. */
	instrument?: string;
	/** ISNI of the person or group: 16 characters. */
	isni?: string;
	/** IPI name number of a writer: 9 to 11 digits. */
	ipi?: string;
	/** The writer's collecting society, as a label, for example "ascap". */
	pro?: string;
	/** The writer's share of the performing right in the work, in percent: more than 0 and at most 100. */
	share?: number;
}

/** One entry of "music.publishers": a music publisher of the work. */
export interface Publisher {
	/** Name of the publisher. The music.publisher filter matches it, ignoring case. */
	name: string;
	/** What the publisher does for the work, as a label, for example "original publisher", "sub-publisher" or "administrator". */
	role?: string;
	/** IPI name number of the publisher: 9 to 11 digits. */
	ipi?: string;
	/** The publisher's collecting society, as a label, for example "prs". */
	pro?: string;
	/** The publisher's share of the performing right in the work, in percent: more than 0 and at most 100. */
	share?: number;
}

/** The music.<field> keys of Offer.ext. Every key is optional. */
export interface Music {
	/** Display credit. Not a matching input. */
	"music.artist"?: string;
	/** Display title of the recording. Not a matching input. */
	"music.title"?: string;
	/** ISRC of the source recording, also for an excerpt. Only the music.isrc filter matches it, as an exact match. */
	"music.isrc"?: string;
	/** One primary genre label. */
	"music.genre"?: string;
	/** Finer genre labels under the primary genre. */
	"music.subgenres"?: string[];
	/** Labels for what the music or the lyrics are about. */
	"music.themes"?: string[];
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
	/** Which version of the recording this is, as a label, for example "instrumental". The music.version filter matches it. */
	"music.version"?: string;
	/** Musical key, as a label, for example "a minor". The music.key filter matches it. */
	"music.key"?: string;
	/** BCP 47 tag of the sung or spoken words. Not a label: compared case-insensitively. */
	"music.language"?: string;
	"music.parental_warning"?: "explicit" | "explicit_edited" | "not_explicit";
	/** True when the recording contains AI-generated content. An absent flag is unknown, never false. */
	"music.contains_ai"?: boolean;
	/** Display title of the album, EP or single. */
	"music.release_title"?: string;
	/** "YYYY", "YYYY-MM" or "YYYY-MM-DD". */
	"music.release_date"?: string;
	/** Name of the record label of the release. */
	"music.label"?: string;
	/** The label's own number for the release. */
	"music.catalog_number"?: string;
	/** UPC or EAN of the release, 12 to 14 digits. */
	"music.upc"?: string;
	/** Global Release Identifier of the release, 18 characters. */
	"music.grid"?: string;
	/** ISWC of the work (the composition) in the compact form: T and 10 digits. */
	"music.iswc"?: string;
	/** The publisher's own identifiers, each "namespace:value". */
	"music.proprietary_ids"?: string[];
	/** The full phonogram notice. */
	"music.p_line"?: string;
	/** The full copyright notice. */
	"music.c_line"?: string;
	/** The credits, one entry per role. */
	"music.contributors"?: Contributor[];
	/** The music publishers of the work, with the data a cue sheet needs. */
	"music.publishers"?: Publisher[];
	/** URL of the cover image. */
	"music.artwork_url"?: string;
}
