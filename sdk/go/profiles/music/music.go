// Package music holds the typed view of the fora-music-v1 extension profile: the
// flat music.<field> keys an offer carries in Offer.ext, for example music.genre.
//
// Music is a convenience type for reading and writing those keys. It is not a
// validator. The profile's JSON Schema, music-v1.schema.json, defines the valid
// shape (label format, ISRC pattern, energy values, bpm and duration bounds). It is
// published at https://fora-protocol.org/protocol/ext-music/. encoding/json also
// matches keys case-insensitively, so decoding into Music accepts input the
// schema rejects. Validate against the schema when the input is untrusted.
//
// Presence follows the profile: an absent key means unknown, and an empty list
// means known to be empty. Scalars are pointers, so an absent music.vocals stays
// absent and never reads as false. Lists use omitzero, so a nil list is left out
// and an empty list is written as []. Decoding an Offer.ext into Music keeps only
// the music.<field> keys: other keys, including a nested "music" object, which is
// not part of the profile, are dropped. The raw Offer.ext keeps them, and the
// offer signature covers them.
package music

// ProfileID is the profile identifier an Exchange lists in
// WellKnownManifest.supported_profiles.
const ProfileID = "fora-music-v1"

// Music is the set of music.<field> keys of Offer.ext. Every key is optional.
type Music struct {
	// Artist is a display credit. It is not a matching input.
	Artist *string `json:"music.artist,omitempty"`
	// ISRC names the source recording, also for an excerpt. It is not a matching input.
	ISRC *string `json:"music.isrc,omitempty"`
	// Genre is one primary genre label.
	Genre       *string  `json:"music.genre,omitempty"`
	Mood        []string `json:"music.mood,omitzero"`
	Instruments []string `json:"music.instruments,omitzero"`
	// SuitableFor is editorial suitability. It gives no permission to use the asset.
	SuitableFor []string `json:"music.suitable_for,omitzero"`
	// Energy is "low", "medium" or "high".
	Energy *string `json:"music.energy,omitempty"`
	// Vocals is true when the delivered asset contains any audible human voice.
	Vocals *bool `json:"music.vocals,omitempty"`
	// BPM is the tempo in whole beats per minute.
	BPM *int `json:"music.bpm,omitempty"`
	// DurationSeconds is the duration of the delivered asset, not of the source recording.
	DurationSeconds *float64 `json:"music.duration_seconds,omitempty"`
}
