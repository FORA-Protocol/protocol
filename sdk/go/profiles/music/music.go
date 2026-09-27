// Package music holds the typed view of the fora-music-v1 extension profile: the
// one nested JSON object an offer carries at Offer.ext.music.
//
// Music is a convenience type for reading and writing that object. It is not a
// validator. The profile's JSON Schema, music-v1.schema.json, defines the valid
// shape (label format, ISRC pattern, energy values, bpm and duration bounds). It is
// published at https://fora-protocol.org/protocol/ext-music/. encoding/json also matches keys case-insensitively, so
// decoding into Music accepts input the schema rejects. Validate against the
// schema when the input is untrusted.
//
// Presence follows the profile: an absent field means unknown, and an empty
// list means known to be empty. Scalars are pointers, so an absent vocals stays
// absent and never reads as false. Lists use omitzero, so a nil list is left out
// and an empty list is written as []. Unknown fields are dropped on decode.
package music

// ProfileID is the profile identifier an Exchange lists in
// ExchangeManifest.supported_profiles.
const ProfileID = "fora-music-v1"

// Music is the Offer.ext.music object. Every field is optional.
type Music struct {
	// Artist is a display credit. It is not a matching input.
	Artist *string `json:"artist,omitempty"`
	// ISRC names the source recording, also for an excerpt. It is not a matching input.
	ISRC *string `json:"isrc,omitempty"`
	// Genre is one primary genre label.
	Genre       *string  `json:"genre,omitempty"`
	Mood        []string `json:"mood,omitzero"`
	Instruments []string `json:"instruments,omitzero"`
	// SuitableFor is editorial suitability. It gives no permission to use the asset.
	SuitableFor []string `json:"suitable_for,omitzero"`
	// Energy is "low", "medium" or "high".
	Energy *string `json:"energy,omitempty"`
	// Vocals is true when the delivered asset contains any audible human voice.
	Vocals *bool `json:"vocals,omitempty"`
	// BPM is the tempo in whole beats per minute.
	BPM *int `json:"bpm,omitempty"`
	// DurationSeconds is the duration of the delivered asset, not of the source recording.
	DurationSeconds *float64 `json:"duration_seconds,omitempty"`
}
