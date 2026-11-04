// Package music holds the typed view of the fora-music-v1 extension profile: the
// flat music.<field> keys an offer carries in Offer.ext, for example music.genre.
//
// Music is a convenience type for reading and writing those keys. It is not a
// validator. The profile's JSON Schema, music-v1.schema.json, defines the valid
// shape (label format, identifier patterns, the date form, the contributor object,
// energy and parental-warning values, bpm and duration bounds). It is
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

import (
	"encoding/json"
	"fmt"
	"math"
)

// ProfileID is the profile identifier an Exchange lists in
// WellKnownManifest.supported_profiles.
const ProfileID = "fora-music-v1"

// Music is the set of music.<field> keys of Offer.ext. Every key is optional.
type Music struct {
	// Artist is a display credit. It is not a matching input.
	Artist *string `json:"music.artist,omitempty"`
	// Title is the display title of the recording. It is not a matching input.
	Title *string `json:"music.title,omitempty"`
	// ISRC names the source recording, also for an excerpt. Only the music.isrc filter
	// matches it, as an exact match.
	ISRC *string `json:"music.isrc,omitempty"`
	// Genre is one primary genre label.
	Genre *string `json:"music.genre,omitempty"`
	// Subgenres are finer genre labels under Genre.
	Subgenres []string `json:"music.subgenres,omitzero"`
	// Themes are labels for what the music or the lyrics are about.
	Themes      []string `json:"music.themes,omitzero"`
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
	// Version is a label for which version of the recording this is, for example
	// "instrumental" or "live". It is not a matching input.
	Version *string `json:"music.version,omitempty"`
	// Language is the BCP 47 tag of the sung or spoken words. It is not a label:
	// consumers compare it case-insensitively.
	Language *string `json:"music.language,omitempty"`
	// ParentalWarning is "explicit", "explicit_edited" or "not_explicit".
	ParentalWarning *string `json:"music.parental_warning,omitempty"`
	// ContainsAI is true when the recording contains AI-generated content. An absent
	// flag means unknown and never reads as false.
	ContainsAI *bool `json:"music.contains_ai,omitempty"`
	// ReleaseTitle is the display title of the album, EP or single.
	ReleaseTitle *string `json:"music.release_title,omitempty"`
	// ReleaseDate is "YYYY", "YYYY-MM" or "YYYY-MM-DD".
	ReleaseDate *string `json:"music.release_date,omitempty"`
	// Label is the name of the record label of the release.
	Label *string `json:"music.label,omitempty"`
	// CatalogNumber is the label's own number for the release.
	CatalogNumber *string `json:"music.catalog_number,omitempty"`
	// UPC is the UPC or EAN of the release, 12 to 14 digits.
	UPC *string `json:"music.upc,omitempty"`
	// GRid is the Global Release Identifier of the release, 18 characters.
	GRid *string `json:"music.grid,omitempty"`
	// ISWC identifies the work (the composition) in the compact form: T and 10 digits.
	ISWC *string `json:"music.iswc,omitempty"`
	// ProprietaryIDs are the publisher's own identifiers, each "namespace:value".
	ProprietaryIDs []string `json:"music.proprietary_ids,omitzero"`
	// PLine is the full phonogram notice.
	PLine *string `json:"music.p_line,omitempty"`
	// CLine is the full copyright notice.
	CLine *string `json:"music.c_line,omitempty"`
	// Contributors are the credits, one entry per role.
	Contributors []Contributor `json:"music.contributors,omitzero"`
	// ArtworkURL is the URL of the cover image.
	ArtworkURL *string `json:"music.artwork_url,omitempty"`
}

// Contributor is one entry of music.contributors: one credit. The schema requires
// Name and Role, so they are plain strings. Instrument and ISNI are optional.
type Contributor struct {
	// Name is the display name of the person or group.
	Name string `json:"name"`
	// Role is a label for what the contributor did, for example "composer".
	Role string `json:"role"`
	// Instrument is a label for the instrument a performer played.
	Instrument *string `json:"instrument,omitempty"`
	// ISNI identifies the person or group: 16 characters.
	ISNI *string `json:"isni,omitempty"`
}

// UnmarshalJSON decodes m as encoding/json does, with one difference: music.bpm
// also accepts a whole number written with a fraction or an exponent, for example
// 90.0 or 1e2. JSON Schema counts such a number as an integer, and a
// google.protobuf.Struct stores every number as a double, so some encoders write
// 90.0 for 90. A bpm with a fractional part, a string or a value outside the int
// range is still an error.
func (m *Music) UnmarshalJSON(data []byte) error {
	type plain Music // no methods, so the embedded decode does not recurse
	var aux struct {
		*plain
		// A shallower field wins over plain's BPM for the same JSON key.
		BPM json.RawMessage `json:"music.bpm"`
	}
	aux.plain = (*plain)(m)
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	switch {
	case aux.BPM == nil:
		return nil
	case string(aux.BPM) == "null":
		m.BPM = nil
		return nil
	}
	var n int
	if err := json.Unmarshal(aux.BPM, &n); err == nil {
		m.BPM = &n
		return nil
	}
	var f float64
	if err := json.Unmarshal(aux.BPM, &f); err != nil ||
		f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return fmt.Errorf("music: music.bpm must be a whole number, got %s", aux.BPM)
	}
	n = int(f)
	m.BPM = &n
	return nil
}
