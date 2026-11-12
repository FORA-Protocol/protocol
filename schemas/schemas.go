// Package schemas ships the machine-readable files of the extension profiles.
//
// A file is at the path the site publishes it under, below
// https://fora-protocol.org/schemas/:
//
//	music/v1/music-v1.search-filters.schema.json  the fora-music-v1 search filter keys
//
// The files are hand-written. They are the source the profile page renders its tables
// from, and the tests in sdk/go/profiles/music hold them to the profile. FS embeds
// them, so a Go program reads the files of the module version it pins.
package schemas

import "embed"

// FS holds every profile file, at its published path.
//
//go:embed music/v1/*.json
var FS embed.FS

// MusicSearchFilters is the path in FS of the fora-music-v1 search filter schema.
const MusicSearchFilters = "music/v1/music-v1.search-filters.schema.json"
