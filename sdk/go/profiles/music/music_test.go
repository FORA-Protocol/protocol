package music_test

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/profiles/music"
)

type roundTripCase struct {
	Name   string          `json:"name"`
	Input  json.RawMessage `json:"input"`
	Output json.RawMessage `json:"output"`
}

func TestMusicRoundTrip(t *testing.T) {
	raw, err := os.ReadFile("testdata/music-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []roundTripCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases in testdata/music-cases.json")
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var m music.Music
			if err := json.Unmarshal(c.Input, &m); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			// Compare as generic JSON, so key order does not matter but [] vs absent does.
			var got, want any
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(c.Output, &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("round trip:\n got  %s\n want %s", encoded, c.Output)
			}
		})
	}
}
