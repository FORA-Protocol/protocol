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

// A bpm that is not a whole number is refused, as the schema refuses it. The
// round-trip cases cover the whole numbers written as 90.0 and 1e2.
func TestMusicRefusesBPMThatIsNotAWholeNumber(t *testing.T) {
	for _, in := range []string{
		`{"music.bpm": 90.5}`,
		`{"music.bpm": "90"}`,
		`{"music.bpm": 1e300}`,
		`{"music.bpm": true}`,
	} {
		var m music.Music
		if err := json.Unmarshal([]byte(in), &m); err == nil {
			t.Errorf("%s: decoded to bpm %v, want an error", in, *m.BPM)
		}
	}
}

// Decoding into Music still fills every other field, and a null bpm is absent.
func TestMusicDecodesOtherFieldsWithBPM(t *testing.T) {
	var m music.Music
	in := `{"music.genre": "jazz", "music.vocals": false, "music.bpm": 120.0, "music.mood": []}`
	if err := json.Unmarshal([]byte(in), &m); err != nil {
		t.Fatal(err)
	}
	if m.Genre == nil || *m.Genre != "jazz" || m.Vocals == nil || *m.Vocals || m.BPM == nil || *m.BPM != 120 || m.Mood == nil {
		t.Fatalf("decoded %+v", m)
	}
	if err := json.Unmarshal([]byte(`{"music.bpm": null}`), &m); err != nil || m.BPM != nil {
		t.Fatalf("null bpm: err=%v bpm=%v, want absent", err, m.BPM)
	}
}
