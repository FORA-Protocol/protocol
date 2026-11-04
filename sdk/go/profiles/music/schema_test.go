package music_test

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The profile page is the only copy of music-v1.schema.json: the schema is the
// ```json block of its "JSON Schema" section. These tests read it from there, so the
// published schema is the one that is checked.
const specPage = "../../../../website/src/content/docs/protocol/ext-music.mdx"

const schemaID = "https://fora-protocol.org/schemas/music/v1/music-v1.schema.json"

var schemaFenceRe = regexp.MustCompile("(?s)\n## JSON Schema\n.*?```json[ \t]*\n(.*?)```")

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	page, err := os.ReadFile(specPage)
	if err != nil {
		t.Fatal(err)
	}
	m := schemaFenceRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no ```json block under \"## JSON Schema\" in %s", specPage)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(m[1]))
	if err != nil {
		t.Fatalf("the schema block is not JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(schemaID, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(schemaID)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return sch
}

func validate(t *testing.T, sch *jsonschema.Schema, raw string) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return sch.Validate(v)
}

// Every shared case is a valid Offer.ext, so an offer with every key and an offer
// with the ten original keys both validate. The cases also cover what the schema
// allows on purpose: unknown keys, a nested "music" object, and a bpm written as
// 90.0 or 1e2. Each form of the release date is valid.
func TestSchemaAcceptsSharedCasesAndDateForms(t *testing.T) {
	sch := compileSchema(t)
	for _, c := range loadCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			if err := validate(t, sch, string(c.Input)); err != nil {
				t.Errorf("input is invalid:\n%v", err)
			}
		})
	}
	for _, d := range []string{"2015", "2015-06", "2015-06-17"} {
		if err := validate(t, sch, `{"music.release_date": "`+d+`"}`); err != nil {
			t.Errorf("release_date %q is invalid:\n%v", d, err)
		}
	}
}

// An invalid value fails, and the error is located at the key, so a publisher sees
// which key to fix.
func TestSchemaRejectsInvalidValuesAtTheKey(t *testing.T) {
	sch := compileSchema(t)
	cases := []struct{ name, in, at string }{
		{"upc_too_short", `{"music.upc": "02012345678"}`, "/music.upc"},
		{"upc_too_long", `{"music.upc": "020123456789012"}`, "/music.upc"},
		{"upc_with_letter", `{"music.upc": "02012345678A"}`, "/music.upc"},
		{"upper_case_subgenre", `{"music.subgenres": ["lo-fi", "Ambient"]}`, "/music.subgenres/1"},
		{"release_date_month_13", `{"music.release_date": "2015-13"}`, "/music.release_date"},
		{"parental_warning_outside_values", `{"music.parental_warning": "clean"}`, "/music.parental_warning"},
		{"contributor_without_name", `{"music.contributors": [{"role": "composer"}]}`, "/music.contributors/0"},
		{"contributor_without_role", `{"music.contributors": [{"name": "Sam Example"}]}`, "/music.contributors/0"},
		{"iswc_in_display_form", `{"music.iswc": "T-034.524.680-1"}`, "/music.iswc"},
		{"language_is_not_a_tag", `{"music.language": "portuguese (brazil)"}`, "/music.language"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validate(t, sch, c.in)
			if err == nil {
				t.Fatal("valid, want an error")
			}
			verr, ok := err.(*jsonschema.ValidationError)
			if !ok {
				t.Fatalf("got %T, want *jsonschema.ValidationError: %v", err, err)
			}
			if !locatedAt(verr, c.at) {
				t.Errorf("no error at %s:\n%v", c.at, err)
			}
		})
	}
}

// locatedAt reports whether e or one of its causes is at the JSON pointer at.
func locatedAt(e *jsonschema.ValidationError, at string) bool {
	if "/"+strings.Join(e.InstanceLocation, "/") == at {
		return true
	}
	for _, cause := range e.Causes {
		if locatedAt(cause, at) {
			return true
		}
	}
	return false
}
