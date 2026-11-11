package music_test

import (
	"bytes"
	"os"
	"regexp"
	"slices"
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
	// Draft 2020-12 treats "format" as an annotation unless the validator asserts
	// it. Assert it here, so music.artwork_url's "format": "uri" is checked.
	c.AssertFormat()
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

// Every shared case is a valid Offer.ext: all_fields has every key, and
// original_ten_keys has only the keys of the profile's first release. The cases
// also cover what the schema allows on purpose: unknown keys, a nested "music"
// object, and a bpm written as 90.0 or 1e2. Each form of the release date is valid,
// including the leap day of a leap year, and a language tag in any shape RFC 5646
// allows is valid.
func TestSchemaAcceptsSharedCasesAndValueForms(t *testing.T) {
	sch := compileSchema(t)
	cases := loadCases(t)
	for _, name := range []string{"all_fields", "original_ten_keys"} {
		if !slices.ContainsFunc(cases, func(c roundTripCase) bool { return c.Name == name }) {
			t.Errorf("shared case %q is missing", name)
		}
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if err := validate(t, sch, string(c.Input)); err != nil {
				t.Errorf("input is invalid:\n%v", err)
			}
		})
	}
	valid := map[string][]string{
		"music.release_date": {"2015", "2015-06", "2015-06-17", "2015-12-31", "2016-02-29", "2000-02-29"},
		"music.language":     {"en", "pt-BR", "zh-Hant-TW", "de-CH-1901", "sl-rozaj-biske", "en-US-u-islamcal", "x-klingon", "i-klingon"},
	}
	for key, values := range valid {
		for _, v := range values {
			if err := validate(t, sch, `{"`+key+`": "`+v+`"}`); err != nil {
				t.Errorf("%s %q is invalid:\n%v", key, v, err)
			}
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
		{"release_date_month_without_zero", `{"music.release_date": "2015-6"}`, "/music.release_date"},
		{"release_date_feb_29_in_a_common_year", `{"music.release_date": "2015-02-29"}`, "/music.release_date"},
		{"release_date_feb_29_in_a_century_year", `{"music.release_date": "1900-02-29"}`, "/music.release_date"},
		{"release_date_feb_31", `{"music.release_date": "2015-02-31"}`, "/music.release_date"},
		{"release_date_april_31", `{"music.release_date": "2015-04-31"}`, "/music.release_date"},
		{"parental_warning_outside_values", `{"music.parental_warning": "clean"}`, "/music.parental_warning"},
		{"contributor_without_name", `{"music.contributors": [{"role": "composer"}]}`, "/music.contributors/0"},
		{"contributor_without_role", `{"music.contributors": [{"name": "Sam Example"}]}`, "/music.contributors/0"},
		{"publisher_without_name", `{"music.publishers": [{"ipi": "00987654321"}]}`, "/music.publishers/0"},
		{"ipi_with_letter", `{"music.publishers": [{"name": "Example", "ipi": "0098765432A"}]}`, "/music.publishers/0/ipi"},
		{"ipi_too_short", `{"music.contributors": [{"name": "Sam", "role": "composer", "ipi": "12345678"}]}`, "/music.contributors/0/ipi"},
		{"share_zero", `{"music.contributors": [{"name": "Sam", "role": "composer", "share": 0}]}`, "/music.contributors/0/share"},
		{"share_over_100", `{"music.publishers": [{"name": "Example", "share": 100.5}]}`, "/music.publishers/0/share"},
		{"upper_case_pro", `{"music.publishers": [{"name": "Example", "pro": "ASCAP"}]}`, "/music.publishers/0/pro"},
		{"upper_case_key", `{"music.key": "A minor"}`, "/music.key"},
		{"upper_case_publisher_role", `{"music.publishers": [{"name": "Example", "role": "Original Publisher"}]}`, "/music.publishers/0/role"},
		{"iswc_in_display_form", `{"music.iswc": "T-034.524.680-1"}`, "/music.iswc"},
		{"language_is_not_a_tag", `{"music.language": "portuguese (brazil)"}`, "/music.language"},
		{"language_singleton_without_extension", `{"music.language": "en-a"}`, "/music.language"},
		{"language_one_letter_primary", `{"music.language": "a-DE"}`, "/music.language"},
		{"language_empty_subtag", `{"music.language": "en--US"}`, "/music.language"},
		{"artwork_url_is_not_a_url", `{"music.artwork_url": "not a URL"}`, "/music.artwork_url"},
		{"artwork_url_is_relative", `{"music.artwork_url": "/tracks/night-orbit/cover.jpg"}`, "/music.artwork_url"},
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
