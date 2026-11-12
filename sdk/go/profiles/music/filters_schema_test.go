package music_test

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/FORA-Protocol/protocol/schemas"
)

// The fora-music-v1 search filter keys are one file, schemas/music/v1/
// music-v1.search-filters.schema.json. The profile page renders its filter table from
// it, and FORA Server reads it as a deployment's filter vocabulary. These tests read
// it through the published schemas.FS and hold it to the profile: the form a filter
// vocabulary takes, the key count the page states, the value formats of the offer
// schema, and the shared vectors.

const filtersURL = "https://fora-protocol.org/schemas/music/v1/" + "music-v1.search-filters.schema.json"

// filterKeyRe is the profile's key pattern: the music. namespace, then a snake_case
// field name.
var filterKeyRe = regexp.MustCompile(`^music\.[a-z][a-z0-9_]*$`)

// The keys a filter vocabulary may use at its top level: annotations, and the three
// that make it one flat object of keys.
var filterTopLevel = []string{"$schema", "$comment", "title", "description", "type", "properties", "additionalProperties"}

// Keywords a filter vocabulary never uses, at any depth: it is one self-contained
// document, and a filter applies only when the agent sends it.
var filterForbidden = []string{"$id", "$ref", "$defs", "$anchor", "$dynamicRef", "$dynamicAnchor", "default"}

type filterProp struct {
	Description string          `json:"description"`
	Type        json.RawMessage `json:"type"`
	Pattern     string          `json:"pattern"`
	MinLength   *int            `json:"minLength"`
	MinItems    *int            `json:"minItems"`
	Items       *struct {
		Type    string `json:"type"`
		Pattern string `json:"pattern"`
	} `json:"items"`
	Examples []json.RawMessage `json:"examples"`
}

type filterDoc struct {
	Schema     string                `json:"$schema"`
	Type       string                `json:"type"`
	Additional *bool                 `json:"additionalProperties"`
	Properties map[string]filterProp `json:"properties"`
}

func readFilters(t *testing.T) []byte {
	t.Helper()
	raw, err := schemas.FS.ReadFile(schemas.MusicSearchFilters)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func loadFilters(t *testing.T) filterDoc {
	t.Helper()
	var doc filterDoc
	if err := json.Unmarshal(readFilters(t), &doc); err != nil {
		t.Fatalf("the filter schema is not JSON: %v", err)
	}
	if len(doc.Properties) == 0 {
		t.Fatal("the filter schema declares no key")
	}
	return doc
}

func compileFilters(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(readFilters(t)))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	if err := c.AddResource(filtersURL, doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile(filtersURL)
	if err != nil {
		t.Fatalf("not a valid draft 2020-12 schema: %v", err)
	}
	return sch
}

// The file is a filter vocabulary in the form a Broker's deployment declares one: a
// draft 2020-12 object schema whose properties are the keys, each with a description,
// a type and examples, and no other key allowed.
func TestFilterSchemaIsAFlatFilterVocabulary(t *testing.T) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(readFilters(t), &top); err != nil {
		t.Fatal(err)
	}
	for k := range top {
		if !slices.Contains(filterTopLevel, k) {
			t.Errorf("top-level keyword %q: a filter vocabulary constrains each key on its own", k)
		}
	}
	var tree any
	_ = json.Unmarshal(readFilters(t), &tree)
	for _, kw := range filterForbidden {
		if path := keywordPath(tree, kw, ""); path != "" {
			t.Errorf("uses %s at %s", kw, path)
		}
	}
	doc := loadFilters(t)
	if doc.Schema != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %q, want the draft 2020-12 dialect", doc.Schema)
	}
	if doc.Type != "object" || doc.Additional == nil || *doc.Additional {
		t.Errorf("want type object and additionalProperties false, got type %q", doc.Type)
	}
	for key, p := range doc.Properties {
		if !filterKeyRe.MatchString(key) {
			t.Errorf("key %q does not match %s", key, filterKeyRe)
		}
		if strings.TrimSpace(p.Description) == "" || len(p.Type) == 0 || len(p.Examples) == 0 {
			t.Errorf("%s: needs a description, a type and examples", key)
		}
	}
	compileFilters(t)
}

// keywordPath returns where kw is used as a key in node, or "". Values of data
// keywords are not schemas, so they are not searched.
func keywordPath(node any, kw, at string) string {
	switch n := node.(type) {
	case map[string]any:
		if _, ok := n[kw]; ok {
			return at + "/" + kw
		}
		for k, v := range n {
			if k == "examples" || k == "enum" || k == "const" {
				continue
			}
			if p := keywordPath(v, kw, at+"/"+k); p != "" {
				return p
			}
		}
	case []any:
		for i, v := range n {
			if p := keywordPath(v, kw, at+"/"+strconv.Itoa(i)); p != "" {
				return p
			}
		}
	}
	return ""
}

// The page's Field Summary states how many filter keys the profile defines; the file
// has that many.
func TestFilterSchemaHasTheKeyCountThePageStates(t *testing.T) {
	page, err := os.ReadFile(specPage)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("\\| `DiscoveryRequest\\.search_filters` \\| ([0-9]+) \\|").FindSubmatch(page)
	if m == nil {
		t.Fatal("no DiscoveryRequest.search_filters row in the Field Summary table")
	}
	want, _ := strconv.Atoi(string(m[1]))
	if got := len(loadFilters(t).Properties); got != want {
		t.Errorf("the filter schema has %d keys, the page states %d", got, want)
	}
}

// Each key filters on a field of the offer schema, and its values have that field's
// format: a label key uses the Label pattern, an identifier key the identifier's
// pattern, music.language the language tag pattern, and music.release_date_range
// two release dates. So the two schemas cannot drift apart.
func TestFilterSchemaUsesTheOfferSchemaFormats(t *testing.T) {
	offer := offerSchemaDoc(t)
	label := offer.Defs["Label"].Pattern
	date := offer.Properties["music.release_date"].Pattern
	date = date[1 : len(date)-1]
	want := map[string]string{
		"music.isrc":               offer.Properties["music.isrc"].Pattern,
		"music.upc":                offer.Properties["music.upc"].Pattern,
		"music.grid":               offer.Properties["music.grid"].Pattern,
		"music.iswc":               offer.Properties["music.iswc"].Pattern,
		"music.language":           offer.Properties["music.language"].Pattern,
		"music.ipi":                offer.Defs["IPI"].Pattern,
		"music.release_date_range": "^(?:" + date + "/" + date + "|" + date + "/|/" + date + ")$",
	}
	labelKeys := []string{
		"music.genre", "music.subgenres", "music.themes", "music.mood", "music.instruments",
		"music.suitable_for", "music.key", "music.version",
	}
	for _, k := range labelKeys {
		want[k] = label
	}
	// music.publisher and music.ipi filter on keys inside music.publishers and
	// music.contributors; every other key names its field, a range key with _range.
	inside := map[string]bool{"music.publisher": true, "music.ipi": true}
	for key, p := range loadFilters(t).Properties {
		field := strings.TrimSuffix(key, "_range")
		if _, ok := offer.Properties[field]; !ok && !inside[key] {
			t.Errorf("%s filters on %s, which the offer schema does not define", key, field)
		}
		w, ok := want[key]
		if !ok {
			continue
		}
		got := p.Pattern
		if p.Items != nil {
			if p.Items.Pattern != p.Pattern {
				t.Errorf("%s: the item pattern differs from the string pattern", key)
			}
		}
		if got != w {
			t.Errorf("%s: pattern %q, want the offer schema's %q", key, got, w)
		}
	}
	if label == "" || date == "" {
		t.Fatal("the offer schema has no Label or music.release_date pattern")
	}
}

type offerPattern struct {
	Pattern string `json:"pattern"`
}

type offerDoc struct {
	Properties map[string]offerPattern `json:"properties"`
	Defs       map[string]offerPattern `json:"$defs"`
}

func offerSchemaDoc(t *testing.T) offerDoc {
	t.Helper()
	page, err := os.ReadFile(specPage)
	if err != nil {
		t.Fatal(err)
	}
	m := schemaFenceRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no ```json block under \"## JSON Schema\" in %s", specPage)
	}
	var doc offerDoc
	if err := json.Unmarshal(m[1], &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

type filterCase struct {
	Name    string          `json:"name"`
	Filters json.RawMessage `json:"filters"`
	At      string          `json:"at"`
}

// The shared vectors: each valid case passes, each invalid case fails at the value it
// breaks, and every key has at least one case of each kind, so no key goes untested.
func TestFilterSchemaVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/search-filter-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Valid   []filterCase `json:"valid"`
		Invalid []filterCase `json:"invalid"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	sch := compileFilters(t)
	keys := loadFilters(t).Properties
	validKeys, invalidKeys := map[string]bool{}, map[string]bool{}
	for _, c := range cases.Valid {
		t.Run("valid/"+c.Name, func(t *testing.T) {
			if err := validate(t, sch, string(c.Filters)); err != nil {
				t.Errorf("invalid:\n%v", err)
			}
		})
		for k := range filterKeysOf(t, c.Filters) {
			validKeys[k] = true
		}
	}
	for _, c := range cases.Invalid {
		t.Run("invalid/"+c.Name, func(t *testing.T) {
			err := validate(t, sch, string(c.Filters))
			if err == nil {
				t.Fatal("valid, want an error")
			}
			verr, ok := err.(*jsonschema.ValidationError)
			if !ok {
				t.Fatalf("got %T, want *jsonschema.ValidationError: %v", err, err)
			}
			if c.At == "" {
				if !refusesAKey(verr) {
					t.Errorf("not refused as an unlisted key:\n%v", err)
				}
			} else if !locatedAt(verr, c.At) {
				t.Errorf("no error at %q:\n%v", c.At, err)
			}
		})
		for k := range filterKeysOf(t, c.Filters) {
			invalidKeys[k] = true
		}
	}
	for k := range keys {
		if !validKeys[k] || !invalidKeys[k] {
			t.Errorf("%s needs a valid and an invalid case", k)
		}
	}
}

// refusesAKey reports whether e or one of its causes refuses a key that
// additionalProperties does not allow.
func refusesAKey(e *jsonschema.ValidationError) bool {
	if _, ok := e.ErrorKind.(*kind.AdditionalProperties); ok {
		return true
	}
	return slices.ContainsFunc(e.Causes, refusesAKey)
}

func filterKeysOf(t *testing.T, raw json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
