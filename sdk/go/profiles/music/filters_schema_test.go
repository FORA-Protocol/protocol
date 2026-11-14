package music_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"

	"github.com/FORA-Protocol/protocol/schemas"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// The fora-music-v1 search filter keys are one file, schemas/music/v1/
// music-v1.search-filters.schema.json. The profile page renders its filter table from
// it. It has the form of a Broker deployment's filter vocabulary, although the SDK's
// registration-schema compiler refuses its patterns today (see
// TestFilterSchemaRegistrationCompilerVerdict). These tests read
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
	Description string            `json:"description"`
	Type        json.RawMessage   `json:"type"`
	Examples    []json.RawMessage `json:"examples"`
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

// Each key filters on a field of the offer schema, and its value rule is derived from
// that field's rule: a label key uses the Label pattern; an identifier key, music.ipi
// and music.language the field's pattern; music.energy and music.parental_warning a
// pattern of the field's enum; music.label and music.publisher the name's minLength;
// the range keys the offer's lower bound for music.bpm and music.duration_seconds, and
// two release dates; the boolean keys the boolean type. A key that takes a list has
// minItems 1 and the same rule on each item. Every key must have a derived rule, so a
// new key fails here until its rule is tied to the offer schema.
func TestFilterSchemaUsesTheOfferSchemaFormats(t *testing.T) {
	offer := offerSchemaRaw(t)
	prop := func(path ...string) map[string]any {
		node := offer
		for _, k := range path {
			next, ok := node[k].(map[string]any)
			if !ok {
				t.Fatalf("the offer schema has no %s", strings.Join(path, "/"))
			}
			node = next
		}
		return node
	}
	str := func(m map[string]any, k string) string {
		v, ok := m[k].(string)
		if !ok || v == "" {
			t.Fatalf("the offer schema has no %q here: %v", k, m)
		}
		return v
	}
	enumPattern := func(m map[string]any) string {
		vals, ok := m["enum"].([]any)
		if !ok || len(vals) == 0 {
			t.Fatalf("the offer schema has no enum here: %v", m)
		}
		alts := make([]string, len(vals))
		for i, v := range vals {
			alts[i] = regexp.QuoteMeta(v.(string))
		}
		return "^(?:" + strings.Join(alts, "|") + ")$"
	}
	props := func(k string) map[string]any { return prop("properties", k) }

	// The bounds the range patterns encode: a bpm is an integer of at least 1, and a
	// duration a number above 0.
	if b := props("music.bpm"); b["type"] != "integer" || b["minimum"] != 1.0 {
		t.Errorf("offer music.bpm is %v; music.bpm_range encodes an integer of at least 1", b)
	}
	if d := props("music.duration_seconds"); d["type"] != "number" || d["exclusiveMinimum"] != 0.0 {
		t.Errorf("offer music.duration_seconds is %v; music.duration_seconds_range encodes a number above 0", d)
	}
	const posInt = "[0-9]*[1-9][0-9]*"
	const posNum = `(?:[0-9]*[1-9][0-9]*(?:\.[0-9]+)?|[0-9]+\.[0-9]*[1-9][0-9]*)`
	rangeOf := func(n string) string { return "^(?:" + n + "-" + n + "|" + n + "-|-" + n + ")$" }
	date := str(props("music.release_date"), "pattern")
	date = date[1 : len(date)-1]

	type rule struct {
		Type      any
		Pattern   any
		MinLength any
	}
	many := func(r rule) map[string]any {
		item := map[string]any{"type": "string"}
		out := map[string]any{"type": []any{"string", "array"}, "minItems": 1.0}
		for k, v := range map[string]any{"pattern": r.Pattern, "minLength": r.MinLength} {
			if v != nil {
				item[k], out[k] = v, v
			}
		}
		out["items"] = item
		return out
	}
	label := str(prop("$defs", "Label"), "pattern")
	pat := func(p string) map[string]any { return many(rule{Pattern: p}) }
	want := map[string]map[string]any{
		"music.isrc":                   pat(str(props("music.isrc"), "pattern")),
		"music.upc":                    pat(str(props("music.upc"), "pattern")),
		"music.grid":                   pat(str(props("music.grid"), "pattern")),
		"music.iswc":                   pat(str(props("music.iswc"), "pattern")),
		"music.language":               pat(str(props("music.language"), "pattern")),
		"music.ipi":                    pat(str(prop("$defs", "IPI"), "pattern")),
		"music.energy":                 pat(enumPattern(props("music.energy"))),
		"music.parental_warning":       pat(enumPattern(props("music.parental_warning"))),
		"music.label":                  many(rule{MinLength: props("music.label")["minLength"]}),
		"music.publisher":              many(rule{MinLength: prop("$defs", "Publisher", "properties", "name")["minLength"]}),
		"music.bpm_range":              {"type": "string", "pattern": rangeOf(posInt)},
		"music.duration_seconds_range": {"type": "string", "pattern": rangeOf(posNum)},
		"music.release_date_range":     {"type": "string", "pattern": "^(?:" + date + "/" + date + "|" + date + "/|/" + date + ")$"},
		"music.vocals":                 {"type": props("music.vocals")["type"]},
		"music.contains_ai":            {"type": props("music.contains_ai")["type"]},
	}
	for _, k := range []string{
		"music.genre", "music.subgenres", "music.themes", "music.mood", "music.instruments",
		"music.suitable_for", "music.key", "music.version",
	} {
		want[k] = pat(label)
	}

	var doc struct {
		Properties map[string]map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(readFilters(t), &doc); err != nil {
		t.Fatal(err)
	}
	// music.publisher and music.ipi filter on keys inside music.publishers and
	// music.contributors; every other key names its field, a range key with _range.
	inside := map[string]bool{"music.publisher": true, "music.ipi": true}
	for key, p := range doc.Properties {
		field := strings.TrimSuffix(key, "_range")
		if _, ok := offer["properties"].(map[string]any)[field]; !ok && !inside[key] {
			t.Errorf("%s filters on %s, which the offer schema does not define", key, field)
		}
		w, ok := want[key]
		if !ok {
			t.Errorf("%s has no rule derived from the offer schema", key)
			continue
		}
		got := map[string]any{}
		for k, v := range p {
			if k != "description" && k != "examples" {
				got[k] = v
			}
		}
		if !reflect.DeepEqual(got, w) {
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(w)
			t.Errorf("%s:\n got %s\nwant %s", key, gj, wj)
		}
	}
}

func offerSchemaRaw(t *testing.T) map[string]any {
	t.Helper()
	page, err := os.ReadFile(specPage)
	if err != nil {
		t.Fatal(err)
	}
	m := schemaFenceRe.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no ```json block under \"## JSON Schema\" in %s", specPage)
	}
	var doc map[string]any
	if err := json.Unmarshal(m[1], &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The protocol SDK's registration-schema compiler, which FORA Server's filter
// vocabulary loader uses, refuses the file today: eleven keys have a pattern outside
// its portable alphabet. The eight label keys use \p{...} classes, and music.language,
// music.release_date_range and music.duration_seconds_range quantify a group whose body
// repeats or branches. This test records that verdict, so a change in either the file
// or the compiler is noticed.
func TestFilterSchemaRegistrationCompilerVerdict(t *testing.T) {
	raw := readFilters(t)
	if _, v := helpers.CompileRegistrationSchema(raw); v != helpers.SchemaUnsafePattern {
		t.Errorf("CompileRegistrationSchema = %s, want %s", v, helpers.SchemaUnsafePattern)
	}
	var doc struct {
		Properties map[string]struct {
			Pattern string `json:"pattern"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var unsafe []string
	for k, p := range doc.Properties {
		if p.Pattern != "" && !helpers.IsSafeSchemaPattern(p.Pattern) {
			unsafe = append(unsafe, k)
		}
	}
	slices.Sort(unsafe)
	want := []string{
		"music.duration_seconds_range", "music.genre", "music.instruments", "music.key",
		"music.language", "music.mood", "music.release_date_range", "music.subgenres",
		"music.suitable_for", "music.themes", "music.version",
	}
	if !slices.Equal(unsafe, want) {
		t.Errorf("keys outside the portable pattern alphabet:\n got %v\nwant %v", unsafe, want)
	}
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
