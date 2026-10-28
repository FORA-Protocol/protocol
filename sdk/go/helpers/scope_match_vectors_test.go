package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// scopeCoverVector is one ScopeCovers case: a granted scope, a required scope
// and the verdict the WRITTEN scope-matching rule (Requester.scopes) gives.
type scopeCoverVector struct {
	Name     string `json:"name"`
	Granted  string `json:"granted"`
	Required string `json:"required"`
	Expected bool   `json:"expected"`
}

// scopeCoverSetVector is one ScopesCover case over lists. The same row also
// pins ScopesSubset(required, granted), which is the same containment check
// read from the child's side.
type scopeCoverSetVector struct {
	Name     string   `json:"name"`
	Granted  []string `json:"granted"`
	Required []string `json:"required"`
	Expected bool     `json:"expected"`
}

// TestScopeMatchCorpusReplays drives every row of scope-match-vectors.json
// through ScopeCovers, ScopesCover and ScopesSubset. Unlike the emitted
// corpora, this file is hand-written from the rule text so the verdicts do not
// derive from the implementation they test; Python and TypeScript replay the
// same file.
func TestScopeMatchCorpusReplays(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "scope-match-vectors.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var doc struct {
		Covers    []scopeCoverVector    `json:"covers"`
		CoverSets []scopeCoverSetVector `json:"cover_sets"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode corpus: %v", err)
	}
	if len(doc.Covers) == 0 || len(doc.CoverSets) == 0 {
		t.Fatal("corpus must carry covers and cover_sets rows")
	}
	for _, c := range doc.Covers {
		if got := ScopeCovers(c.Granted, c.Required); got != c.Expected {
			t.Errorf("%s: ScopeCovers(%q, %q) = %v, corpus says %v", c.Name, c.Granted, c.Required, got, c.Expected)
		}
	}
	for _, c := range doc.CoverSets {
		if got := ScopesCover(c.Granted, c.Required); got != c.Expected {
			t.Errorf("%s: ScopesCover(%q, %q) = %v, corpus says %v", c.Name, c.Granted, c.Required, got, c.Expected)
		}
		if got := ScopesSubset(c.Required, c.Granted); got != c.Expected {
			t.Errorf("%s: ScopesSubset(%q, %q) = %v, corpus says %v", c.Name, c.Required, c.Granted, got, c.Expected)
		}
	}
}
