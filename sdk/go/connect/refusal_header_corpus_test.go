package connect_test

// Go replay of the refusal-header corpus (refusal-header-vectors.json).
//
// The corpus is the cross-language contract for which failures carry the header fields of
// the answer that produced them, so Go replays the committed rows too rather than only
// emitting them: each row's own answer is served again and the real client must carry
// exactly what the row records.

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

func TestRefusalHeaderCorpusReplay(t *testing.T) {
	raw, err := os.ReadFile(refusalHeaderVectorsPath) //nolint:gosec // a committed test vector
	if err != nil {
		t.Fatalf("read %s: %v", refusalHeaderVectorsPath, err)
	}
	var doc struct {
		Refusals []refusalHeaderVector `json:"refusals"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", refusalHeaderVectorsPath, err)
	}
	if len(doc.Refusals) == 0 {
		t.Fatalf("%s carries no vectors — the replay would assert nothing", refusalHeaderVectorsPath)
	}

	// Both outcomes on both legs, or the corpus pins half a rule.
	seen := map[string]bool{}
	for _, row := range doc.Refusals {
		t.Run(row.Name, func(t *testing.T) {
			cerr := refusalHeaderFailure(t, row)
			if len(row.Carried) == 0 {
				if len(cerr.Header) != 0 {
					t.Errorf("carries %v, want no field at all", cerr.Header)
				}
			} else {
				if cerr.Status != row.Status {
					t.Errorf("status = %d, want %d", cerr.Status, row.Status)
				}
				for name, want := range row.Carried {
					if got := fieldValue(cerr.Header, name); got != want {
						t.Errorf("%s = %q, want %q", name, got, want)
					}
				}
			}
			if _, hint := refusalHeaderOutcome(row, cerr); hint != row.Hint {
				t.Errorf("hint = %+v, want %+v", hint, row.Hint)
			}
		})
		seen[row.Leg+map[bool]string{true: " carried", false: " empty"}[len(row.Carried) > 0]] = true
		if row.Strict {
			seen["strict"] = true
		}
		if row.Status == http.StatusForbidden && row.Hint.ExchangeState == "valid" {
			seen["hint"] = true
		}
	}
	for _, want := range []string{"rpc carried", "rpc empty", "content carried", "content empty", "strict", "hint"} {
		if !seen[want] {
			t.Errorf("the corpus has no %s row", want)
		}
	}
}
