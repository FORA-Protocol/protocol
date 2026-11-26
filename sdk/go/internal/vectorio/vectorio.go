// Package vectorio holds the byte semantics of a committed conformance corpus.
//
// Every emitter renders a corpus the same way and compares it the same way, and the
// bytes are the contract: a corpus is committed, so an emitter that indented
// differently or dropped the trailing newline would rewrite the whole file and
// report the change as drift. Those semantics lived in one package's test files and
// were re-inlined by the emitter in another, because Go cannot reach a _test.go
// helper across a package boundary.
//
// An emitter only compares. When the committed corpus differs from what it renders,
// Check writes the rendering beside it, as <corpus>.got, and reports the mismatch;
// scripts/vectors.sh runs the emitters and moves each .got file over its corpus.
// No test writes a committed corpus, and nothing a test reads chooses between
// comparing and writing.
//
// It deliberately takes no *testing.T and returns errors instead of failing. A
// non-test package that imports testing registers the -test.* flags on every binary
// that links it, so what is shared here is the byte handling; each emitter keeps its
// own t.Fatal.
package vectorio

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// GotSuffix names the file Check writes beside a corpus its emitter no longer matches.
const GotSuffix = ".got"

// Accepted is the corpus outcome of a call that did not refuse.
const Accepted = "accepted"

// gotPerm is the mode of a .got file: a local, untracked rendering.
const gotPerm = 0o600

// Marshal renders v the way every committed corpus is written: two-space indent and
// exactly one trailing newline.
func Marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Outcome renders the outcome of a call in the one corpus format (ADR-002 rule 3):
// "accepted" when err is nil, and "refused:" + reason otherwise, where reason is the
// token the SDK reports for err (helpers.ReasonOf). A refusal without a token renders
// as "refused:", which the corpus-contract gate refuses.
func Outcome(err error, reason string) string {
	if err == nil {
		return Accepted
	}
	return "refused:" + reason
}

// Check compares the corpus committed at path with what v renders to.
//
// On a match it removes a .got file left beside the corpus by an earlier mismatch,
// and returns nil. On a mismatch, or when the corpus cannot be read, it writes the
// rendering to path+GotSuffix and returns an error that names that file.
func Check(path string, v any) error {
	want, err := Marshal(v)
	if err != nil {
		return fmt.Errorf("render %s: %w", path, err)
	}
	got, err := os.ReadFile(path) //nolint:gosec // a path this package's callers own
	if err == nil && string(got) == string(want) {
		return removeGot(path)
	}
	readErr := err
	if err := os.WriteFile(path+GotSuffix, want, gotPerm); err != nil {
		return fmt.Errorf("%s differs from its emitter, and writing %s failed: %w", path, path+GotSuffix, err)
	}
	if readErr != nil {
		return fmt.Errorf("cannot read %s (%w); the emitter's rendering is in %s: "+
			"run scripts/vectors.sh to move it into place", path, readErr, path+GotSuffix)
	}
	return fmt.Errorf("%s differs from what its emitter renders, now in %s: "+
		"run scripts/vectors.sh to move it into place", path, path+GotSuffix)
}

// removeGot removes the .got file an earlier mismatch left beside the corpus at path.
func removeGot(path string) error {
	if err := os.Remove(path + GotSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale %s: %w", path+GotSuffix, err)
	}
	return nil
}
