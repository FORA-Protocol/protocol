package vectorio_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

type corpus struct {
	Vectors []string `json:"vectors"`
}

var sample = corpus{Vectors: []string{"a", "b"}}

// writeCorpus commits v at a fresh path and returns the path.
func writeCorpus(t *testing.T, v any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample-vectors.json")
	b, err := vectorio.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCheckPassesOnAMatchAndRemovesAStaleGotFile(t *testing.T) {
	path := writeCorpus(t, sample)
	got := path + vectorio.GotSuffix
	if err := os.WriteFile(got, []byte("left by an earlier mismatch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := vectorio.Check(path, sample); err != nil {
		t.Fatalf("Check on a matching corpus = %v, want nil", err)
	}
	if _, err := os.Stat(got); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a match left %s in place (stat: %v)", got, err)
	}
}

func TestCheckFailsOnAMismatchAndWritesTheRenderingBesideTheCorpus(t *testing.T) {
	path := writeCorpus(t, corpus{Vectors: []string{"old"}})
	committed := readFile(t, path)
	err := vectorio.Check(path, sample)
	got := path + vectorio.GotSuffix
	if err == nil || !strings.Contains(err.Error(), got) {
		t.Fatalf("Check on a stale corpus = %v, want an error naming %s", err, got)
	}
	want, mErr := vectorio.Marshal(sample)
	if mErr != nil {
		t.Fatal(mErr)
	}
	if readFile(t, got) != string(want) {
		t.Fatalf("%s does not hold the emitter's rendering", got)
	}
	if readFile(t, path) != committed {
		t.Fatal("Check changed the committed corpus")
	}
}

func TestCheckFailsOnAMissingCorpusAndWritesTheRendering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent-vectors.json")
	if err := vectorio.Check(path, sample); err == nil {
		t.Fatal("Check on a missing corpus = nil, want an error")
	}
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Check created the committed corpus %s", path)
	}
	if readFile(t, path+vectorio.GotSuffix) == "" {
		t.Fatal("Check left no rendering for a missing corpus")
	}
}
