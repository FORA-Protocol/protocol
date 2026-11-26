package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// contractSource is one contract file's .proto source, split into lines.
type contractSource struct {
	path  string
	lines []string
}

// contractSources reads the .proto source of every contract file, in Contract order.
// The descriptor keeps no comments, so a guard that reads a rule out of a comment
// reads the source. Contract carries the descriptor path (e.g. "fora/v1/fora.proto");
// the buf module root is ../proto relative to this package's directory.
func contractSources(t *testing.T) []contractSource {
	t.Helper()
	out := make([]contractSource, 0, len(Contract))
	for _, cf := range Contract {
		path := filepath.Join("..", "proto", cf.File.Path())
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		out = append(out, contractSource{path: path, lines: strings.Split(string(b), "\n")})
	}
	return out
}
