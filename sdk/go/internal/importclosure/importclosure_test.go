package importclosure_test

// The walk the purity guards rely on, run on a module built for the test: it follows
// imports through other packages, ignores the standard library and imports only a test
// makes, and fails rather than returning a smaller closure when an import path does not
// map to a package.

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/importclosure"
)

const module = "example.test/m"

// writeModule lays out files (path relative to the module root → content) under a fresh
// directory and returns it.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestWalkFollowsImportsThroughOtherPackages(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":      "module " + module + "\n\ngo 1.26\n",
		"a/a.go":      "package a\n\nimport (\n\t_ \"" + module + "/b\"\n\t_ \"" + module + "/c\"\n)\n",
		"a/a_test.go": "package a\n\nimport _ \"" + module + "/d\"\n",
		"b/b.go":      "package b\n\nimport (\n\t\"fmt\"\n\n\t_ \"" + module + "/c\"\n)\n\nvar _ = fmt.Sprint\n",
		"c/c.go":      "package c\n",
		"d/d.go":      "package d\n",
	})
	got, err := importclosure.Walk(root, module, module+"/a")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{module + "/a", module + "/b", module + "/c"}
	if paths := slices.Sorted(maps.Keys(got)); !slices.Equal(paths, want) {
		t.Fatalf("closure = %v, want %v: transitive, without the standard library or a test-only import", paths, want)
	}
	if dir := got[module+"/c"]; dir != filepath.Join(root, "c") {
		t.Errorf("%s/c is at %s, want %s", module, dir, filepath.Join(root, "c"))
	}

	path, err := importclosure.ModulePath(root)
	if err != nil || path != module {
		t.Errorf("ModulePath = %q, %v; want %q", path, err, module)
	}
}

func TestWalkFailsOnAnImportItCannotMapToAPackage(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"a missing directory", map[string]string{
			"a/a.go": "package a\n\nimport _ \"" + module + "/missing\"\n",
		}},
		{"a directory with test files only", map[string]string{
			"a/a.go":      "package a\n\nimport _ \"" + module + "/e\"\n",
			"e/e_test.go": "package e\n",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := importclosure.Walk(writeModule(t, c.files), module, module+"/a")
			if err == nil {
				t.Fatal("the walk returned a closure; it must fail instead of leaving the package out")
			}
			if !strings.HasPrefix(err.Error(), "importclosure:") {
				t.Errorf("error %q does not say where it came from", err)
			}
		})
	}
}
