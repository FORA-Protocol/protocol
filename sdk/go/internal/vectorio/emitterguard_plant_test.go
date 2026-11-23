package vectorio_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// plantedTree writes a small Go tree that breaks the emitter rule in each way the
// guard catches, beside files that look alike and do not, and returns its root.
func plantedTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		// A helper that calls Check makes every file of its package that calls it an
		// emitter, here under a renamed import of vectorio.
		"a/helper_test.go": "package a\n\nimport vec \"" + vectorioPath + "\"\n\n" +
			"func assertMatches() { _ = vec.Check(\"c.json\", nil) }\n",
		"a/emitter_test.go": "package a\n\nimport \"os\"\n\nfunc TestE() {\n\tassertMatches()\n" +
			"\tif os.Getenv(\"REGEN\") != \"\" {\n\t\t_ = os.WriteFile(\"c.json\", nil, 0o600)\n\t}\n}\n",
		// Writing a temporary file is fine in a file that is not an emitter.
		"a/temp_test.go": "package a\n\nimport \"os\"\n\nfunc TestT() { _ = os.WriteFile(\"x\", nil, 0o600) }\n",
		"a/alias_test.go": "package a\n\nimport (\n\txos \"os\"\n\n\t\"" + vectorioPath + "\"\n)\n\n" +
			"func TestA() {\n\t_ = vectorio.Check(\"c.json\", nil)\n\t_ = xos.Getenv(\"X\")\n}\n",
		"a/flag_test.go": "package a\n\nimport (\n\t\"flag\"\n\n\t\"" + vectorioPath + "\"\n)\n\n" +
			"var update = flag.Bool(\"update\", false, \"\")\n\n" +
			"func TestF() { _ = vectorio.Check(\"c.json\", nil) }\n",
		// A file named as an emitter is one, whether or not it calls Check.
		"a/gen_y_test.go": "package a\n\nimport \"os\"\n\nfunc TestG() { _, _ = os.LookupEnv(\"X\") }\n",
		// Another package's assertMatches does not call Check, and another package
		// named vectorio is not this one.
		"b/b_test.go": "package b\n\nimport \"os\"\n\nfunc assertMatches() {}\n\n" +
			"func TestB() {\n\tassertMatches()\n\t_ = os.Getenv(\"X\")\n}\n",
		"b/other_test.go": "package b\n\nimport (\n\t\"os\"\n\n\t\"example.com/vectorio\"\n)\n\n" +
			"func TestO() {\n\t_ = vectorio.Check(\"x\", nil)\n\t_ = os.Getenv(\"X\")\n}\n",
		"b/named_test.go": "package b\n\n// " + retiredSwitch + "=1 rewrites it\n",
	}
	for name, src := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestTheEmitterGuardFindsEachForbiddenCall(t *testing.T) {
	root := plantedTree(t)
	problems, err := scan(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"a/alias_test.go: an emitter calls os.Getenv",
		"a/emitter_test.go: an emitter calls os.Getenv",
		"a/emitter_test.go: an emitter calls os.WriteFile",
		"a/flag_test.go: an emitter calls flag.Bool",
		"a/gen_y_test.go: an emitter calls os.LookupEnv",
		"b/named_test.go: names " + retiredSwitch + "; regenerate with scripts/vectors.sh",
	}
	got := make([]string, 0, len(problems))
	for _, p := range problems {
		got = append(got, filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator))))
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("the guard found:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}
