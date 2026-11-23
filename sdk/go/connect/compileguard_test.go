package connect_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// compileGuardDir holds one Go program per case of the compile-time guard on
// Client.Execute: an app cannot forge a core.VerifiedOffer and cannot hand Execute
// anything but one. "Does not compile" is not a runtime assertion, so each case is
// a program the test builds. Each file names the compiler errors it must produce
// on its `// want-compile-error:` lines; a file with none must compile. The files
// end in .go.txt so that no build of this module reads them.
const compileGuardDir = "testdata/compileguard"

const wantCompileError = "// want-compile-error: "

// TestExecuteAcceptsOnlyAVerifiedOffer builds each case as a package inside this
// module, so its imports resolve to the module's own packages and the module cache
// with no network, and asserts the build fails with every error the case names,
// or succeeds when it names none.
func TestExecuteAcceptsOnlyAVerifiedOffer(t *testing.T) {
	cases, err := filepath.Glob(filepath.Join(compileGuardDir, "*.go.txt"))
	if err != nil || len(cases) == 0 {
		t.Fatalf("no compile-guard cases in %s (err %v)", compileGuardDir, err)
	}
	for _, path := range cases {
		t.Run(strings.TrimSuffix(filepath.Base(path), ".go.txt"), func(t *testing.T) {
			checkCompileGuardCase(t, path)
		})
	}
}

// checkCompileGuardCase builds the case at path and checks the outcome it names.
func checkCompileGuardCase(t *testing.T, path string) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := wantedErrors(string(src))
	out, buildErr := buildProgram(t, src)
	if len(want) == 0 {
		if buildErr != nil {
			t.Fatalf("the control case must compile: %v\n%s", buildErr, out)
		}
		return
	}
	if buildErr == nil {
		t.Fatalf("the case compiled; the guard must refuse it with %q", want)
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("the build failed without the error %q:\n%s", w, out)
		}
	}
}

// wantedErrors returns the text of each `// want-compile-error:` line of src.
func wantedErrors(src string) []string {
	var want []string
	for line := range strings.SplitSeq(src, "\n") {
		if text, ok := strings.CutPrefix(line, wantCompileError); ok {
			want = append(want, strings.TrimSpace(text))
		}
	}
	return want
}

// buildProgram writes src as main.go into a fresh directory under testdata, which
// the module's ./... patterns never match, and runs `go build` on it there.
func buildProgram(t *testing.T, src []byte) (string, error) {
	t.Helper()
	dir, err := os.MkdirTemp("testdata", "compileguard-build-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.WriteFile(filepath.Join(dir, "main.go"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", os.DevNull, ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}
