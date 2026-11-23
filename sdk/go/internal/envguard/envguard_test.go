// Package envguard holds the structural guard that keeps the Go SDK from reading the
// environment.
//
// An SDK that reads an environment variable lets whoever controls the process
// environment change what the library does, and the variables this repository
// inherited (SKIP_SSRF and ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md
// forbids any switch a test could use to relax a check; a caller that needs different
// behavior passes its own client, resolver, clock or key.
//
// The rule, the same in all three SDKs: every source file under the SDK's root is
// parsed, except a path the exemption table names with its reason, and a finding is
// any occurrence in code of a name in the language's set of environment readers: as an
// identifier, as a member of any receiver, as an imported name, or as a string literal
// whose whole value is the name. The receiver does not matter, so a reader reached
// through an alias, a reflective lookup or a string key is refused like a direct call,
// and so is an unrelated name that happens to match; rename it. Comments are not code.
// A name assembled at run time, for example by joining strings, is not caught. An
// exemption that matches no file fails the guard.
//
// In Go the SDK's root is sdk/go, the files are read with go/parser, and the set is
// Getenv, LookupEnv, Environ, ExpandEnv, Setenv, Unsetenv, Clearenv, UserHomeDir,
// UserCacheDir, UserConfigDir and TempDir: the functions of os and syscall (and of
// golang.org/x/sys) that read or write the environment, including the ones that read
// HOME, the XDG variables or TMPDIR. The Python and TypeScript SDKs hold the same rule
// with their own parsers: sdk/python/tests/test_guards_no_environment_reads.py and
// sdk/ts/tests/no-environment-reads.guard.test.ts.
package envguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// goRoot is sdk/go, relative to this package's directory (sdk/go/internal/envguard).
const goRoot = "../.."

// envReaders is the Go set of environment readers.
var envReaders = map[string]bool{
	"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true,
	"Setenv": true, "Unsetenv": true, "Clearenv": true,
	"UserHomeDir": true, "UserCacheDir": true, "UserConfigDir": true, "TempDir": true,
}

// exemption is one path the guard does not read, as a regular expression over the
// slash-separated path relative to the SDK's root, and the reason.
type exemption struct {
	pattern *regexp.Regexp
	reason  string
}

// exemptions is the guard's config: the only paths under sdk/go it does not read.
var exemptions = []exemption{
	{regexp.MustCompile(`_test\.go$`), "the test files apply the SDK; they call t.Setenv to prove " +
		"the retired variables change nothing, and the vector emitters read FORA_UPDATE_VECTORS, " +
		"a separate inherited switch AGENTS.md tracks on its own"},
}

// readers returns each environment reader named in the Go source src, as
// "line:column name".
func readers(t *testing.T, name string, src []byte) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var found []string
	report := func(pos token.Pos, what string) {
		p := fset.Position(pos)
		found = append(found, fmt.Sprintf("%d:%d %s", p.Line, p.Column, what))
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			if envReaders[node.Name] {
				report(node.Pos(), node.Name)
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING {
				if s, uerr := strconv.Unquote(node.Value); uerr == nil && envReaders[s] {
					report(node.Pos(), node.Value)
				}
			}
		}
		return true
	})
	return found
}

// exempt returns the index of the exemption that covers path, or -1.
func exempt(path string) int {
	return slices.IndexFunc(exemptions, func(e exemption) bool { return e.pattern.MatchString(path) })
}

// sourceFiles returns the Go files under fsys the guard reads, and records in used
// which exemptions covered a file.
func sourceFiles(t *testing.T, fsys fs.FS, used []bool) []string {
	t.Helper()
	var out []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if i := exempt(path); i >= 0 {
			used[i] = true
			return nil
		}
		out = append(out, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", goRoot, err)
	}
	if len(out) == 0 {
		t.Fatalf("no source file under %s; the guard would check nothing", goRoot)
	}
	return out
}

func TestNoGoSDKLibraryCodeReadsTheEnvironment(t *testing.T) {
	sdk := os.DirFS(goRoot)
	used := make([]bool, len(exemptions))
	for _, path := range sourceFiles(t, sdk, used) {
		src, err := fs.ReadFile(sdk, path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, r := range readers(t, path, src) {
			t.Errorf("sdk/go/%s names an environment reader (%s); pass the value in through the API instead", path, r)
		}
	}
	for i, e := range exemptions {
		if !used[i] {
			t.Errorf("the exemption %q matches no file; remove it", e.pattern)
		}
	}
}

// planted names an environment reader in every form the guard claims to catch. Each
// case is one file; want is how many names it holds.
var planted = []struct {
	name, src string
	want      int
}{
	{"each reader, qualified", `package p
import ("os"; "syscall")
var a, b, c, d = os.Getenv("X"), os.Environ, os.ExpandEnv, syscall.Environ
var e = func() { _, _ = os.LookupEnv("X"); _, _ = syscall.Getenv("X"); os.Clearenv() }
var f = func() { _ = os.Setenv("X", ""); _ = os.Unsetenv("X") }
var g, h, i, j = os.UserHomeDir, os.UserCacheDir, os.UserConfigDir, os.TempDir
`, 13},
	{"an aliased import", `package p
import e "os"
var a = e.Getenv("X")
`, 1},
	{"a dot import", `package p
import . "os"
var a = Getenv("X")
`, 1},
	{"another package's reader", `package p
import "golang.org/x/sys/unix"
var a, _ = unix.Getenv("X")
`, 1},
	{"a reader held in a variable", `package p
import "os"
var read = os.LookupEnv
`, 1},
	{"a reflective lookup by name", `package p
import "reflect"
var m = reflect.ValueOf(nil).MethodByName("Getenv")
`, 1},
	{"an unrelated name that matches", `package p
type cfg struct{}
func (cfg) Environ() []string { return nil }
`, 1},
	{"a mention in a comment, or in a longer string", `package p
import "os"
// os.Getenv is named here and not called.
var a = "os.Getenv(\"X\") // #"
var b = os.Args
`, 0},
	{"a name assembled at run time", `package p
var a = "Get" + "env"
`, 0},
}

// The guard is seen to fail: every form it claims to catch is caught, and a mention
// in a comment or a longer string is not.
func TestTheGuardCatchesEveryForm(t *testing.T) {
	for _, c := range planted {
		if got := readers(t, "planted.go", []byte(c.src)); len(got) != c.want {
			t.Errorf("%s: caught %v, want %d names", c.name, got, c.want)
		}
	}
}

// The exemption table covers exactly the paths it names.
func TestTheExemptionsCoverOnlyTheirPaths(t *testing.T) {
	for path, want := range map[string]bool{
		"resolvers/guardedclient_test.go": true,
		"resolvers/guardedclient.go":      false,
		"resolvers/test.go":               false,
	} {
		if got := exempt(path) >= 0; got != want {
			t.Errorf("exempt(%q) = %v, want %v", path, got, want)
		}
	}
}
