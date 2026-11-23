// Package envguard holds the structural guard that keeps the Go SDK from reading the
// environment.
//
// An SDK that reads an environment variable lets whoever controls the process
// environment change what the library does, and the variables this repository
// inherited (SKIP_SSRF and ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md
// forbids any switch a test could use to relax a check; a caller that needs different
// behavior passes its own client, resolver, clock or key.
//
// The guard parses every library file of the Go SDK with go/parser and fails on:
//   - any reference to os.Getenv, os.LookupEnv, os.Environ or os.ExpandEnv, or to
//     syscall.Getenv or syscall.Environ, called or not, through whatever name the file
//     imports the package as;
//   - a dot import of os or syscall, which would let those functions be named
//     unqualified.
//
// Comments and string literals are not code, so a mention there is not a read. The test
// files, testdata, the examples and the build scripts are applications of the SDK, not
// the SDK, and are not read; the vector emitters' FORA_UPDATE_VECTORS is a separate
// inherited switch AGENTS.md tracks on its own. The Python and TypeScript SDKs hold the
// same rule with their own parsers: sdk/python/tests/test_guards_no_environment_reads.py
// and sdk/ts/tests/no-environment-reads.guard.test.ts.
package envguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
)

// goRoot is sdk/go, relative to this package's directory (sdk/go/internal/envguard).
const goRoot = "../.."

// envReads are the functions of os and syscall that read the environment.
var envReads = map[string]map[string]bool{
	"os":      {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
	"syscall": {"Getenv": true, "Environ": true},
}

// reads returns each environment read in the Go source src, as "pkg.Func", and each
// dot import of an environment package, as "import . pkg".
func reads(t *testing.T, name string, src []byte) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var found []string
	local := map[string]string{} // the name a file binds os or syscall to -> the package
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		if _, ok := envReads[path]; !ok {
			continue
		}
		switch {
		case spec.Name == nil:
			local[path] = path
		case spec.Name.Name == ".":
			found = append(found, "import . "+path)
		default:
			local[spec.Name.Name] = path
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && envReads[local[id.Name]][sel.Sel.Name] {
			found = append(found, local[id.Name]+"."+sel.Sel.Name)
		}
		return true
	})
	return found
}

// libraryFiles returns the library sources of the Go SDK, as paths in fsys: every .go
// file under it but the test files and the test, example and script trees.
func libraryFiles(t *testing.T, fsys fs.FS) []string {
	t.Helper()
	skipDirs := map[string]bool{"testdata": true, "examples": true, "scripts": true}
	var out []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", goRoot, err)
	}
	if len(out) == 0 {
		t.Fatalf("no library file under %s; the guard would check nothing", goRoot)
	}
	return out
}

func TestNoGoSDKLibraryCodeReadsTheEnvironment(t *testing.T) {
	sdk := os.DirFS(goRoot)
	for _, path := range libraryFiles(t, sdk) {
		src, err := fs.ReadFile(sdk, path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, read := range reads(t, path, src) {
			t.Errorf("sdk/go/%s reads the environment (%s); pass the value in through the API instead", path, read)
		}
	}
}

// planted reads the environment in every form the guard claims to catch. Each case is
// one file; want is how many reads it holds.
var planted = []struct {
	name, src string
	want      int
}{
	{"each function, qualified", `package p
import "os"
import "syscall"
var a, b, c, d = os.Getenv("X"), os.Environ, os.ExpandEnv, syscall.Environ
var e = func() { _, _ = os.LookupEnv("X"); _, _ = syscall.Getenv("X") }
`, 6},
	{"an aliased import", `package p
import e "os"
var a = e.Getenv("X")
`, 1},
	{"a dot import of os", `package p
import . "os"
var a = Getenv("X")
`, 1},
	{"a dot import of syscall", `package p
import . "syscall"
`, 1},
	{"a mention in a comment or a string", `package p
import "os"
// os.Getenv is named here and not called.
var a = "os.Getenv(\"X\") // #"
var b = os.Args
`, 0},
	{"a package of another name", `package p
import os "path"
var a = os.Join("a", "b")
`, 0},
}

// The guard is seen to fail: every form it claims to catch is caught, and a mention
// in a comment or a string, or another package's function, is not.
func TestTheGuardCatchesEveryForm(t *testing.T) {
	for _, c := range planted {
		if got := reads(t, "planted.go", []byte(c.src)); len(got) != c.want {
			t.Errorf("%s: caught %v, want %d reads", c.name, got, c.want)
		}
	}
}
