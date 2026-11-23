// Package envguard holds the structural guard that keeps the three SDKs from reading
// the environment.
//
// An SDK that reads an environment variable lets whoever controls the process
// environment change what the library does, and the variables this repository
// inherited (SKIP_SSRF and ALLOW_INSECURE) did exactly that to the SSRF guard. AGENTS.md
// forbids any switch a test could use to relax a check; a caller that needs different
// behavior passes its own client, resolver, clock or key. This guard fails if the
// library code of any SDK reads the environment again, in any form the language offers.
//
// It reads the library code only: the test suites, the examples and the build scripts
// are applications of the SDK, not the SDK, and the vector emitters' FORA_UPDATE_VECTORS
// is a separate inherited switch AGENTS.md tracks on its own.
package envguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// sdkRoot is sdk/, relative to this package's directory (sdk/go/internal/envguard).
const sdkRoot = "../../.."

// goEnvReads are the functions of os and syscall that read the environment.
var goEnvReads = map[string]map[string]bool{
	"os":      {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
	"syscall": {"Getenv": true, "Environ": true},
}

// pythonEnvRead matches a read of the environment in Python: os.environ (and
// os.environb), os.getenv, and the names imported from os on their own.
var pythonEnvRead = regexp.MustCompile(
	`\bos\.(?:environb?|getenv)\b|\bfrom\s+os\s+import\b[^\n]*\b(?:environb?|getenv)\b`)

// tsEnvRead matches a read of the environment in TypeScript: Node's process.env in
// either spelling, Deno.env, Bun.env and import.meta.env.
var tsEnvRead = regexp.MustCompile(
	`\bprocess\s*(?:\.\s*env\b|\[\s*["'` + "`" + `]env["'` + "`" + `]\s*\])|` +
		`\bDeno\.env\b|\bBun\.env\b|\bimport\.meta\.env\b`,
)

// pythonComment and tsComment strip what a reader writes in prose, so a comment that
// names a variable is not a read. A string literal that spells one out is still caught,
// which is the safe side: a library has no business quoting process.env either.
var (
	pythonComment = regexp.MustCompile(`(?m)#.*$`)
	tsComment     = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)
)

// goReads returns each environment read in the Go source src, as "pkg.Func".
func goReads(t *testing.T, name string, src []byte) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), name, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	local := map[string]string{} // the name a file binds os or syscall to -> the package
	for _, spec := range file.Imports {
		path, _ := strconv.Unquote(spec.Path.Value)
		if _, ok := goEnvReads[path]; !ok {
			continue
		}
		alias := path
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		local[alias] = path
	}
	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && goEnvReads[local[id.Name]][sel.Sel.Name] {
			found = append(found, local[id.Name]+"."+sel.Sel.Name)
		}
		return true
	})
	return found
}

// textReads returns each match of read in src once comment strips the comments.
func textReads(src []byte, comment, read *regexp.Regexp) []string {
	return read.FindAllString(comment.ReplaceAllString(string(src), ""), -1)
}

// libraryFiles returns the library sources of one SDK, as paths in fsys: the files
// under dir with the suffix, minus the test, example and script trees and the test
// files.
func libraryFiles(t *testing.T, fsys fs.FS, dir, suffix string) []string {
	t.Helper()
	skipDirs := map[string]bool{
		"tests": true, "testdata": true, "examples": true, "scripts": true,
		"node_modules": true, ".venv": true, "__pycache__": true,
	}
	var out []string
	err := fs.WalkDir(fsys, dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if strings.HasSuffix(name, suffix) && !strings.HasSuffix(name, "_test.go") &&
			!strings.HasSuffix(name, ".test.ts") && !strings.HasSuffix(name, ".d.ts") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if len(out) == 0 {
		t.Fatalf("no %s library file under %s; the guard would check nothing", suffix, dir)
	}
	return out
}

// libraryScan is one SDK: where its library code is, and how a read of the
// environment is spelled in its language.
type libraryScan struct {
	dir, suffix string
	reads       func(name string, src []byte) []string
}

func libraryScans(t *testing.T) []libraryScan {
	t.Helper()
	return []libraryScan{
		{"go", ".go", func(name string, src []byte) []string { return goReads(t, name, src) }},
		{"python/fora_sdk", ".py", func(_ string, src []byte) []string {
			return textReads(src, pythonComment, pythonEnvRead)
		}},
		{"ts", ".ts", func(_ string, src []byte) []string { return textReads(src, tsComment, tsEnvRead) }},
	}
}

func TestNoSDKLibraryCodeReadsTheEnvironment(t *testing.T) {
	sdk := os.DirFS(sdkRoot)
	for _, scan := range libraryScans(t) {
		for _, path := range libraryFiles(t, sdk, scan.dir, scan.suffix) {
			src, err := fs.ReadFile(sdk, path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for _, read := range scan.reads(path, src) {
				t.Errorf("sdk/%s reads the environment (%s); pass the value in through the API instead", path, read)
			}
		}
	}
}

// goPlanted reads the environment five ways, one of them through an aliased import,
// and names a read in a comment that must not count.
const goPlanted = `package p

import (
	e "os"
	"syscall"
)

// os.Getenv is named here and not called.
var a, b, c, d = e.Getenv("X"), syscall.Getenv, e.Environ, e.ExpandEnv

var f = func() { _, _ = e.LookupEnv("X") }
`

// The guard is seen to fail: every spelling of a read it claims to catch is caught, and
// a mention in a comment, or a name that only contains the word, is not.
func TestTheGuardCatchesEveryForm(t *testing.T) {
	scans := libraryScans(t)
	if got := scans[0].reads("planted.go", []byte(goPlanted)); len(got) != 5 {
		t.Errorf("go: caught %v, want the five reads", got)
	}
	cases := []struct {
		scan       int
		read, mere []string
	}{
		{1, []string{
			`os.environ["X"]`, `os.getenv("X")`, "from os import environ", "from os import path, getenv as g", "os.environb",
		}, []string{"# os.environ is not read", "os.environment_name = 1", "getenv_count = 0", "import os"}},
		{2, []string{
			"process.env.X", `process["env"]`, "process . env", "Deno.env.get(x)", "Bun.env.X", "import.meta.env.X",
		}, []string{
			"// process.env is not read", "/* Deno.env */ const x = 1;", "const processEnv = 1;", "process.envelope()",
		}},
	}
	for _, c := range cases {
		scan := scans[c.scan]
		for _, src := range c.read {
			if got := scan.reads("planted", []byte(src)); len(got) != 1 {
				t.Errorf("%s: caught %v in %q, want one read", scan.dir, got, src)
			}
		}
		for _, src := range c.mere {
			if got := scan.reads("planted", []byte(src)); len(got) != 0 {
				t.Errorf("%s: caught %v in %q, which reads nothing", scan.dir, got, src)
			}
		}
	}
}
