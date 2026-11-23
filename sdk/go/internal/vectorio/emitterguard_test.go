package vectorio_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The guard holds every corpus emitter to the rule that it only compares: it reads
// no environment variable and no flag, and writes no file. vectorio.Check writes the
// .got file, and nothing a test reads chooses between comparing and writing.

// retiredSwitch is the environment variable that once made an emitter write its corpus
// instead of comparing it. It is spelled in two pieces so this file does not name it.
const retiredSwitch = "FORA_UPDATE_" + "VECTORS"

const vectorioPath = "github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"

// forbidden maps an import path to the functions of it an emitter may not call; an
// empty list forbids every function of the package. Calls are matched by the import
// path, so a renamed import (`xos "os"`) is caught too.
var forbidden = map[string][]string{
	"os":        {"Getenv", "LookupEnv", "Environ", "WriteFile", "Create", "OpenFile", "Rename"},
	"syscall":   {"Getenv"},
	"io/ioutil": {"WriteFile"},
	"flag":      nil,
}

// call is a call to a package-level function: of an imported package (pkg is its
// import path), or of the file's own package (pkg is empty).
type call struct{ pkg, name string }

// goFile is a parsed Go file and the calls it makes.
type goFile struct {
	path  string
	pkg   string // directory and package name, so a test package is its own package
	calls []call
	decls map[string][]call // the calls each function declared in the file makes
}

// importNames maps each name the file refers to an import by to the import's path.
func importNames(f *ast.File) map[string]string {
	names := map[string]string{}
	for _, spec := range f.Imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		names[name] = p
	}
	return names
}

// callsIn returns the package-level calls made inside node.
func callsIn(node ast.Node, imports map[string]string) []call {
	var out []call
	ast.Inspect(node, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := c.Fun.(type) {
		case *ast.Ident:
			out = append(out, call{"", fun.Name})
		case *ast.SelectorExpr:
			if x, ok := fun.X.(*ast.Ident); ok && imports[x.Name] != "" {
				out = append(out, call{imports[x.Name], fun.Sel.Name})
			}
		}
		return true
	})
	return out
}

// parseGoFile reads the Go file at p.
func parseGoFile(p string) (goFile, []byte, error) {
	src, err := os.ReadFile(p)
	if err != nil {
		return goFile{}, nil, err
	}
	f, err := parser.ParseFile(token.NewFileSet(), p, src, 0)
	if err != nil {
		return goFile{}, nil, err
	}
	imports := importNames(f)
	g := goFile{path: p, pkg: filepath.Dir(p) + " " + f.Name.Name, calls: callsIn(f, imports), decls: map[string][]call{}}
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Body != nil {
			g.decls[fn.Name.Name] = callsIn(fn.Body, imports)
		}
	}
	return g, src, nil
}

var checkCall = call{vectorioPath, "Check"}

// checkers returns, per package, the functions whose bodies call vectorio.Check.
func checkers(files []goFile) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, g := range files {
		for name, calls := range g.decls {
			if slices.Contains(calls, checkCall) {
				if out[g.pkg] == nil {
					out[g.pkg] = map[string]bool{}
				}
				out[g.pkg][name] = true
			}
		}
	}
	return out
}

// isEmitter reports whether g writes a corpus: it is named gen_*_test.go, or it calls
// vectorio.Check or a function of its own package that does.
func isEmitter(g goFile, pkgCheckers map[string]bool) bool {
	base := filepath.Base(g.path)
	if strings.HasPrefix(base, "gen_") && strings.HasSuffix(base, "_test.go") {
		return true
	}
	return slices.ContainsFunc(g.calls, func(c call) bool {
		return c == checkCall || (c.pkg == "" && pkgCheckers[c.name])
	})
}

// forbiddenCalls returns the calls in g an emitter may not make, as "path.Func".
func forbiddenCalls(g goFile) []string {
	var out []string
	for _, c := range g.calls {
		names, listed := forbidden[c.pkg]
		if listed && (names == nil || slices.Contains(names, c.name)) {
			out = append(out, c.pkg+"."+c.name)
		}
	}
	return out
}

// ownPackage is this package's directory. Its tests exercise Check against temporary
// files, and the guard names the retired switch, so the scan leaves it out.
const ownPackage = "sdk/go/internal/vectorio/"

// skipDir returns filepath.SkipDir for a directory below root that holds no source
// to scan (installed packages, or a hidden directory such as .git), and nil otherwise.
func skipDir(root, p string, d fs.DirEntry) error {
	if p != root && (d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".")) {
		return filepath.SkipDir
	}
	return nil
}

// goFiles parses every Go file under root, outside this package, and reports each
// file that names the retired switch.
func goFiles(root string) ([]goFile, []string, error) {
	var files []goFile
	var problems []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return skipDir(root, p, d)
		}
		if !strings.HasSuffix(p, ".go") || strings.Contains(filepath.ToSlash(p), ownPackage) {
			return nil
		}
		g, src, err := parseGoFile(p)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), retiredSwitch) {
			problems = append(problems, p+": names "+retiredSwitch+"; regenerate with scripts/vectors.sh")
		}
		files = append(files, g)
		return nil
	})
	return files, problems, err
}

// scan returns what is wrong with the Go files under root.
func scan(root string) ([]string, error) {
	files, problems, err := goFiles(root)
	if err != nil {
		return nil, err
	}
	byPkg := checkers(files)
	for _, g := range files {
		if !isEmitter(g, byPkg[g.pkg]) {
			continue
		}
		for _, c := range forbiddenCalls(g) {
			problems = append(problems, g.path+": an emitter calls "+c)
		}
	}
	return problems, nil
}

// TestNoEmitterReadsTheEnvironmentOrWritesACorpus holds every Go file in the
// repository to the rule that an emitter only compares.
func TestNoEmitterReadsTheEnvironmentOrWritesACorpus(t *testing.T) {
	problems, err := scan(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) > 0 {
		t.Fatalf("emitters that do more than compare:\n  %s", strings.Join(problems, "\n  "))
	}
}
