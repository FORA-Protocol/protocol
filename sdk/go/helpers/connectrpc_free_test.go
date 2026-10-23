package helpers_test

// Structural neutrality guard for the sdk/go L1 helpers package (the
// core/connect split with the folded-in AsConnectError decouple). The Core
// Invariant of that split is transport neutrality: a grpc-go / plain
// net/http / any-transport consumer that only wants the neutral L1 mechanics
// (ErrorDetail builders, sign/verify, key-resolution, money, signed URLs) must
// compile ZERO Connect. The Connect-coupled pieces (AsConnectError, the
// connect.Error unwrap in ErrorDetailFrom) live in the connect binding.
//
// This is a STRUCTURAL guard, not a behavior test: the byte-level behavior net
// lives in the L2 suites (sdk/go/core/*, sdk/go/connect/*). This guard pins the
// package-boundary invariant those suites cannot see.
//
// SCOPE — every package of this module that helpers is built from, helpers
// included (helpersClosure, in io_leaf_guard_test.go). A scan of this directory
// alone could not see a Connect import pulled in through another package, such
// as an internal package helpers calls; the closure follows imports through
// them. The generated wire packages under gen/ are scanned too: the check reads
// import specs, so their comments cannot trip it, and a generated Connect stub
// entering the closure would.
//
// Import detection uses go/parser (real import specs), NOT a raw substring
// match, so a doc comment that merely mentions "connectrpc.com" (e.g.
// validate.go's prose about connectrpc.com/validate) is correctly NOT flagged —
// only an actual import counts.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/importclosure"
)

const connectrpcModulePrefix = "connectrpc.com"

// importsConnectrpc is the pure guard predicate: it parses src as Go source and
// reports whether ANY of its import specs has a path under connectrpc.com. It
// returns the offending import path (for a precise failure message) and true
// when the forbidden dependency is present. Parsing (rather than substring
// scanning) is what makes a "connectrpc.com" mention in a COMMENT a non-match —
// only a real import spec triggers the guard. filename is used solely for the
// parser's error position reporting.
func importsConnectrpc(t *testing.T, filename, src string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, spec := range f.Imports {
		// spec.Path.Value is the quoted import path, e.g. "connectrpc.com/connect".
		path := strings.Trim(spec.Path.Value, `"`)
		if path == connectrpcModulePrefix || strings.HasPrefix(path, connectrpcModulePrefix+"/") {
			return path, true
		}
	}
	return "", false
}

func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestHelpersConnectrpcFree pins the neutrality invariant: no non-test .go file of
// a package helpers is built from may import connectrpc.com/*.
func TestHelpersConnectrpcFree(t *testing.T) {
	root, _, closure := helpersClosure(t)
	scanned := 0
	for _, dir := range closure {
		files, err := importclosure.SourceFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			scanned++
			name, _ := filepath.Rel(root, file)
			if path, bad := importsConnectrpc(t, name, readSourceFile(t, file)); bad {
				t.Errorf(
					"%s imports %q; every package the L1 helpers are built from must be transport-neutral (zero Connect) so a non-Connect consumer compiles no connectrpc — move the Connect-coupled code (AsConnectError / connect.Error unwrap) into the connect binding",
					name, path)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned 0 non-test .go files for sdk/go/helpers; the guard is not looking at the right packages")
	}
	// Cross-check the scan is anchored on the real package, not an empty cwd.
	if _, statErr := os.Stat(filepath.Join(".", "errordetail.go")); statErr != nil {
		t.Fatalf("expected sdk/go/helpers/errordetail.go to exist as the guard's anchor: %v", statErr)
	}
}

// --- Meta-tests: prove the predicate CATCHES a real connectrpc import
// (positive) and does NOT fire on a comment-only mention or a clean file
// (negative). Parser-based, so the doc-comment false-positive class that a raw
// substring scan would hit cannot occur. ---

func TestHelpersConnectrpcFree_Meta_CatchesRealImport(t *testing.T) {
	src := "package helpers\n\nimport (\n\t\"errors\"\n\n\t\"connectrpc.com/connect\"\n)\n\nvar _ = errors.New\nvar _ = connect.CodeUnauthenticated\n"
	path, bad := importsConnectrpc(t, "synthetic.go", src)
	if !bad {
		t.Fatal("guard must flag a real connectrpc.com/connect import")
	}
	if path != "connectrpc.com/connect" {
		t.Fatalf("guard must report the offending import path; got %q", path)
	}
}

func TestHelpersConnectrpcFree_Meta_IgnoresCommentMention(t *testing.T) {
	// A file that only MENTIONS connectrpc.com in a comment (as validate.go does)
	// must NOT be flagged — only real imports count.
	src := "package helpers\n\n// This wraps connectrpc.com/validate under the hood, but imports nothing from it.\nimport \"sync\"\n\nvar _ sync.Mutex\n"
	if _, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatal("guard must NOT fire on a comment-only connectrpc.com mention")
	}
}

func TestHelpersConnectrpcFree_Meta_PassesCleanSource(t *testing.T) {
	src := "package helpers\n\nimport (\n\t\"errors\"\n\n\tforav1 \"github.com/FORA-Protocol/protocol/gen/go/fora/v1\"\n)\n\nvar _ = errors.New\nvar _ *forav1.ErrorDetail\n"
	if path, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatalf("guard must PASS a connect-free file; flagged %q", path)
	}
}
