package core_test

// Structural guard for the sdk/go L2 low-tier packages after the core/connect
// split. Two invariants are pinned here:
//
//  1. L1 COMPOSITION — the L2 client sign face, the offer Verifier, and the server
//     verify seam compose the sdk/go/helpers L1 primitives (SignRequest,
//     VerifyOffer, VerifyMultisigRequestResolved) rather than re-hand-rolling RFC
//     9421 sign/verify. If a future edit reintroduces the disease — a bespoke
//     sign/verify in L2 — a required marker disappears and the guard fails.
//
//  2. TRANSPORT NEUTRALITY — no non-test .go file of a package core is built from
//     (core itself, the L1 helpers it builds on, the internal packages they call
//     and the generated wire types) may import connectrpc.com/*. That is the Core
//     Invariant of the split: a grpc-go / plain net/http / any-transport consumer
//     of core compiles ZERO Connect. Connect lives ONLY in the bindings
//     sdk/go/connect (client) and sdk/go/connectserver (server). The scan follows
//     imports through other packages (internal/importclosure), so a Connect import
//     core would reach only through another package fails here too.
//
// SCOPE — deliberately the sdk/go L2/L1 packages ONLY. A tree-wide ban on
// hand-rolled sign/verify would false-fire on the app's internal/httpsig +
// internal/forahttpsig, which MUST still exist until their deletion in the
// downstream adoption ticket. The tree-wide guard belongs to that ticket; here the
// guard is correctly scoped to the new canonical L2 substance.
//
// The behavioral guards (client sign→verify round-trip, fail-closed
// {verified,rejected}, replay rejection, the compile-guard in
// doc_compileguard_test.go) remain the primary safety net; this file adds the
// source-level composition + neutrality guards the sweep atom asks for.

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FORA-Protocol/protocol/sdk/go/internal/importclosure"
)

// evalSite is the pure guard predicate: it returns one message per violation (a
// required L1-composition marker absent, or a forbidden reinvention present) in
// src. Extracted so the meta-tests exercise the guard logic against synthetic
// source without touching the real files.
func evalSite(src, file string, required, forbidden []string) []string {
	var violations []string
	for _, req := range required {
		if !strings.Contains(src, req) {
			violations = append(violations,
				fmt.Sprintf("%s is missing the L1-composition marker %q; the L2 face must compose sdk/go/helpers, not reinvent it", file, req))
		}
	}
	for _, bad := range forbidden {
		if strings.Contains(src, bad) {
			violations = append(violations,
				fmt.Sprintf("%s contains the reinvention marker %q; route it through sdk/go/helpers instead", file, bad))
		}
	}
	return violations
}

func readSource(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// TestLibraryAdoptionGuard_ClientSignComposesL1 pins that the client sign face
// signs via helpers.SignRequest (the L1 primitive) rather than a bespoke RFC
// 9421 signer.
func TestLibraryAdoptionGuard_ClientSignComposesL1(t *testing.T) {
	for _, v := range evalSite(readSource(t, "transport.go"), "transport.go",
		[]string{"helpers.SignRequest"}, nil) {
		t.Error(v)
	}
}

// TestLibraryAdoptionGuard_OfferVerifyComposesL1 pins that the unified offer
// Verifier verifies via helpers.VerifyOffer rather than a bespoke check.
func TestLibraryAdoptionGuard_OfferVerifyComposesL1(t *testing.T) {
	for _, v := range evalSite(readSource(t, "verifier.go"), "verifier.go",
		[]string{"helpers.VerifyOffer"}, nil) {
		t.Error(v)
	}
}

// TestLibraryAdoptionGuard_ServerVerifyComposesL1 pins that the server verify
// seam runs the L1 request verifier rather than a bespoke RFC 9421 verify.
func TestLibraryAdoptionGuard_ServerVerifyComposesL1(t *testing.T) {
	for _, v := range evalSite(readSource(t, "../connectserver/verify.go"), "connectserver/verify.go",
		[]string{"helpers.VerifyMultisigRequestResolved"}, nil) {
		t.Error(v)
	}
}

// --- Meta-tests for the L1-composition guard: prove it CATCHES a reintroduction
// (positive) and PASSES clean composed source (negative). Substring-based, so no
// regex-slip case exists. ---

func TestLibraryAdoptionGuard_Meta_CatchesReinvention(t *testing.T) {
	// L1 marker dropped AND a bespoke ed25519 sign reintroduced → two violations.
	bad := "package core\nfunc sign() { _ = ed25519.Sign(priv, base) }\n"
	got := evalSite(bad, "synthetic.go",
		[]string{"helpers.SignRequest"}, []string{"ed25519.Sign("})
	if len(got) != 2 {
		t.Fatalf("guard must flag BOTH the missing L1 marker and the reinvention; got %d: %v", len(got), got)
	}
}

func TestLibraryAdoptionGuard_Meta_PassesCleanSource(t *testing.T) {
	good := "package core\nfunc sign() { _ = helpers.SignRequest(ctx, req, body, s, o) }\n"
	if got := evalSite(good, "synthetic.go",
		[]string{"helpers.SignRequest"}, []string{"ed25519.Sign("}); len(got) != 0 {
		t.Fatalf("guard must PASS clean composed source; got: %v", got)
	}
}

// ---------------------------------------------------------------------------
// Transport-neutrality guard: no connectrpc.com import in any package core is built from.
// ---------------------------------------------------------------------------

const connectrpcModulePrefix = "connectrpc.com"

// importsConnectrpc parses src as Go source and reports whether ANY of its import
// specs has a path under connectrpc.com. It returns the offending import path (for a
// precise failure message) and true when the forbidden dependency is present.
// Parsing (rather than substring scanning) is what makes a "connectrpc.com" mention
// in a COMMENT a non-match — only a real import spec triggers the guard.
func importsConnectrpc(t *testing.T, filename, src string) (string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	for _, spec := range f.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		if path == connectrpcModulePrefix || strings.HasPrefix(path, connectrpcModulePrefix+"/") {
			return path, true
		}
	}
	return "", false
}

// TestCoreConnectrpcFree pins that no non-test .go file of a package core is built
// from imports connectrpc.com/* — the transport-neutral L2 substance, and everything
// under it, imposes no Connect dependency. The L1 helpers are among those packages, so
// this pins their neutrality from the guard that owns the core/connect boundary too;
// the helpers package also guards itself (connectrpc_free_test.go).
func TestCoreConnectrpcFree(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	module, err := importclosure.ModulePath(root)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := importclosure.Walk(root, module, module+"/sdk/go/core")
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range []string{"sdk/go/core", "sdk/go/helpers"} {
		if _, ok := closure[module+"/"+pkg]; !ok {
			t.Fatalf("the closure of sdk/go/core no longer reaches %s, so the guard would not scan it", pkg)
		}
	}
	scanned := 0
	for _, dir := range closure {
		files, err := importclosure.SourceFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			scanned++
			name, _ := filepath.Rel(root, file)
			if path, bad := importsConnectrpc(t, name, readSource(t, file)); bad {
				t.Errorf(
					"%s imports %q; core and every package it is built from must be transport-neutral (zero Connect) so a non-Connect consumer compiles no connectrpc — the Connect binding lives ONLY in sdk/go/connect",
					name, path)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("scanned 0 non-test .go files for sdk/go/core; the guard is not looking at the right packages")
	}
	if _, statErr := os.Stat("verifier.go"); statErr != nil {
		t.Fatalf("expected sdk/go/core/verifier.go to exist as the guard's anchor: %v", statErr)
	}
}

// --- Meta-tests for the neutrality predicate: prove it CATCHES a real connectrpc
// import (positive) and does NOT fire on a comment-only mention or a clean file
// (negative). Parser-based, so the doc-comment false-positive class a raw substring
// scan would hit cannot occur. ---

func TestConnectrpcFree_Meta_CatchesRealImport(t *testing.T) {
	src := "package core\n\nimport (\n\t\"errors\"\n\n\t\"connectrpc.com/connect\"\n)\n\nvar _ = errors.New\nvar _ = connect.CodeUnauthenticated\n"
	path, bad := importsConnectrpc(t, "synthetic.go", src)
	if !bad {
		t.Fatal("guard must flag a real connectrpc.com/connect import")
	}
	if path != "connectrpc.com/connect" {
		t.Fatalf("guard must report the offending import path; got %q", path)
	}
}

func TestConnectrpcFree_Meta_IgnoresCommentMention(t *testing.T) {
	src := "package core\n\n// This wraps connectrpc.com/validate under the hood, but imports nothing from it.\nimport \"sync\"\n\nvar _ sync.Mutex\n"
	if _, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatal("guard must NOT fire on a comment-only connectrpc.com mention")
	}
}

func TestConnectrpcFree_Meta_PassesCleanSource(t *testing.T) {
	src := "package core\n\nimport (\n\t\"errors\"\n\n\tforav1 \"github.com/FORA-Protocol/protocol/gen/go/fora/v1\"\n)\n\nvar _ = errors.New\nvar _ *forav1.ErrorDetail\n"
	if path, bad := importsConnectrpc(t, "synthetic.go", src); bad {
		t.Fatalf("guard must PASS a connect-free file; flagged %q", path)
	}
}
