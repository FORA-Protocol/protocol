// Package conformance — lookup_test.go checks the bare-name → message resolution that
// contract.go's FindContractMessage performs for every corpus- and doc-example-driven
// test.
//
// The corpus (Case.Message) and the {/* fora-validate: X */} doc markers carry
// BARE message names — the same names the generated Pydantic/Zod classes use —
// so resolution tries each contract package in order. Bare names are unique
// across the packages; contract.go's AssertUniqueBareNames proves it (see
// TestContractBareNamesUnique) and corpusgen re-checks it at generation time.
package conformance

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// contractPackages is the resolution order, materialized once for error messages.
var contractPackages = ContractPackages()

// walkOnce calls visit on root and on every message the walk reaches, once each: visit
// returns the messages the walk continues from.
func walkOnce(
	root protoreflect.MessageDescriptor,
	visit func(protoreflect.MessageDescriptor) []protoreflect.MessageDescriptor,
) {
	seen := map[protoreflect.FullName]bool{}
	pending := []protoreflect.MessageDescriptor{root}
	for len(pending) > 0 {
		md := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[md.FullName()] {
			continue
		}
		seen[md.FullName()] = true
		pending = append(pending, visit(md)...)
	}
}

// TestContractBareNamesUnique exercises the guard corpusgen relies on, inside the test
// binary too — so a cross-package name collision fails `go test ./...`, not only the
// next `go run ./conformance/corpusgen`.
func TestContractBareNamesUnique(t *testing.T) {
	if err := AssertUniqueBareNames(); err != nil {
		t.Fatal(err)
	}
	if len(Contract) == 0 {
		t.Fatal("no contract files — the guard would be vacuous")
	}
}
