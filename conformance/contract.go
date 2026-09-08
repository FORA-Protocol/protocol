// Package conformance — contract.go is the SINGLE source of "which proto packages make
// up the wire contract". Every descriptor-walking guard and every generator iterates this
// list, so adding the next contract package is one entry here and nothing else.
//
// This is the only non-test file in the package, and that is deliberate: the corpus and
// required/unique manifest generators are `package main` under conformance/*/ and cannot
// import a _test.go file. Before this existed, each of them re-hardcoded the same two
// walk() calls, so a new package was covered only where someone remembered to add it —
// the exact opt-in failure mode descriptor_invariants_test.go's header warns about.
//
// Note wire_naming_test.go deliberately does NOT walk descriptors: it reads the committed
// corpus JSON, which already covers every package walked here.
package conformance

import (
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"

	foraadminv1 "github.com/FORA-Protocol/protocol/gen/go/fora/admin/v1"
	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
)

// ContractFile is one proto package of the wire contract: its descriptor, its package
// name (the corpus and doc markers carry BARE message names, resolved against these in
// order), and the website reference page that must document every symbol it defines.
type ContractFile struct {
	Package string
	File    protoreflect.FileDescriptor
	// RefPage is the doc-coverage reference page, relative to the conformance/ directory
	// (where `go test ./conformance` runs).
	RefPage string
}

// Contract is the wire contract, in bare-name resolution order.
var Contract = []ContractFile{
	{
		Package: "fora.v1",
		File:    forav1.File_fora_v1_fora_proto,
		RefPage: "../website/src/content/docs/reference/proto-fora.mdx",
	},
	{
		Package: "fora.admin.v1",
		File:    foraadminv1.File_fora_admin_v1_admin_proto,
		RefPage: "../website/src/content/docs/reference/proto-admin.mdx",
	},
}

// ContractPackages returns the contract package names in resolution order.
func ContractPackages() []string {
	out := make([]string, 0, len(Contract))
	for _, c := range Contract {
		out = append(out, c.Package)
	}
	return out
}

// ContractFiles returns the contract file descriptors in resolution order.
func ContractFiles() []protoreflect.FileDescriptor {
	out := make([]protoreflect.FileDescriptor, 0, len(Contract))
	for _, c := range Contract {
		out = append(out, c.File)
	}
	return out
}

// EachMessage visits every message of every contract file, including nested messages,
// and skipping synthetic map-entry messages (they carry no rules, no docs, and no
// corpus representation).
func EachMessage(fn func(protoreflect.MessageDescriptor)) {
	var walk func(protoreflect.MessageDescriptors)
	walk = func(ms protoreflect.MessageDescriptors) {
		for i := 0; i < ms.Len(); i++ {
			md := ms.Get(i)
			if !md.IsMapEntry() {
				fn(md)
			}
			walk(md.Messages())
		}
	}
	for _, f := range Contract {
		walk(f.File.Messages())
	}
}

// AssertUniqueBareNames reports an error when two contract packages define a message
// with the same bare name. The corpus keys cases by bare short name (Case.Message ==
// the generated class/schema name), the merged JSON-Schema $defs are keyed the same way,
// and the {/* fora-validate: X */} doc markers resolve the same way — a cross-package
// duplicate would silently collide in all three. Returned as an error, not a fatal, so
// both a `package main` generator (which exits) and a test (which fails) can use it.
func AssertUniqueBareNames() error {
	seen := map[string]protoreflect.FullName{}
	var err error
	EachMessage(func(md protoreflect.MessageDescriptor) {
		if prev, ok := seen[string(md.Name())]; ok && prev != md.FullName() && err == nil {
			err = fmt.Errorf("duplicate bare message name %q (%s vs %s) — the corpus/parity bare-name scheme cannot represent it",
				md.Name(), prev, md.FullName())
			return
		}
		seen[string(md.Name())] = md.FullName()
	})
	return err
}
