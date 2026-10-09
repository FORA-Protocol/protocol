package resolvers_test

// Golden-vector emitter for the cross-language revocation-set-membership parity
// corpus. sdk/ts `revoked()` and sdk/python `revoked()` assert their verdict
// matches this sdk/go oracle for EVERY labelled case.
//
// The vector carries two served WBA directories, each with its keys, its own
// revocation snapshot (as_of + revoked thumbprints) and a prime thumbprint
// resolved to load that snapshot, and the labelled (thumbprint, directory) cases
// with their expected `revoked()` verdict. One directory lists no key and its list
// names the other's key, so the corpus pins that a list answers only for its own
// directory. The verdicts are produced by
// RUNNING the real Go resolver against a real httptest origin — Go is the oracle,
// never a hand-authored table.
//
// DETERMINISM: every key is derived from a FIXED seed and every instant is a
// FIXED constant, so re-running reproduces byte-identical output. Default
// `go test` asserts the committed file matches a fresh emit; FORA_UPDATE_VECTORS=1
// rewrites it (same drift-gate shape as gen_vectors_test.go).

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// revMembershipJWK is one served directory key (snake_case, protojson shape).
type revMembershipJWK struct {
	X         string `json:"x"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// revMembershipDirectory is one served key directory with its own revocation list.
// Directory names a directory symbolically ("A", "B"): the parity ports serve each
// on a random loopback origin, so the concrete host cannot be stored. The ports
// serve the directories and resolve each PrimeThumbprint against it IN LIST ORDER,
// which loads that directory's list; PrimeResolves is whether that resolve
// succeeds (a keyless directory resolves nothing, yet its list still loads).
type revMembershipDirectory struct {
	Directory       string             `json:"directory"`
	DirectoryKeys   []revMembershipJWK `json:"directory_keys"`
	Revoked         []string           `json:"revoked"`
	PrimeThumbprint string             `json:"prime_thumbprint"`
	PrimeResolves   bool               `json:"prime_resolves"`
}

// revMembershipCase is one labelled (thumbprint, directory) question and the
// oracle's revoked() verdict. Directory is a symbolic name from Directories, or ""
// for no directory; Form is how the port spells it: "origin" (https://host:port) or
// "bare" (host:port).
type revMembershipCase struct {
	Label           string `json:"label"`
	Thumbprint      string `json:"thumbprint"`
	Directory       string `json:"directory"`
	Form            string `json:"form"`
	ExpectedRevoked bool   `json:"expected_revoked"`
}

// revMembershipVector is the whole served-doc + cases corpus.
type revMembershipVector struct {
	Note        string                   `json:"note"`
	AsOf        string                   `json:"as_of"`
	Directories []revMembershipDirectory `json:"directories"`
	Cases       []revMembershipCase      `json:"cases"`
}

// revMembershipAnchor is the fixed instant the emitter clocks the resolver at —
// well inside the emitted validity windows.
var revMembershipAnchor = time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

// buildRevocationMembershipVector constructs the served docs, runs the real Go
// resolver as the oracle, and returns the vector with oracle-produced verdicts.
//
// Directory B lists no key and its revocation list names directory A's key: no
// party's list revokes another party's key, so A's key must stay unrevoked when
// asked about A, and must still resolve against A after B's list has loaded.
func buildRevocationMembershipVector(t *testing.T) revMembershipVector {
	t.Helper()
	windowStart := revMembershipAnchor.Add(-time.Hour)
	windowEnd := revMembershipAnchor.Add(1000 * time.Hour)

	presentPriv, presentJWK := newSigningKey("present.v1", windowStart, windowEnd)
	tpPresent := mustThumbprint(t, presentPriv.Public().(ed25519.PublicKey))
	absentPriv, _ := newSigningKey("absent-revoked.v1", windowStart, windowEnd)
	tpAbsentRevoked := mustThumbprint(t, absentPriv.Public().(ed25519.PublicKey))
	unknownPriv, _ := newSigningKey("unknown.v1", windowStart, windowEnd)
	tpUnknown := mustThumbprint(t, unknownPriv.Public().(ed25519.PublicKey))

	originA := newWBAOrigin(nil)
	defer originA.close()
	originA.setWBA(marshalWBAWithRevocation(presentJWK, originA.revocationURL()))
	originA.setRevocation(marshalRevocation(revMembershipAnchor, tpAbsentRevoked))

	originB := newWBAOrigin(nil)
	defer originB.close()
	originB.setWBA(marshalKeylessWBAWithRevocation(originB.revocationURL()))
	originB.setRevocation(marshalRevocation(revMembershipAnchor, tpPresent))

	r := resolvers.NewWBAKeyResolver(resolvers.WBAKeyResolverOptions{
		HTTP: originA.Client(),
		Now:  func() time.Time { return revMembershipAnchor },
	})
	// B first, so A's key is resolved against A after B's list naming it has loaded.
	if _, err := r.Resolve(helpers.WithSignatureAgent(context.Background(), originB.url), tpUnknown); !errors.Is(err, resolvers.ErrUnknownKey) {
		t.Fatalf("prime B: want ErrUnknownKey from a keyless directory, got %v", err)
	}
	if _, err := r.Resolve(helpers.WithSignatureAgent(context.Background(), originA.url), tpPresent); err != nil {
		t.Fatalf("prime A: A's key must resolve although B's list names it: %v", err)
	}

	dirs := map[string]string{"A": originA.url, "B": originB.url, "": ""}
	ask := func(label, tp, dir, form string) revMembershipCase {
		ref := dirs[dir]
		if form == "bare" {
			ref = strings.TrimPrefix(ref, "https://")
		}
		return revMembershipCase{Label: label, Thumbprint: tp, Directory: dir, Form: form, ExpectedRevoked: r.Revoked(tp, ref)}
	}
	cases := []revMembershipCase{
		ask("directory-absent-but-revoked", tpAbsentRevoked, "A", "origin"),
		ask("directory-present-not-revoked", tpPresent, "A", "origin"),
		ask("unknown", tpUnknown, "A", "origin"),
		ask("bare-host-form", tpAbsentRevoked, "A", "bare"),
		ask("keyless-directory-own-list", tpPresent, "B", "origin"),
		ask("another-directory-revocation-not-applied", tpAbsentRevoked, "B", "origin"),
		ask("no-directory", tpAbsentRevoked, "", "origin"),
	}
	// Sanity: the oracle must produce the semantics the labels claim.
	assertRevMembershipSemantics(t, cases)

	return revMembershipVector{
		Note: "revoked(thumbprint, directory) reports membership in that directory's own revocation list, independent of WBA directory membership; no directory's list answers for another's keys; verdicts produced by the sdk/go oracle",
		AsOf: revMembershipAnchor.UTC().Format(time.RFC3339),
		Directories: []revMembershipDirectory{
			{Directory: "B", DirectoryKeys: []revMembershipJWK{}, Revoked: []string{tpPresent}, PrimeThumbprint: tpUnknown, PrimeResolves: false},
			{Directory: "A", DirectoryKeys: []revMembershipJWK{{X: presentJWK.GetX(), NotBefore: presentJWK.GetNotBefore(), NotAfter: presentJWK.GetNotAfter()}}, Revoked: []string{tpAbsentRevoked}, PrimeThumbprint: tpPresent, PrimeResolves: true},
		},
		Cases: cases,
	}
}

// marshalKeylessWBAWithRevocation serializes a WBAFile that lists no key and
// names revURL as its revocation list.
func marshalKeylessWBAWithRevocation(revURL string) []byte {
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(&forav1.WBAFile{RevocationUrl: &revURL})
	return raw
}

func assertRevMembershipSemantics(t *testing.T, cases []revMembershipCase) {
	t.Helper()
	want := map[string]bool{
		"directory-absent-but-revoked":             true,
		"directory-present-not-revoked":            false,
		"unknown":                                  false,
		"bare-host-form":                           true,
		"keyless-directory-own-list":               true,
		"another-directory-revocation-not-applied": false,
		"no-directory":                             false,
	}
	for _, c := range cases {
		exp, ok := want[c.Label]
		if !ok {
			t.Fatalf("unexpected case label %q", c.Label)
		}
		if c.ExpectedRevoked != exp {
			t.Fatalf("oracle verdict for %q = %v, want %v", c.Label, c.ExpectedRevoked, exp)
		}
	}
}

// TestGenerateRevocationMembershipVector emits the revocation-membership golden
// vector. Default run asserts the committed file is byte-identical to a fresh
// emit; FORA_UPDATE_VECTORS=1 rewrites it.
func TestGenerateRevocationMembershipVector(t *testing.T) {
	t.Parallel()
	vec := buildRevocationMembershipVector(t)
	path := filepath.Join("testdata", "revocation-membership-vectors.json")

	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		writeRevMembershipVector(t, path, vec)
		return
	}
	want, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want = append(want, '\n')
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", path)
	}
}

func writeRevMembershipVector(t *testing.T, path string, vec revMembershipVector) {
	t.Helper()
	b, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // committed test vector
		t.Fatalf("write %s: %v", path, err)
	}
}
