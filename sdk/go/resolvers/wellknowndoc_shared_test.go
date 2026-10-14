package resolvers_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// One fetch decodes one manifest for three faces — keys, endpoint and registration
// requirements — so a member only one of them reads must never be able to fail the
// document for the other two.
//
// The manifest is a THIRD PARTY's, and terms_digest and account_registration are
// optional members of it. An Exchange that publishes one of them with the wrong
// type is off-spec, but the answer to that has to be "this face sees nothing"
// rather than "nobody can read this document": a decode failure is classified as a
// transport failure, which is RETRYABLE, so failing the document would turn every
// usage report and every key resolution against that Exchange into an endless
// retry over a member neither of them reads. Usage reports are how money moves.
//
// The wrong-type answer is also what both ports already give, so the three SDKs
// agree on a value rather than on an error.

// literalManifest serves body verbatim, which is what lets these tests put a
// member on the wire that no typed encoder here would produce.
func literalManifest(body string, hits *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits != nil {
			*hits++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
}

// offSpecMembers are optional members served with a type the contract does not
// admit, plus the two JSON nulls. Null is listed because it is the case a type
// check alone misses: encoding/json decodes null into a string without error and
// leaves the zero value, so a reader that only consulted the error would report a
// present, empty digest where the ports report none.
var offSpecMembers = []struct {
	name   string
	member string
}{
	{"digest is a number", `"terms_digest":123`},
	{"digest is a bool", `"terms_digest":false`},
	{"digest is an object", `"terms_digest":{"sha256":"x"}`},
	{"digest is null", `"terms_digest":null`},
	{"registration is a string", `"account_registration":"https://exchange.test/signup"`},
	{"registration is an array", `"account_registration":[1,2]`},
	{"registration is null", `"account_registration":null`},
}

func TestWellKnownDoc_anOffSpecOptionalMemberDoesNotFailTheEndpointFace(t *testing.T) {
	for _, tc := range offSpecMembers {
		t.Run(tc.name, func(t *testing.T) {
			// The advertised endpoint must anchor to the host that served the
			// manifest, so the body is built per request from the Host header
			// rather than from a value fixed before the listener has a port.
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"ver":%q,"role":"ROLE_EXCHANGE","endpoint":"https://%s",%s}`,
					helpers.WellKnownManifestVersion, req.Host, tc.member)
			}))
			defer srv.Close()
			host := hostOf(t, srv)

			r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
				TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
			})
			got, err := r.ResolveEndpoint(context.Background(), host)
			if err != nil {
				t.Fatalf("resolve endpoint: %v", err)
			}
			if want := "https://" + host; got != want {
				t.Errorf("endpoint = %q, want %q", got, want)
			}
		})
	}
}

func TestWellKnownDoc_anOffSpecOptionalMemberDoesNotFailTheKeyFace(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)

	for _, tc := range offSpecMembers {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(literalManifest(fmt.Sprintf(
				`{"ver":%q,"role":"ROLE_EXCHANGE","keys":[{"kid":"ex.v1","kty":"OKP","crv":"Ed25519","x":%q}],%s}`,
				helpers.WellKnownManifestVersion, x, tc.member), nil))
			defer srv.Close()

			r := resolvers.NewWellKnownKeyResolver(srv.URL, resolvers.WellKnownOptions{TTL: time.Hour})
			got, err := r.Resolve(context.Background(), "ex.v1")
			if err != nil {
				t.Fatalf("resolve key: %v", err)
			}
			if !got.Equal(pub) {
				t.Error("resolved key does not match the served one")
			}
		})
	}
}

func TestWellKnownDoc_anOffSpecOptionalMemberReadsAsAbsent(t *testing.T) {
	for _, tc := range offSpecMembers {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(literalManifest(fmt.Sprintf(
				`{"ver":%q,"role":"ROLE_EXCHANGE","endpoint":"https://exchange.test",%s}`,
				helpers.WellKnownManifestVersion, tc.member), nil))
			defer srv.Close()

			got, err := loopbackReader(nil).ResolveRegistrationRequirements(
				context.Background(), hostOf(t, srv))
			if err != nil {
				t.Fatalf("resolve requirements: %v", err)
			}
			if got.TermsDigest != nil {
				t.Errorf("terms digest = %q, want absent — a member of the wrong type is not a value",
					*got.TermsDigest)
			}
			if got.Schema != nil {
				t.Error("schema is set; an unreadable account_registration block publishes none")
			}
			if got.Verdict != helpers.SchemaNotPublished {
				t.Errorf("verdict = %v, want %v", got.Verdict, helpers.SchemaNotPublished)
			}
		})
	}
}

// A conformant manifest still reads exactly as before. The tolerance above is for
// members this SDK cannot use, and it must not become tolerance for members it can:
// a good digest is still returned, and a good schema still compiles.
func TestWellKnownDoc_toleranceDoesNotSwallowAConformantMember(t *testing.T) {
	digest := "sha256:" + repeat64("cd")
	srv := httptest.NewServer(literalManifest(fmt.Sprintf(
		`{"ver":%q,"role":"ROLE_EXCHANGE","endpoint":"https://exchange.test","terms_digest":%q,`+
			`"account_registration":{"data_schema":%s}}`,
		helpers.WellKnownManifestVersion, digest, acceptedSchema), nil))
	defer srv.Close()

	got, err := loopbackReader(nil).ResolveRegistrationRequirements(
		context.Background(), hostOf(t, srv))
	if err != nil {
		t.Fatalf("resolve requirements: %v", err)
	}
	if got.TermsDigest == nil || *got.TermsDigest != digest {
		t.Errorf("terms digest = %v, want %q", got.TermsDigest, digest)
	}
	if got.Verdict != helpers.SchemaAccepted || got.Schema == nil {
		t.Errorf("verdict = %v, schema nil = %t; want an accepted, usable schema",
			got.Verdict, got.Schema == nil)
	}
}

// The three faces share one fetch, so a manifest the host does not publish reads
// the same way on each: an unavailable document, like any failed read, and also
// ErrDocumentNotFound, so a caller can tell an absent manifest from an unreachable
// host. It is never an unknown key, and never a refused redirect.
func TestWellKnownDoc_aMissingManifestIsNotFoundOnEveryFace(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	ctx, host := context.Background(), hostOf(t, srv)
	for name, read := range map[string]func() error{
		"key": func() error {
			r := resolvers.NewWellKnownKeyResolver(srv.URL+helpers.WellKnownPath, resolvers.WellKnownOptions{TTL: time.Hour})
			_, err := r.Resolve(ctx, "ex.v1")
			return err
		},
		"endpoint": func() error {
			r := resolvers.NewWellKnownEndpointResolver(resolvers.WellKnownOptions{
				TTL: time.Hour, Scheme: "http", HTTP: http.DefaultClient,
			})
			_, err := r.ResolveEndpoint(ctx, host)
			return err
		},
		"requirements": func() error {
			_, err := loopbackReader(nil).ResolveRegistrationRequirements(ctx, host)
			return err
		},
	} {
		before := hits.Load()
		err := read()
		if hits.Load() == before {
			t.Fatalf("%s: the host was never asked", name)
		}
		if !errors.Is(err, resolvers.ErrDocumentNotFound) || !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			t.Errorf("%s: err = %v, want ErrDocumentNotFound wrapped with ErrDirectoryUnavailable", name, err)
		}
		if errors.Is(err, resolvers.ErrUnknownKey) || errors.Is(err, resolvers.ErrRedirectRefused) {
			t.Errorf("%s: err = %v also reads as an unknown key or a refused redirect", name, err)
		}
	}
}
