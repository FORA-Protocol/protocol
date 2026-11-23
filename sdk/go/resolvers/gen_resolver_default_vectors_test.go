package resolvers

// Resolver default-transport golden-vector emitter.
//
// The four SSRF corpora next door pin what the guard refuses. This one pins which
// resolver faces get the guard at all when the caller injects no transport: the rule
// that a fixed, operator-chosen address takes the plain client and a host another
// party named takes the guarded one (the WellKnownOptions.HTTP comment). Each row
// names a face, a target and the outcome the face's DEFAULT transport produces, and
// the outcome is not written by hand: the emitter drives the Go face against a real
// listener and records what happened, and fails if that differs from the intended
// outcome in the table below.
//
// Python and TypeScript replay every row through their public resolver API with the
// same harness: one loopback listener that counts connections, and IP-literal hosts for
// the targets that have no listener. Nothing in any SDK is replaced; the transport
// under test is always the face's own default.
//
// The rows are the ones that tell a guarded default from a plain one without a test
// switch in the SDK. Two kinds are left out for that reason. A public address is
// reached by both defaults, so a row for it proves nothing about which one a face
// took. A redirect into a reserved address needs a first hop the guard lets through,
// and the only local listener is on loopback, which the guard refuses. So no row shows
// a guarded face reaching anything; each refusal row is its contract. The plain key
// resolver gets no private or link-local row either: a plain transport would dial the
// real address, so the row would wait on the network instead of observing anything.
// Its loopback and plain-http rows show that its default is the plain client.
//
// Verification no-op by default (asserts the committed file matches a fresh emit);
// (re)writes under FORA_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

// The outcomes a row can record. A refusal is classified by which check refused, so a
// face refused for the wrong reason (a host check, a decode) does not pass as guarded.
const (
	outcomeReached        = "reached"         // a connection reached the target listener
	outcomeRefusedAddress = "refused_address" // the dial-time address guard, before any connection
	outcomeRefusedScheme  = "refused_scheme"  // the https-only scheme guard, before any connection
)

// The targets, and how every replay realises them. The IP literals carry a port so
// they are bare domains the requirements reader accepts; no listener is behind them.
const (
	targetLoopback         = "loopback"   // the listener on 127.0.0.1, ALLOW_INSECURE set
	targetPrivate          = "private"    // 10.0.0.5:9, ALLOW_INSECURE set
	targetLinkLocal        = "link_local" // 169.254.169.254:9 (cloud metadata), ALLOW_INSECURE set
	targetPlainHTTP        = "plain_http" // the listener on 127.0.0.1, ALLOW_INSECURE unset
	privateLiteral         = "10.0.0.5:9"
	linkLocalLiteral       = "169.254.169.254:9"
	defaultsManifestFormat = `{"ver":"1.0","role":"ROLE_EXCHANGE","endpoint":"http://%s/fora.v1.ExchangeService","keys":[]}`
)

// The faces, by the name every replay maps to its own public constructor or reader.
//
// The offer-directory fetch (NewWBADirectoryFetcher) is not one of them. Its default is
// guarded in all three languages, but Python and TypeScript contain every failure as
// "no directory" by that seam's contract, where Go returns the error, so the refusal a
// row records cannot be read through two of the three public surfaces. It stays in each
// language's transport-defaults guard, which asserts only that no connection is made.
//
// The WBA key resolver is not one either. It reads its directory over https from the
// Signature-Agent origin and has no scheme to set, so the plaintext listener here
// cannot serve it. Its guarded default is pinned by wbakeyresolver_ssrf_internal_test.go
// and its two port mirrors.
const (
	faceKeyResolver      = "wellknown_key_resolver"
	faceEndpointResolver = "wellknown_endpoint_resolver"
	faceRequirements     = "registration_requirements_reader"
	faceManifestReader   = "manifest_reader"
	faceDirectoryReader  = "wba_directory_reader"
	faceRevocationReader = "revocation_list_reader"
	faceLicenseReader    = "license_document_reader"
)

// defaultsLicenseDigest is a well-formed uri_digest, so the License passes its strict
// check and the read reaches the transport. No served body matches it, which no row
// observes: the outcome is decided before the digest is compared.
const defaultsLicenseDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// resolverDefaultVector is one row. AllowInsecure is the ALLOW_INSECURE value the row
// runs under, every other SSRF flag being cleared; it is true wherever the row is
// about the address guard, so the scheme guard is not what refuses the plaintext
// listener.
type resolverDefaultVector struct {
	Name          string `json:"name"`
	Face          string `json:"face"`
	Target        string `json:"target"`
	AllowInsecure bool   `json:"allow_insecure"`
	Outcome       string `json:"outcome"`
}

// defaultsListener is the loopback origin. It counts accepted connections, which is
// the observable that separates a refusal before the dial from everything else.
type defaultsListener struct {
	srv   *httptest.Server
	conns atomic.Int64
}

func startDefaultsListener(t *testing.T) *defaultsListener {
	t.Helper()
	l := &defaultsListener{}
	l.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, defaultsManifestFormat, r.Host)
	}))
	l.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			l.conns.Add(1)
		}
	}
	l.srv.Start()
	t.Cleanup(l.srv.Close)
	return l
}

// exerciseFace runs one face's default construction against host, the way a caller
// that injects nothing would.
func exerciseFace(ctx context.Context, face, host string) error {
	switch face {
	case faceKeyResolver:
		_, err := NewWellKnownKeyResolver("http://"+host+"/.well-known/fora.json", WellKnownOptions{}).
			Resolve(ctx, "ex.v1")
		return err
	case faceEndpointResolver:
		_, err := NewWellKnownEndpointResolver(WellKnownOptions{Scheme: "http"}).ResolveEndpoint(ctx, host)
		return err
	case faceRequirements:
		_, err := NewWellKnownRequirementsReader(WellKnownOptions{Scheme: "http"}).
			ResolveRegistrationRequirements(ctx, host)
		return err
	case faceManifestReader:
		_, err := ReadManifest(ctx, host, ReadOptions{Scheme: "http"})
		return err
	case faceDirectoryReader:
		_, err := ReadWBADirectory(ctx, host, ReadOptions{Scheme: "http"})
		return err
	case faceRevocationReader:
		_, err := ReadRevocationList(ctx, "http://"+host+"/revocation", ReadOptions{})
		return err
	case faceLicenseReader:
		license := &forav1.License{
			Uri: proto.String("http://" + host + "/license"), UriDigest: proto.String(defaultsLicenseDigest),
		}
		_, err := ReadLicenseDocument(ctx, license, ReadOptions{})
		return err
	}
	return fmt.Errorf("unknown face %q", face)
}

// classifyRefusal names which check refused, from the error a face returned.
func classifyRefusal(err error) string {
	switch {
	case err == nil:
		return "no error"
	case strings.Contains(err.Error(), "disallowed scheme") && strings.Contains(err.Error(), "SSRF guard"):
		return outcomeRefusedScheme
	case strings.Contains(err.Error(), "refusing to dial") && strings.Contains(err.Error(), "SSRF guard"):
		return outcomeRefusedAddress
	}
	return "other: " + err.Error()
}

// runDefaultsRow drives one row and returns the outcome the Go face produced.
func runDefaultsRow(t *testing.T, face, target string, allowInsecure bool) string {
	t.Helper()
	for _, name := range []string{"SKIP_SSRF", "ALLOW_INSECURE", "HTTP_PROXY", "HTTPS_PROXY"} {
		t.Setenv(name, "")
	}
	if allowInsecure {
		t.Setenv("ALLOW_INSECURE", "1")
	}
	ctx := context.Background()
	switch target {
	case targetPrivate:
		return classifyRefusal(exerciseFace(ctx, face, privateLiteral))
	case targetLinkLocal:
		return classifyRefusal(exerciseFace(ctx, face, linkLocalLiteral))
	}
	l := startDefaultsListener(t)
	err := exerciseFace(ctx, face, strings.TrimPrefix(l.srv.URL, "http://"))
	if l.conns.Load() > 0 {
		return outcomeReached
	}
	return classifyRefusal(err)
}

// buildResolverDefaultVectors drives every row and checks it against the intent.
func buildResolverDefaultVectors(t *testing.T) []resolverDefaultVector {
	t.Helper()
	// Every guarded face gets every target. The plain key resolver gets only the
	// targets a plain transport can reach without the network.
	guarded := []struct {
		target        string
		allowInsecure bool
		want          string
	}{
		{targetLoopback, true, outcomeRefusedAddress},
		{targetPrivate, true, outcomeRefusedAddress},
		{targetLinkLocal, true, outcomeRefusedAddress},
		{targetPlainHTTP, false, outcomeRefusedScheme},
	}
	type row struct {
		face, target  string
		allowInsecure bool
		want          string
	}
	rows := []row{
		{faceKeyResolver, targetLoopback, true, outcomeReached},
		{faceKeyResolver, targetPlainHTTP, false, outcomeReached},
	}
	for _, face := range []string{
		faceEndpointResolver, faceRequirements,
		faceManifestReader, faceDirectoryReader, faceRevocationReader, faceLicenseReader,
	} {
		for _, g := range guarded {
			rows = append(rows, row{face, g.target, g.allowInsecure, g.want})
		}
	}
	out := make([]resolverDefaultVector, 0, len(rows))
	for _, r := range rows {
		name := r.face + "/" + r.target
		var got string
		t.Run(name, func(t *testing.T) { got = runDefaultsRow(t, r.face, r.target, r.allowInsecure) })
		if got != r.want {
			t.Fatalf("resolver default vector %s: the Go oracle's default transport gave %q, intended %q",
				name, got, r.want)
		}
		out = append(out, resolverDefaultVector{
			Name: name, Face: r.face, Target: r.target, AllowInsecure: r.allowInsecure, Outcome: got,
		})
	}
	return out
}

// TestGenerateResolverDefaultVectors emits the resolver default-transport corpus.
// Verification no-op by default, (re)writes under FORA_UPDATE_VECTORS=1.
func TestGenerateResolverDefaultVectors(t *testing.T) {
	doc := map[string]any{"resolver_defaults": buildResolverDefaultVectors(t)}
	path := filepath.Join("testdata", "resolver-default-vectors.json")
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(path, doc); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	stale, err := vectorio.Stale(path, doc)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", path)
	}
}
