package resolvers

// Resolver default-transport golden-vector emitter.
//
// The four SSRF corpora next door pin what the guard refuses. This one pins which
// resolver faces get the guard at all when the caller injects no transport: the rule
// that a fixed, operator-chosen address takes the plain client and a host another
// party named takes the guarded one (the WellKnownOptions.HTTP comment). Every face
// that dials such a host is a row here. Each row names a face, a target, the scheme
// and host it dials, and the outcome the face's DEFAULT transport produces, and the
// outcome is not written by hand: the emitter drives the Go face against a real
// listener and records what happened, and fails if that differs from the intended
// outcome in the table below.
//
// Python and TypeScript replay every row through their public resolver API with the
// same harness: one loopback listener that counts connections, and the row's own host
// for the targets that have no listener. They classify a refusal by the same rule as
// classifyRefusal. Nothing in any SDK is replaced; the transport under test is the
// face's own default, except in a control row, which injects a plain client.
//
// The rows are the ones that tell a guarded default from a plain one without a test
// switch in the SDK. Two kinds are left out for that reason. A public address is
// reached by both defaults, so a row for it proves nothing about which one a face
// took. A redirect into a reserved address needs a first hop the guard lets through,
// and the only local listener is on loopback, which the guard refuses. So no row shows
// a guarded face reaching anything; each refusal row is its contract. The plain key
// resolver gets no private or link-local row either: a plain transport would dial the
// real address, so the row would wait on the network instead of observing anything.
// Its loopback, plain-http and loopback-https rows show that its default is the plain
// client, and that the listener sees a connection on each listener target.
//
// Redirect re-vetting is a property of the guarded transport, not of a face, and is
// pinned at that level. Python's test_guarded_client_refuses_redirect_to_internal_address
// (test_resolvers_wba_ssrf.py) and TypeScript's "re-vets every redirect hop" test
// (resolvers-http-wiring.test.ts, on the ssrfGuard connector guardedFetchFromEnv also
// builds) follow a 302 into 169.254.169.254 and see it refused. Go pins redirect scheme
// re-vetting and the depth cap (TestGuardedClientRefusesRedirectScheme,
// TestGuardedClientRedirectDepthCap). No Go test follows a redirect into a reserved
// address; Go's address guard runs in the dialer, at every dial, so a second hop is
// vetted by the same check as the first.
//
// CHANGING A ROW OBLIGES A CHECK OF THE License.uri SSRF GUARDS in
// proto/fora/v1/fora.proto and Licensing Terms
// (website/src/content/docs/protocol/licensing-terms.mdx), which say what a consumer
// must apply before it fetches a URL another party named.
//
// Verification no-op by default (asserts the committed file matches a fresh emit);
// (re)writes under FORA_UPDATE_VECTORS=1. TEST INFRASTRUCTURE.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// The outcomes a row can record. A refusal is classified by which check refused, so a
// face refused for the wrong reason (a host check, a decode) does not pass as guarded.
const (
	outcomeReached        = "reached"         // a connection reached the target listener
	outcomeRefusedAddress = "refused_address" // the dial-time address guard, before any connection
	outcomeRefusedScheme  = "refused_scheme"  // the https-only scheme guard, before any connection
	// No connection was made, and the face's public seam reports nothing more. It is the
	// outcome of a face whose ports contain every failure (see faceContainsFailures); Go,
	// which returns the error, records it only when the address guard is what refused.
	outcomeNotReached = "not_reached"
)

// The targets. A row carries the scheme and the host it dials, so no replay keeps its
// own copy of either; an empty host is the loopback listener, whose port exists only at
// run time. The IP literals carry a port so they are bare domains the requirements
// reader accepts; no listener is behind them.
const (
	targetLoopback      = "loopback"       // the listener over http, ALLOW_INSECURE set
	targetPrivate       = "private"        // privateLiteral over http, ALLOW_INSECURE set
	targetLinkLocal     = "link_local"     // linkLocalLiteral over http, ALLOW_INSECURE set
	targetPlainHTTP     = "plain_http"     // the listener over http, ALLOW_INSECURE unset
	targetLoopbackHTTPS = "loopback_https" // the listener over https, ALLOW_INSECURE unset
	privateLiteral      = "10.0.0.5:9"
	linkLocalLiteral    = "169.254.169.254:9" // cloud metadata
)

// The transport a row runs the face with. Every row but a control runs the face's own
// default; a control row injects a plain client to show the same input does reach the
// listener, so a check before the dial cannot pass as the guard.
const (
	transportDefault = "default"
	transportPlain   = "plain"
)

// The faces, by the name every replay maps to its own public constructor or reader.
const (
	faceKeyResolver      = "wellknown_key_resolver"
	faceEndpointResolver = "wellknown_endpoint_resolver"
	faceRequirements     = "registration_requirements_reader"
	faceManifestReader   = "manifest_reader"
	faceDirectoryReader  = "wba_directory_reader"
	faceRevocationReader = "revocation_list_reader"
	faceLicenseReader    = "license_document_reader"
	faceWBAKeyResolver   = "wba_key_resolver"
	faceOfferDirectory   = "offer_directory_fetch"
)

// faceContainsFailures names the faces whose Python and TypeScript seams answer "no
// directory" for every failure where Go returns the error. A refusal cannot be read
// through those two surfaces, so their rows record outcomeNotReached: the ports observe
// that no connection was made, and Go additionally requires the address guard to be the
// reason.
var faceContainsFailures = map[string]bool{faceOfferDirectory: true}

// defaultsLicenseDigest is a well-formed uri_digest, so the License passes its strict
// check and the read reaches the transport. No served body matches it, which no row
// observes: the outcome is decided before the digest is compared. It is emitted into
// the corpus, so the ports read it rather than copy it.
const defaultsLicenseDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// resolverDefaultVector is one row. AllowInsecure is the ALLOW_INSECURE value the row
// runs under, every other SSRF flag being cleared; it is true wherever an http row is
// about the address guard, so the scheme guard is not what refuses the plaintext
// listener. Host is empty for the loopback listener.
type resolverDefaultVector struct {
	Name          string `json:"name"`
	Face          string `json:"face"`
	Target        string `json:"target"`
	Scheme        string `json:"scheme"`
	Host          string `json:"host"`
	AllowInsecure bool   `json:"allow_insecure"`
	Transport     string `json:"transport"`
	Outcome       string `json:"outcome"`
}

// targetSpec is how a target is realised: its scheme, its host (empty for the listener)
// and the ALLOW_INSECURE value it runs under.
type targetSpec struct {
	scheme, host  string
	allowInsecure bool
}

var targets = map[string]targetSpec{
	targetLoopback:      {"http", "", true},
	targetPrivate:       {"http", privateLiteral, true},
	targetLinkLocal:     {"http", linkLocalLiteral, true},
	targetPlainHTTP:     {"http", "", false},
	targetLoopbackHTTPS: {"https", "", false},
}

// defaultsListener is the loopback origin. It counts accepted connections, which is
// the observable that separates a refusal before the dial from everything else. It
// serves nothing: no row's outcome depends on a body.
type defaultsListener struct {
	srv   *httptest.Server
	conns atomic.Int64
}

func startDefaultsListener(t *testing.T) *defaultsListener {
	t.Helper()
	l := &defaultsListener{}
	l.srv = httptest.NewUnstartedServer(http.NotFoundHandler())
	l.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			l.conns.Add(1)
		}
	}
	l.srv.Start()
	t.Cleanup(l.srv.Close)
	return l
}

// exerciseFace runs one face against scheme://host, the way a caller would: with its
// default transport when client is nil, else with client injected.
func exerciseFace(ctx context.Context, face, scheme, host string, client *http.Client) error {
	base := scheme + "://" + host
	switch face {
	case faceKeyResolver:
		_, err := NewWellKnownKeyResolver(base+"/.well-known/fora.json", WellKnownOptions{HTTP: client}).
			Resolve(ctx, "ex.v1")
		return err
	case faceEndpointResolver:
		_, err := NewWellKnownEndpointResolver(WellKnownOptions{Scheme: scheme, HTTP: client}).
			ResolveEndpoint(ctx, host)
		return err
	case faceRequirements:
		_, err := NewWellKnownRequirementsReader(WellKnownOptions{Scheme: scheme, HTTP: client}).
			ResolveRegistrationRequirements(ctx, host)
		return err
	case faceManifestReader:
		_, err := ReadManifest(ctx, host, ReadOptions{Scheme: scheme, Client: client})
		return err
	case faceDirectoryReader:
		_, err := ReadWBADirectory(ctx, host, ReadOptions{Scheme: scheme, Client: client})
		return err
	case faceRevocationReader:
		_, err := ReadRevocationList(ctx, base+"/revocation", ReadOptions{Client: client})
		return err
	case faceLicenseReader:
		license := &forav1.License{
			Uri: proto.String(base + "/license"), UriDigest: proto.String(defaultsLicenseDigest),
		}
		_, err := ReadLicenseDocument(ctx, license, ReadOptions{Client: client})
		return err
	case faceWBAKeyResolver:
		_, err := NewWBAKeyResolver(WBAKeyResolverOptions{HTTP: client}).
			Resolve(helpers.WithSignatureAgent(ctx, base), "ex.v1")
		return err
	case faceOfferDirectory:
		_, err := NewWBADirectoryFetcher(client, scheme, "")(ctx, host)
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
func runDefaultsRow(t *testing.T, v resolverDefaultVector) string {
	t.Helper()
	// No proxy variable is cleared: no row can be proxied. The guarded transports drop
	// the proxy, and the plain rows dial 127.0.0.1, which ProxyFromEnvironment never
	// proxies (it also reads the variables only once per process).
	for _, name := range []string{"SKIP_SSRF", "ALLOW_INSECURE"} {
		t.Setenv(name, "")
	}
	if v.AllowInsecure {
		t.Setenv("ALLOW_INSECURE", "1")
	}
	var client *http.Client
	if v.Transport == transportPlain {
		client = &http.Client{}
	}
	ctx := context.Background()
	if v.Host != "" {
		return classifyRefusal(exerciseFace(ctx, v.Face, v.Scheme, v.Host, client))
	}
	l := startDefaultsListener(t)
	err := exerciseFace(ctx, v.Face, v.Scheme, strings.TrimPrefix(l.srv.URL, "http://"), client)
	got := classifyRefusal(err)
	switch {
	case l.conns.Load() > 0:
		return outcomeReached
	case faceContainsFailures[v.Face] && got == outcomeRefusedAddress:
		return outcomeNotReached
	}
	return got
}

// buildResolverDefaultVectors drives every row and checks it against the intent.
func buildResolverDefaultVectors(t *testing.T) []resolverDefaultVector {
	t.Helper()
	type row struct {
		face, target, transport, want string
	}
	guardedFaces := []string{
		faceEndpointResolver, faceRequirements,
		faceManifestReader, faceDirectoryReader, faceRevocationReader, faceLicenseReader,
	}
	// Three key-resolver rows, five per guarded face, three Web Bot Auth rows.
	rows := make([]row, 0, 3+5*len(guardedFaces)+3)
	// The plain key resolver gets only the targets a plain transport can reach without
	// the network.
	rows = append(rows,
		row{faceKeyResolver, targetLoopback, transportDefault, outcomeReached},
		row{faceKeyResolver, targetPlainHTTP, transportDefault, outcomeReached},
		row{faceKeyResolver, targetLoopbackHTTPS, transportDefault, outcomeReached},
	)
	// Every guarded face that takes a scheme gets every target.
	for _, face := range guardedFaces {
		rows = append(rows,
			row{face, targetLoopback, transportDefault, outcomeRefusedAddress},
			row{face, targetPrivate, transportDefault, outcomeRefusedAddress},
			row{face, targetLinkLocal, transportDefault, outcomeRefusedAddress},
			row{face, targetPlainHTTP, transportDefault, outcomeRefusedScheme},
			row{face, targetLoopbackHTTPS, transportDefault, outcomeRefusedAddress},
		)
	}
	// The two Web Bot Auth directory faces read over https, so they get the https
	// target only. The offer-directory fetch contains its failures in the ports, so its
	// refusal row is outcomeNotReached, and its control row injects a plain client to
	// show the same input reaches the listener.
	rows = append(rows,
		row{faceWBAKeyResolver, targetLoopbackHTTPS, transportDefault, outcomeRefusedAddress},
		row{faceOfferDirectory, targetLoopbackHTTPS, transportDefault, outcomeNotReached},
		row{faceOfferDirectory, targetLoopbackHTTPS, transportPlain, outcomeReached},
	)
	out := make([]resolverDefaultVector, 0, len(rows))
	for _, r := range rows {
		spec := targets[r.target]
		name := r.face + "/" + r.target
		if r.transport != transportDefault {
			name += "/injected_" + r.transport
		}
		v := resolverDefaultVector{
			Name: name, Face: r.face, Target: r.target, Scheme: spec.scheme, Host: spec.host,
			AllowInsecure: spec.allowInsecure, Transport: r.transport,
		}
		t.Run(name, func(t *testing.T) { v.Outcome = runDefaultsRow(t, v) })
		if v.Outcome != r.want {
			t.Fatalf("resolver default vector %s: the Go oracle gave %q, intended %q", name, v.Outcome, r.want)
		}
		out = append(out, v)
	}
	return out
}

// TestGenerateResolverDefaultVectors emits the resolver default-transport corpus.
func TestGenerateResolverDefaultVectors(t *testing.T) {
	doc := map[string]any{
		"license_digest":    defaultsLicenseDigest,
		"resolver_defaults": buildResolverDefaultVectors(t),
	}
	emitOrCheck(t, filepath.Join("testdata", "resolver-default-vectors.json"), doc)
}
