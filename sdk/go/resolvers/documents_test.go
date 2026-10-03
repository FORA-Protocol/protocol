package resolvers_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/resolvers"
)

// The document readers, driven against a real in-process origin. Each reader
// dials through the SDK's guarded client by default, so these tests relax the
// guards the way a sandbox does (SKIP_SSRF, ALLOW_INSECURE) rather than injecting a
// plain client: the path under test is the default one. The verdicts on the bytes
// themselves are pinned across the three languages by the document-check and
// license-digest corpora; this file proves the readers reach those checks over
// HTTP and that every failure leaves as its sentinel.

const licenseText = "Licensed for retrieval-augmented answers, attribution required.\n"

type served struct {
	body        string
	contentType string // "" sends no Content-Type
	status      int
}

// documentOrigin serves each path's document verbatim, under the label given.
func documentOrigin(t *testing.T, docs map[string]served) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc, ok := docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if doc.contentType != "" {
			w.Header().Set("Content-Type", doc.contentType)
		} else {
			w.Header()["Content-Type"] = nil // suppress net/http's sniffed default
		}
		if doc.status != 0 {
			w.WriteHeader(doc.status)
		}
		_, _ = w.Write([]byte(doc.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sandbox(t *testing.T) {
	t.Helper()
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")
}

var plain = resolvers.ReadOptions{Scheme: "http"}

func TestReadManifestReturnsTheManifestAndItsMediaType(t *testing.T) {
	sandbox(t)
	srv := documentOrigin(t, map[string]served{
		helpers.WellKnownPath: {body: `{"ver":"1.0","role":"ROLE_EXCHANGE","endpoint":"https://exchange.example/rpc"}`, contentType: "application/json; charset=utf-8"},
	})
	doc, err := resolvers.ReadManifest(context.Background(), hostOf(t, srv), plain)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if doc.Message.GetRole() != forav1.Role_ROLE_EXCHANGE || doc.Message.GetEndpoint() != "https://exchange.example/rpc" {
		t.Errorf("manifest = %v", doc.Message)
	}
	if doc.MediaType != resolvers.ManifestMediaType || doc.URL != srv.URL+helpers.WellKnownPath {
		t.Errorf("media type %q, url %q", doc.MediaType, doc.URL)
	}
}

func TestReadManifestRefusals(t *testing.T) {
	cases := []struct {
		name string
		doc  served
		want error
	}{
		{"unknown member", served{body: `{"ver":"1.0","role":"ROLE_EXCHANGE","endpoints":[]}`, contentType: "application/json"}, helpers.ErrStrictViolation},
		{"cross-field rule", served{body: `{"ver":"1.0","role":"ROLE_EXCHANGE","terms_digest":"sha256:` + strings.Repeat("0", 64) + `"}`, contentType: "application/json"}, helpers.ErrStrictViolation},
		{"wrong media type", served{body: `{"ver":"1.0","role":"ROLE_EXCHANGE"}`, contentType: "text/plain"}, resolvers.ErrMediaTypeRefused},
		{"no media type", served{body: `{"ver":"1.0","role":"ROLE_EXCHANGE"}`}, resolvers.ErrMediaTypeRefused},
		{"version read first", served{body: `{"ver":"2.0","role":"ROLE_EXCHANGE","endpoints":[]}`, contentType: "application/json"}, resolvers.ErrManifestVersionRefused},
		{"not published", served{status: http.StatusNotFound, contentType: "application/json"}, resolvers.ErrDirectoryUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sandbox(t)
			srv := documentOrigin(t, map[string]served{helpers.WellKnownPath: tc.doc})
			doc, err := resolvers.ReadManifest(context.Background(), hostOf(t, srv), plain)
			if !errors.Is(err, tc.want) || doc != nil {
				t.Fatalf("ReadManifest = %v, %v; want %v", doc, err, tc.want)
			}
		})
	}
}

func TestReadManifestRefusesAValueThatIsNotABareHost(t *testing.T) {
	sandbox(t)
	_, err := resolvers.ReadManifest(context.Background(), "exchange.example/elsewhere", plain)
	if !errors.Is(err, helpers.ErrInvalidHost) {
		t.Fatalf("err = %v, want ErrInvalidHost", err)
	}
}

func TestReadManifestDialsThroughTheGuards(t *testing.T) {
	srv := documentOrigin(t, map[string]served{
		helpers.WellKnownPath: {body: `{"ver":"1.0","role":"ROLE_EXCHANGE"}`, contentType: "application/json"},
	})
	t.Run("address guard", func(t *testing.T) {
		t.Setenv("SKIP_SSRF", "")
		t.Setenv("ALLOW_INSECURE", "true")
		if _, err := resolvers.ReadManifest(context.Background(), hostOf(t, srv), plain); !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			t.Fatalf("loopback read through the guarded client: %v", err)
		}
	})
	t.Run("scheme guard", func(t *testing.T) {
		t.Setenv("SKIP_SSRF", "true")
		t.Setenv("ALLOW_INSECURE", "")
		if _, err := resolvers.ReadManifest(context.Background(), hostOf(t, srv), plain); !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
			t.Fatalf("plaintext read without ALLOW_INSECURE: %v", err)
		}
	})
}

const readerJWK = `{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","not_before":"2026-05-01T00:00:00Z","not_after":"2027-05-01T00:00:00Z"}`

func TestReadWBADirectoryByDomainAndByURL(t *testing.T) {
	sandbox(t)
	srv := documentOrigin(t, map[string]served{
		resolvers.WBADirectoryPath: {body: `{"keys":[` + readerJWK + `]}`, contentType: resolvers.WBADirectoryMediaType},
	})
	for _, ref := range []string{hostOf(t, srv), srv.URL + resolvers.WBADirectoryPath} {
		doc, err := resolvers.ReadWBADirectory(context.Background(), ref, plain)
		if err != nil {
			t.Fatalf("ReadWBADirectory(%q): %v", ref, err)
		}
		if len(doc.Message.GetKeys()) != 1 || doc.MediaType != resolvers.WBADirectoryMediaType {
			t.Errorf("ReadWBADirectory(%q) = %v, %q", ref, doc.Message, doc.MediaType)
		}
	}
}

func TestReadWBADirectoryRefusals(t *testing.T) {
	cases := []struct {
		name string
		doc  served
		want error
	}{
		{"plain json", served{body: `{"keys":[` + readerJWK + `]}`, contentType: "application/json"}, resolvers.ErrMediaTypeRefused},
		{"key carrying a kid", served{body: `{"keys":[{"kid":"k1","kty":"OKP"}]}`, contentType: resolvers.WBADirectoryMediaType}, helpers.ErrStrictViolation},
		{"lower camel member", served{body: `{"revocationUrl":"https://agent.example/r.json"}`, contentType: resolvers.WBADirectoryMediaType}, helpers.ErrStrictViolation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sandbox(t)
			srv := documentOrigin(t, map[string]served{resolvers.WBADirectoryPath: tc.doc})
			if _, err := resolvers.ReadWBADirectory(context.Background(), hostOf(t, srv), plain); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestReadRevocationList(t *testing.T) {
	sandbox(t)
	srv := documentOrigin(t, map[string]served{
		"/ok":      {body: `{"as_of":"2026-05-01T12:00:00Z","revoked":["tp"]}`, contentType: "text/plain"},
		"/unknown": {body: `{"as_of":"2026-05-01T12:00:00Z","revoked":[],"next":"x"}`, contentType: "application/json"},
		"/as-of":   {body: `{"as_of":"yesterday","revoked":[]}`, contentType: "application/json"},
	})
	doc, err := resolvers.ReadRevocationList(context.Background(), srv.URL+"/ok", plain)
	if err != nil {
		t.Fatalf("ReadRevocationList: %v", err)
	}
	if got := doc.Message.GetRevoked(); len(got) != 1 || got[0] != "tp" || doc.MediaType != "text/plain" {
		t.Errorf("list = %v, media type %q", doc.Message, doc.MediaType)
	}
	for _, path := range []string{"/unknown", "/as-of"} {
		if _, err := resolvers.ReadRevocationList(context.Background(), srv.URL+path, plain); !errors.Is(err, helpers.ErrStrictViolation) {
			t.Errorf("%s: err = %v, want ErrStrictViolation", path, err)
		}
	}
}

func TestReadLicenseDocument(t *testing.T) {
	sandbox(t)
	sum := sha256.Sum256([]byte(licenseText))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	srv := documentOrigin(t, map[string]served{
		"/terms":   {body: licenseText, contentType: "text/plain; charset=utf-8"},
		"/amended": {body: licenseText + "Amended after the offer was signed.\n", contentType: "text/plain"},
	})
	uri, digestPtr := srv.URL+"/terms", digest
	doc, err := resolvers.ReadLicenseDocument(context.Background(), &forav1.License{Uri: &uri, UriDigest: &digestPtr}, plain)
	if err != nil {
		t.Fatalf("ReadLicenseDocument: %v", err)
	}
	if string(doc.Body) != licenseText || doc.Digest != digest || doc.MediaType != "text/plain" {
		t.Errorf("document = %q, %q, %q", doc.Body, doc.Digest, doc.MediaType)
	}

	amended := srv.URL + "/amended"
	if _, err := resolvers.ReadLicenseDocument(context.Background(), &forav1.License{Uri: &amended, UriDigest: &digestPtr}, plain); !errors.Is(err, resolvers.ErrDigestMismatch) {
		t.Errorf("amended document: err = %v, want ErrDigestMismatch", err)
	}
	if _, err := resolvers.ReadLicenseDocument(context.Background(), &forav1.License{Uri: &uri}, plain); !errors.Is(err, helpers.ErrStrictViolation) {
		t.Errorf("uri without digest: err = %v, want ErrStrictViolation", err)
	}
	tdl := "tdl:ai-terms/2026"
	if _, err := resolvers.ReadLicenseDocument(context.Background(), &forav1.License{Uri: &tdl, UriDigest: &digestPtr}, plain); !errors.Is(err, resolvers.ErrDirectoryUnavailable) {
		t.Errorf("non-URL uri: err = %v, want ErrDirectoryUnavailable", err)
	}
	id := "CC-BY-4.0"
	if _, err := resolvers.ReadLicenseDocument(context.Background(), &forav1.License{Id: &id}, plain); err == nil {
		t.Error("a license with no uri was read")
	}
}
