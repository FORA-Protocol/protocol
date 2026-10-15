package resolvers

// Golden-vector emitter for the document-check and license-digest corpora.
//
// The document readers (ReadManifest, ReadWBADirectory, ReadRevocationList and
// ReadLicenseDocument, and their Python and TypeScript peers) each end in one pure
// decision over the bytes a party served and the label it served them under. That
// decision is where three languages could disagree about the same document: one
// reads a media-type parameter as part of the type, one accepts the lowerCamel
// spelling protojson also reads, one forgets that `ver` is read before anything
// else. These corpora make the three answer the same documents with the same
// verdict.
//
// document-check-vectors.json: {label, document, content_type, body, verdict}.
// document is "manifest", "wba_directory" or "revocation_list"; content_type ""
// means the header is absent; verdict is one of
//
//	ok           the document is accepted
//	media_type   served under a media type other than the one the protocol names
//	undecodable  the body is not JSON (a transport failure, as an unreadable answer is)
//	version      the manifest's ver is refused, before any other member is read
//	strict       the strict contract refuses the document
//
// license-digest-vectors.json: {label, body, uri_digest, verdict, digest}. verdict
// is "ok" or "mismatch", and digest is what an accepted read reports.
//
// The verdicts are emitted by RUNNING acceptDocument and verifyLicenseDigest — Go
// is the oracle, never a hand-authored table. Default `go test` asserts the
// committed files match a fresh emit; FORA_UPDATE_VECTORS=1 rewrites them.

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
	"github.com/FORA-Protocol/protocol/sdk/go/internal/vectorio"
)

type documentCheckVector struct {
	Label       string `json:"label"`
	Document    string `json:"document"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
	Verdict     string `json:"verdict"`
}

type documentCheckCorpus struct {
	Note    string                `json:"note"`
	Vectors []documentCheckVector `json:"vectors"`
}

type licenseDigestVector struct {
	Label     string `json:"label"`
	Body      string `json:"body"`
	URIDigest string `json:"uri_digest"`
	Verdict   string `json:"verdict"`
	Digest    string `json:"digest"`
}

type licenseDigestCorpus struct {
	Note    string                `json:"note"`
	Vectors []licenseDigestVector `json:"vectors"`
}

const (
	manifestOK = `{"ver":"1.0","role":"ROLE_EXCHANGE","domain":"exchange.example","endpoint":"https://exchange.example/rpc"}`
	jwkOK      = `{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","not_before":"2026-05-01T00:00:00Z","not_after":"2027-05-01T00:00:00Z"}`
	jwksType   = "application/jwk-set+json"
	jsonType   = "application/json"
)

// documentCheckInputs are the documents the corpus pins. Each is chosen to separate
// one decision the readers make; the comment names it where the label does not.
func documentCheckInputs() []documentCheckVector {
	return []documentCheckVector{
		{Label: "manifest-ok", Document: "manifest", ContentType: jsonType, Body: manifestOK},
		{Label: "manifest-media-type-parameter", Document: "manifest", ContentType: "application/json; charset=utf-8", Body: manifestOK},
		{Label: "manifest-media-type-case", Document: "manifest", ContentType: "Application/JSON", Body: manifestOK},
		{Label: "manifest-media-type-text", Document: "manifest", ContentType: "text/plain", Body: manifestOK},
		{Label: "manifest-media-type-absent", Document: "manifest", ContentType: "", Body: manifestOK},
		{Label: "manifest-media-type-jwk-set", Document: "manifest", ContentType: jwksType, Body: manifestOK},
		{Label: "manifest-not-json", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0",`},
		{Label: "manifest-trailing-data", Document: "manifest", ContentType: jsonType, Body: manifestOK + ` {}`},
		{Label: "manifest-null-member", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_EXCHANGE","endpoint":null}`},
		{Label: "manifest-null-inside-struct", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_EXCHANGE","ext":{"vendor":null}}`},
		{Label: "manifest-minor-version", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.7","role":"ROLE_EXCHANGE"}`},
		{Label: "manifest-version-absent", Document: "manifest", ContentType: jsonType, Body: `{"role":"ROLE_EXCHANGE"}`},
		{Label: "manifest-version-major", Document: "manifest", ContentType: jsonType, Body: `{"ver":"2.0","role":"ROLE_EXCHANGE"}`},
		{Label: "manifest-version-not-string", Document: "manifest", ContentType: jsonType, Body: `{"ver":1.0,"role":"ROLE_EXCHANGE"}`},
		// ver is read before any other member, so the unknown member is never reached.
		{Label: "manifest-version-before-strict", Document: "manifest", ContentType: jsonType, Body: `{"ver":"2.0","role":"ROLE_EXCHANGE","endpoints":[]}`},
		{Label: "manifest-not-object", Document: "manifest", ContentType: jsonType, Body: `[]`},
		{Label: "manifest-unknown-member", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_EXCHANGE","endpoints":["https://exchange.example/rpc"]}`},
		{Label: "manifest-lower-camel-member", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_EXCHANGE","termsUri":"https://exchange.example/terms"}`},
		{Label: "manifest-cross-field-rule", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_EXCHANGE","terms_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`},
		{Label: "manifest-int32-as-string", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_EXCHANGE","max_intermediary_hops":"3"}`},
		{Label: "manifest-unknown-enum-name", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_NOTARY"}`},
		{Label: "manifest-role-absent", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0"}`},
		{Label: "manifest-unknown-member-nested", Document: "manifest", ContentType: jsonType, Body: `{"ver":"1.0","role":"ROLE_PUBLISHER","exchanges":[{"domain":"exchange.example","weight":1}]}`},

		{Label: "wba-ok", Document: "wba_directory", ContentType: jwksType, Body: `{"keys":[` + jwkOK + `],"revocation_url":"https://agent.example/.well-known/fora-key-revocations.json"}`},
		{Label: "wba-empty", Document: "wba_directory", ContentType: jwksType, Body: `{}`},
		{Label: "wba-media-type-json", Document: "wba_directory", ContentType: jsonType, Body: `{"keys":[` + jwkOK + `]}`},
		{Label: "wba-media-type-wba-draft", Document: "wba_directory", ContentType: "application/http-message-signatures-directory+json", Body: `{"keys":[` + jwkOK + `]}`},
		{Label: "wba-key-with-kid", Document: "wba_directory", ContentType: jwksType, Body: `{"keys":[{"kid":"k1","kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`},
		{Label: "wba-keys-not-array", Document: "wba_directory", ContentType: jwksType, Body: `{"keys":{}}`},
		{Label: "wba-lower-camel-member", Document: "wba_directory", ContentType: jwksType, Body: `{"revocationUrl":"https://agent.example/revoked.json"}`},
		{Label: "wba-not-json", Document: "wba_directory", ContentType: jwksType, Body: `keys`},

		{Label: "revocation-ok", Document: "revocation_list", ContentType: jsonType, Body: `{"as_of":"2026-05-01T12:00:00Z","revoked":["NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"]}`},
		{Label: "revocation-any-media-type", Document: "revocation_list", ContentType: "text/plain", Body: `{"as_of":"2026-05-01T12:00:00Z","revoked":[]}`},
		{Label: "revocation-media-type-absent", Document: "revocation_list", ContentType: "", Body: `{"revoked":[]}`},
		{Label: "revocation-unknown-member", Document: "revocation_list", ContentType: jsonType, Body: `{"as_of":"2026-05-01T12:00:00Z","revoked":[],"next":"https://agent.example/revoked-2.json"}`},
		{Label: "revocation-as-of-not-rfc3339", Document: "revocation_list", ContentType: jsonType, Body: `{"as_of":"yesterday","revoked":[]}`},
		{Label: "revocation-revoked-not-strings", Document: "revocation_list", ContentType: jsonType, Body: `{"revoked":[1]}`},
		{Label: "revocation-not-json", Document: "revocation_list", ContentType: jsonType, Body: `revoked: []`},
	}
}

func documentCheckKind(name string) (docKind, proto.Message) {
	switch name {
	case "manifest":
		return manifestKind, &forav1.WellKnownManifest{}
	case "wba_directory":
		return wbaDirectoryKind, &forav1.WBAFile{}
	default:
		return revocationListKind, &forav1.KeyRevocationList{}
	}
}

// documentVerdict is the corpus's name for what acceptDocument answered.
func documentVerdict(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrMediaTypeRefused):
		return "media_type"
	case errors.Is(err, ErrDirectoryUnavailable):
		return "undecodable"
	case errors.Is(err, helpers.ErrManifestVersionRefused):
		return "version"
	case errors.Is(err, helpers.ErrStrictViolation):
		return "strict"
	default:
		return "unclassified: " + err.Error()
	}
}

func buildDocumentCheckCorpus() documentCheckCorpus {
	vectors := documentCheckInputs()
	for i := range vectors {
		v := &vectors[i]
		kind, msg := documentCheckKind(v.Document)
		f := fetchedDocument{url: "https://party.example/doc", body: []byte(v.Body), mediaType: mediaTypeEssence(v.ContentType)}
		_, err := acceptDocument(kind, f, msg)
		v.Verdict = documentVerdict(err)
	}
	return documentCheckCorpus{
		Note:    "The verdict each document reader reaches for the bytes and the Content-Type a party served, produced by the sdk/go acceptDocument oracle; py/ts replay and must match every vector",
		Vectors: vectors,
	}
}

func buildLicenseDigestCorpus() licenseDigestCorpus {
	const text = "Licensed for retrieval-augmented answers, attribution required.\n"
	s256 := sha256.Sum256([]byte(text))
	s384 := sha512.Sum384([]byte(text))
	s512 := sha512.Sum512([]byte(text))
	empty := sha256.Sum256(nil)
	vectors := []licenseDigestVector{
		{Label: "sha256", Body: text, URIDigest: "sha256:" + hex.EncodeToString(s256[:])},
		{Label: "sha384", Body: text, URIDigest: "sha384:" + hex.EncodeToString(s384[:])},
		{Label: "sha512", Body: text, URIDigest: "sha512:" + hex.EncodeToString(s512[:])},
		{Label: "empty-document", Body: "", URIDigest: "sha256:" + hex.EncodeToString(empty[:])},
		{Label: "amended-document", Body: text + "Amended after the offer was signed.\n", URIDigest: "sha256:" + hex.EncodeToString(s256[:])},
		{Label: "document-gone-empty", Body: "", URIDigest: "sha256:" + hex.EncodeToString(s256[:])},
		{Label: "method-swapped", Body: text, URIDigest: "sha512:" + hex.EncodeToString(s384[:])},
	}
	for i := range vectors {
		v := &vectors[i]
		doc, err := verifyLicenseDigest(v.URIDigest, fetchedDocument{url: "https://publisher.example/terms", body: []byte(v.Body)})
		switch {
		case err == nil:
			v.Verdict, v.Digest = "ok", doc.Digest
		case errors.Is(err, ErrDigestMismatch):
			v.Verdict = "mismatch"
		default:
			v.Verdict = "unclassified: " + err.Error()
		}
	}
	return licenseDigestCorpus{
		Note:    "Whether the bytes at License.uri match License.uri_digest, produced by the sdk/go verifyLicenseDigest oracle; py/ts replay and must match every vector",
		Vectors: vectors,
	}
}

func TestGenerateDocumentCheckVectors(t *testing.T) {
	t.Parallel()
	emitOrCheck(t, filepath.Join("testdata", "document-check-vectors.json"), buildDocumentCheckCorpus())
}

func TestGenerateLicenseDigestVectors(t *testing.T) {
	t.Parallel()
	emitOrCheck(t, filepath.Join("testdata", "license-digest-vectors.json"), buildLicenseDigestCorpus())
}

func emitOrCheck(t *testing.T, path string, corpus any) {
	t.Helper()
	if os.Getenv("FORA_UPDATE_VECTORS") == "1" {
		if err := vectorio.Write(path, corpus); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	stale, err := vectorio.Stale(path, corpus)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if stale {
		t.Fatalf("%s is stale; re-run with FORA_UPDATE_VECTORS=1 to regenerate", path)
	}
}
