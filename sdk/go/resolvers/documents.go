package resolvers

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	forav1 "github.com/FORA-Protocol/protocol/gen/go/fora/v1"
	"github.com/FORA-Protocol/protocol/sdk/go/helpers"
)

// The documents the protocol defines are served over plain HTTPS rather than
// answered over RPC: the well-known manifest (/.well-known/fora.json), the WBA key
// directory, the key revocation list a directory points to, and the license
// document a License.uri names. This file is the one place each of them is
// fetched and decoded.
//
// Two faces read them, and they share everything up to the decision of how strict
// to be. The public readers (ReadManifest, ReadWBADirectory, ReadRevocationList,
// ReadLicenseDocument) check what a party publishes: the media type, the strict
// contract of the message and, for a license document, the digest. The resolvers
// read the same documents to route and to verify, and skip the strict check: a
// reader that must accept a newer protocol version cannot refuse a field it does
// not know.
//
// A key directory is read under the Web Bot Auth profile by both faces: it is
// fetched with no redirect, must be served as
// application/http-message-signatures-directory+json, and its response must be
// signed by the keys it lists (helpers.VerifyDirectoryResponse). A key the
// response carries no valid signature by is never handed out. A revocation list
// and the manifest may follow up to five redirects.

// ManifestMediaType is the media type /.well-known/fora.json is served under.
const ManifestMediaType = "application/json"

// WBADirectoryMediaType is the media type a Web Bot Auth key directory is served
// under (WG-00 §5.5). Any other label, the JWK Set type
// application/jwk-set+json included, is refused.
const WBADirectoryMediaType = "application/http-message-signatures-directory+json"

// ErrMediaTypeRefused is returned when a document is served under a media type
// other than the one the protocol names for it. A verdict on what the party
// publishes, never worth retrying. The public readers check the manifest's and the
// key directory's label; the resolvers check the key directory's. Peer of Python
// MediaTypeRefusedError and TypeScript MediaTypeRefused.
var ErrMediaTypeRefused = errors.New("resolvers: document served under a media type the protocol does not name for it")

// ErrDigestMismatch is returned by ReadLicenseDocument when the bytes served at
// License.uri do not hash to License.uri_digest. The digest is covered by the
// offer signature, so a mismatch means the document changed after the offer was
// signed, or the server answering is not the one the offer named. Peer of Python
// DigestMismatchError and TypeScript DigestMismatch.
var ErrDigestMismatch = errors.New("resolvers: license document does not match its uri_digest")

// maxDocumentFetch bounds one document read whatever client was injected: a
// ReadOptions.Client may carry no timeout at all. The manifest resolvers' ceiling.
const maxDocumentFetch = maxManifestFetch

// Document is one document a reader fetched and accepted.
type Document[M proto.Message] struct {
	// Message is the parsed generated message.
	Message M
	// MediaType is the Content-Type essence the document was served under,
	// lowercased and without parameters. For the manifest and the WBA directory it
	// is the media type the protocol names, since anything else is refused; for a
	// revocation list, which the protocol names none for, it is whatever was
	// served, or "".
	MediaType string
	// URL is the URL that was fetched.
	URL string
	// Body is the bytes as served.
	Body []byte
}

// LicenseDocument is the document a License.uri names, verified against
// License.uri_digest.
type LicenseDocument struct {
	// Body is the bytes as served.
	Body []byte
	// Digest is the digest of Body in "method:hexdigest" form. Equal to the
	// license's uri_digest, since anything else is refused.
	Digest string
	// MediaType is the Content-Type essence the document was served under, or "".
	// The protocol names no media type for a license document, so it is not checked.
	MediaType string
	// URL is the URL that was fetched.
	URL string
}

// ReadOptions configures a document reader. The zero value reads over https
// through the SDK's guarded client.
type ReadOptions struct {
	// Client dials the document. Nil builds NewGuardedClientFromEnv: the dial-time
	// SSRF guard refuses loopback, private and metadata addresses and the scheme
	// guard refuses anything but https, relaxed only by the SKIP_SSRF and
	// ALLOW_INSECURE flags.
	Client *http.Client
	// Scheme is used when a reader builds the URL from a domain. "" means https.
	Scheme string
}

func (o ReadOptions) client() *http.Client {
	if o.Client != nil {
		return o.Client
	}
	return NewGuardedClientFromEnv()
}

func (o ReadOptions) scheme() string {
	if o.Scheme != "" {
		return o.Scheme
	}
	return "https"
}

// ReadManifest fetches and checks domain's /.well-known/fora.json.
//
// The checks run in the order the contract reads the document: the media type
// must be application/json; the body must be JSON; ver must carry a recognised
// major version before any other member is read; and the whole document must pass
// helpers.CheckStrict as a WellKnownManifest.
//
// A domain that is not a bare host (a port is allowed) wraps
// helpers.ErrInvalidHost and is refused before anything is dialled. Otherwise a
// failure wraps ErrDirectoryUnavailable (the fetch failed, or the body is not
// JSON), ErrMediaTypeRefused, ErrManifestVersionRefused, or
// helpers.ErrStrictViolation.
func ReadManifest(ctx context.Context, domain string, opts ReadOptions) (*Document[*forav1.WellKnownManifest], error) {
	if bare, err := helpers.IsBareHost(domain); err != nil || !bare {
		return nil, fmt.Errorf("resolvers: read manifest: %w: %q is not a bare host", helpers.ErrInvalidHost, domain)
	}
	f, err := fetchDocument(ctx, opts.client(), opts.scheme()+"://"+domain+helpers.WellKnownPath)
	if err != nil {
		return nil, err
	}
	return acceptDocument(manifestKind, f, &forav1.WellKnownManifest{})
}

// ReadWBADirectory fetches and checks a WBA key directory. urlOrDomain is the
// directory's full URL, or a bare host whose directory is read from
// scheme://host/.well-known/http-message-signatures-directory.
//
// The directory is fetched with no redirect: a redirect fails the fetch. The media
// type must be application/http-message-signatures-directory+json, the body must
// pass helpers.CheckStrict as a WBAFile, and the response must carry a valid
// response signature by every key it lists. Key validity windows and revocation
// are not evaluated: that is WBAKeyResolver's job, and a directory listing an
// expired key is still a well-formed directory. A failure wraps
// helpers.ErrInvalidHost, ErrDirectoryUnavailable, ErrMediaTypeRefused,
// helpers.ErrStrictViolation, or helpers.ErrDirectoryResponseUnsigned.
func ReadWBADirectory(ctx context.Context, urlOrDomain string, opts ReadOptions) (*Document[*forav1.WBAFile], error) {
	url := urlOrDomain
	if !strings.Contains(urlOrDomain, "://") {
		if bare, err := helpers.IsBareHost(urlOrDomain); err != nil || !bare {
			return nil, fmt.Errorf("resolvers: read WBA directory: %w: %q is neither a URL nor a bare host",
				helpers.ErrInvalidHost, urlOrDomain)
		}
		url = WBADirectoryURL(opts.scheme(), urlOrDomain)
	}
	f, err := fetchDocumentNoRedirect(ctx, opts.client(), url)
	if err != nil {
		return nil, err
	}
	doc, err := acceptDocument(wbaDirectoryKind, f, &forav1.WBAFile{})
	if err != nil {
		return nil, err
	}
	signed, err := signedDirectoryKeys(f, doc.Message, time.Now())
	if err != nil {
		return nil, fmt.Errorf("resolvers: %w", err)
	}
	if len(signed.GetKeys()) != len(doc.Message.GetKeys()) {
		return nil, fmt.Errorf("resolvers: %w: %d of %d listed keys signed the response at %s",
			helpers.ErrDirectoryResponseUnsigned, len(signed.GetKeys()), len(doc.Message.GetKeys()), f.url)
	}
	return doc, nil
}

// ReadRevocationList fetches and checks the key revocation list at url, a
// directory's revocation_url. The protocol names no media type for this document,
// so the label is reported and not checked. The body must pass helpers.CheckStrict
// as a KeyRevocationList. Whether url is anchored to the directory's host is the
// caller's question: WBAKeyResolver skips a list that is not. A failure wraps
// ErrDirectoryUnavailable or helpers.ErrStrictViolation.
func ReadRevocationList(ctx context.Context, url string, opts ReadOptions) (*Document[*forav1.KeyRevocationList], error) {
	f, err := fetchDocument(ctx, opts.client(), url)
	if err != nil {
		return nil, err
	}
	return acceptDocument(revocationListKind, f, &forav1.KeyRevocationList{})
}

// ReadLicenseDocument fetches the document license.uri names and verifies it
// against license.uri_digest.
//
// The license itself is checked first, with helpers.CheckStrictMessage, so a uri
// without a digest, or a digest whose method is not sha256, sha384 or sha512, is
// refused before anything is dialled. The fetched bytes are then hashed with the
// digest's method and compared with it. The protocol names no media type for a
// license document, so the label is reported and not checked. A uri with a scheme
// other than https, such as a data-labels identifier that is not a URL, is refused
// by the scheme guard and wraps ErrDirectoryUnavailable: it names a document, not
// a place to fetch one.
//
// A license with no uri is an error that wraps none of the sentinels. Otherwise a
// failure wraps helpers.ErrStrictViolation, ErrDirectoryUnavailable or
// ErrDigestMismatch.
func ReadLicenseDocument(ctx context.Context, license *forav1.License, opts ReadOptions) (*LicenseDocument, error) {
	if license.GetUri() == "" {
		return nil, errors.New("resolvers: read license document: the license carries no uri")
	}
	if err := helpers.CheckStrictMessage(license); err != nil {
		return nil, fmt.Errorf("resolvers: read license document: fora.v1.License %w", err)
	}
	f, err := fetchDocument(ctx, opts.client(), license.GetUri())
	if err != nil {
		return nil, err
	}
	return verifyLicenseDigest(license.GetUriDigest(), f)
}

// fetchWBAFile GETs base+WBADirectoryPath through client, with no redirect, and
// decodes the WBAFile leniently: an unknown member is a newer minor version, not a
// reason to stop verifying. The media type must be WBADirectoryMediaType. The file
// returned lists only the keys that signed the response (signedDirectoryKeys), so
// no caller can hand out a key the directory did not sign for. Any failure wraps
// ErrDirectoryUnavailable. It is the one read of a directory
// WBAKeyResolver.fetchDirectory and the domain-keyed offer-key fetcher
// (NewWBADirectoryFetcher) share, so the two never drift.
//
// now is the clock the response signatures' windows are judged against.
func fetchWBAFile(ctx context.Context, client *http.Client, base string, now time.Time) (*forav1.WBAFile, error) {
	f, err := fetchDocumentNoRedirect(ctx, client, base+WBADirectoryPath)
	if err != nil {
		return nil, err
	}
	if f.mediaType != WBADirectoryMediaType {
		return nil, fmt.Errorf("%w: %w: %s was served as %q", ErrDirectoryUnavailable, ErrMediaTypeRefused, f.url, f.mediaType)
	}
	var file forav1.WBAFile
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(f.body, &file); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrDirectoryUnavailable, err)
	}
	signed, err := signedDirectoryKeys(f, &file, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryUnavailable, err)
	}
	return signed, nil
}

// signedDirectoryKeys returns a copy of file listing only the keys whose response
// signature verifies, checked against the authority f was fetched from. A key that
// is not an Ed25519 key cannot sign and is dropped with the rest. The error is a
// response listing keys that cannot be checked at all: a Content-Digest that does
// not match the body, or no response signature. A directory listing no key has
// nothing to sign and is returned as it is.
func signedDirectoryKeys(f fetchedDocument, file *forav1.WBAFile, now time.Time) (*forav1.WBAFile, error) {
	if len(file.GetKeys()) == 0 {
		return file, nil // nothing listed, so nothing to have signed
	}
	authority, err := requestAuthority(f.url)
	if err != nil {
		return nil, err
	}
	pubs := make([]ed25519.PublicKey, 0, len(file.GetKeys()))
	for _, k := range file.GetKeys() {
		if pub, perr := wbaPublicKey(k); perr == nil {
			pubs = append(pubs, pub)
		}
	}
	verified, err := helpers.VerifyDirectoryResponse(authority, f.header, f.body, pubs, now)
	if err != nil {
		return nil, err
	}
	out := proto.Clone(file).(*forav1.WBAFile)
	out.Keys = out.Keys[:0]
	for _, k := range file.GetKeys() {
		pub, perr := wbaPublicKey(k)
		if perr != nil {
			continue
		}
		if tp, terr := helpers.Thumbprint(pub); terr == nil && verified[tp] {
			out.Keys = append(out.Keys, k)
		}
	}
	return out, nil
}

// requestAuthority is the RFC 9421 @authority of a fetch of rawURL: the host,
// lowercased, with the port only when it is not the scheme's default.
func requestAuthority(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: cannot derive the authority of %q", ErrDirectoryUnavailable, rawURL)
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port == "" || (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		return host, nil
	}
	return host + ":" + port, nil
}

// fetchRevocationList GETs url through client and decodes the KeyRevocationList
// leniently. Any failure wraps ErrDirectoryUnavailable; WBAKeyResolver's revocation
// refresh logs it and keeps the snapshot it holds.
func fetchRevocationList(ctx context.Context, client *http.Client, url string) (*forav1.KeyRevocationList, error) {
	f, err := fetchDocument(ctx, client, url)
	if err != nil {
		return nil, err
	}
	var list forav1.KeyRevocationList
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(f.body, &list); err != nil {
		return nil, fmt.Errorf("%w: decode: %w", ErrDirectoryUnavailable, err)
	}
	return &list, nil
}

// docKind is what the contract says about one document: its message, and the
// media type it is served under when the protocol names one.
type docKind struct {
	message     string
	mediaType   string
	versionGate bool // ver is read before any other member (the manifest's rule)
}

var (
	manifestKind       = docKind{message: "fora.v1.WellKnownManifest", mediaType: ManifestMediaType, versionGate: true}
	wbaDirectoryKind   = docKind{message: "fora.v1.WBAFile", mediaType: WBADirectoryMediaType}
	revocationListKind = docKind{message: "fora.v1.KeyRevocationList"}
)

// acceptDocument checks a fetched document as kind and decodes it into msg. The
// checks run in the order the contract reads a document: the media type, when the
// protocol names one; the body as JSON; for the manifest, ver before any other
// member; then the strict contract. Pure: the document-check corpus replays it
// with the bytes and the label it carries, so the three languages answer one
// document with one verdict.
func acceptDocument[M proto.Message](kind docKind, f fetchedDocument, msg M) (*Document[M], error) {
	if kind.mediaType != "" && f.mediaType != kind.mediaType {
		served := "no media type"
		if f.mediaType != "" {
			served = fmt.Sprintf("%q", f.mediaType)
		}
		return nil, fmt.Errorf("%w: %s was served with %s, not %q", ErrMediaTypeRefused, f.url, served, kind.mediaType)
	}
	if !utf8.Valid(f.body) || !json.Valid(f.body) {
		return nil, fmt.Errorf("%w: decode %s: not JSON", ErrDirectoryUnavailable, f.url)
	}
	if kind.versionGate {
		var probe struct {
			Ver json.RawMessage `json:"ver"`
		}
		_ = json.Unmarshal(f.body, &probe) // a body that is not an object carries no ver
		if err := helpers.CheckWellKnownManifestVersion(manifestVer(probe.Ver)); err != nil {
			return nil, fmt.Errorf("resolvers: %w", err)
		}
	}
	if err := helpers.CheckStrict(kind.message, f.body); err != nil {
		return nil, fmt.Errorf("resolvers: %w", err)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(f.body, msg); err != nil {
		return nil, fmt.Errorf("resolvers: %w: %s: %v", helpers.ErrStrictViolation, kind.message, err)
	}
	return &Document[M]{Message: msg, MediaType: f.mediaType, URL: f.url, Body: f.body}, nil
}

// verifyLicenseDigest hashes the fetched bytes with uriDigest's method and
// compares. Pure, and replayed by the license-digest corpus. uriDigest has passed
// the strict License check by the time a reader calls this, so its method is one
// of the three the contract admits; a value that is not is an error.
func verifyLicenseDigest(uriDigest string, f fetchedDocument) (*LicenseDocument, error) {
	method, expected, _ := strings.Cut(uriDigest, ":")
	var h hash.Hash
	switch method {
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	default:
		return nil, fmt.Errorf("resolvers: uri_digest names no supported method: %q", method)
	}
	h.Write(f.body)
	actual := hex.EncodeToString(h.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return nil, fmt.Errorf("%w: document at %s hashes to %s:%s, the license pins %s",
			ErrDigestMismatch, f.url, method, actual, uriDigest)
	}
	return &LicenseDocument{Body: f.body, Digest: method + ":" + actual, MediaType: f.mediaType, URL: f.url}, nil
}

// fetchedDocument is one document as it was served.
type fetchedDocument struct {
	url       string
	body      []byte
	mediaType string // the Content-Type essence, lowercased; "" when absent
	header    http.Header
}

// errRedirectRefused fails a key-directory fetch that met a redirect. A directory
// answers 200 itself: its address is the origin its signer committed to, and a
// redirect would hand key lookup to another one.
var errRedirectRefused = errors.New("resolvers: a key directory is never fetched through a redirect")

// fetchDocumentNoRedirect is fetchDocument over a copy of client that refuses
// every redirect, whatever policy the injected client carries.
func fetchDocumentNoRedirect(ctx context.Context, client *http.Client, url string) (fetchedDocument, error) {
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error { return errRedirectRefused }
	return fetchDocument(ctx, &noRedirect, url)
}

// fetchDocument GETs url through client and returns the body and its media type
// on 200. Every failure wraps ErrDirectoryUnavailable: a transport failure, a
// non-200 status, and a body past maxWellKnownDocBytes, which is refused rather
// than truncated. A truncated document that happens to decode is worse than a
// refusal, and a truncated license document would be reported as a digest
// mismatch it is not.
//
// It is the one GET every document read shares: the public readers, the three
// well-known faces through fetchWellKnownDoc, and the WBA directory and revocation
// reads of WBAKeyResolver and NewWBADirectoryFetcher.
func fetchDocument(ctx context.Context, client *http.Client, url string) (fetchedDocument, error) {
	ctx, cancel := context.WithTimeout(ctx, maxDocumentFetch)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%w: request: %w", ErrDirectoryUnavailable, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%w: fetch: %w", ErrDirectoryUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fetchedDocument{}, fmt.Errorf("%w: status %d", ErrDirectoryUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWellKnownDocBytes+1))
	if err != nil {
		return fetchedDocument{}, fmt.Errorf("%w: read: %w", ErrDirectoryUnavailable, err)
	}
	if len(body) > maxWellKnownDocBytes {
		return fetchedDocument{}, fmt.Errorf("%w: document exceeds the %d byte cap", ErrDirectoryUnavailable, maxWellKnownDocBytes)
	}
	return fetchedDocument{
		url: url, body: body, mediaType: mediaTypeEssence(resp.Header.Get("Content-Type")), header: resp.Header,
	}, nil
}

// mediaTypeEssence is the type/subtype of a Content-Type value, lowercased, with
// its parameters dropped. "" when the header is absent.
func mediaTypeEssence(header string) string {
	essence, _, _ := strings.Cut(header, ";")
	return strings.ToLower(strings.TrimSpace(essence))
}
