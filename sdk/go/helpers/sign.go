package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// AlgEd25519 is the RFC 9421 alg value for Ed25519 signatures.
const AlgEd25519 = "ed25519"

// BrokerKeyIDPrefix was the keyID prefix that marked a broker relay key on the
// wire (shape "broker.<instance>.<rotation>").
//
// Deprecated: a keyid is the RFC 7638 thumbprint of the signing key, and every
// signature's key is resolved in the directory its own Signature-Agent member
// names, so nothing reads a relay prefix any more.
const BrokerKeyIDPrefix = "broker."

// Signer performs the raw crypto half of RFC 9421 request signing. The SDK
// builds the signature base (covered components + parameters); the Signer signs
// exactly those bytes. Splitting it this way means a KMS/HSM/remote signer
// satisfies the same interface and the SDK never sees the private key — custody
// stays with the application (ADR-020 §3, fora-sdk-api.md "The core abstraction:
// Signer").
type Signer interface {
	// KeyID is the RFC 9421 keyid the verifier resolves a public key for.
	KeyID() string
	// Algorithm is the RFC 9421 alg value (e.g. AlgEd25519).
	Algorithm() string
	// Sign returns the signature over the signature base. ctx lets a remote
	// signer carry deadlines/cancellation; local signers ignore it.
	Sign(ctx context.Context, signatureBase []byte) ([]byte, error)
}

// ed25519Signer is the built-in local Ed25519 signer.
type ed25519Signer struct {
	keyID string
	priv  ed25519.PrivateKey
}

// NewEd25519Signer wraps an in-memory Ed25519 private key as a Signer. For
// KMS/HSM custody, implement Signer directly instead.
func NewEd25519Signer(keyID string, priv ed25519.PrivateKey) (Signer, error) {
	if keyID == "" {
		return nil, fmt.Errorf("helpers: signer keyID is empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("helpers: ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	return &ed25519Signer{keyID: keyID, priv: priv}, nil
}

// NewEd25519SignerFromSeed builds a Signer from a 32-byte Ed25519 seed.
func NewEd25519SignerFromSeed(keyID string, seed []byte) (Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("helpers: ed25519 seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	return NewEd25519Signer(keyID, ed25519.NewKeyFromSeed(seed))
}

func (s *ed25519Signer) KeyID() string     { return s.keyID }
func (s *ed25519Signer) Algorithm() string { return AlgEd25519 }

func (s *ed25519Signer) Sign(_ context.Context, base []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, base), nil
}

// SignOptions tune SignRequest and AppendSignature. Created/Expires are injected
// (L1 reads no clock) as unix-seconds; the verifier enforces the window against
// its own clock. The window must be positive and at most MaxSignatureLifetime,
// or signing fails with ErrSignatureLifetime.
//
// SignatureAgent is the signer's key-directory origin, the ASCII serialization of
// an https origin such as "https://agent.example". It is required: the signature
// covers its own Signature-Agent member, <label>="<origin>", which names the
// directory a verifier resolves the keyid in. A value that is not an https origin
// fails with ErrSignatureAgentNotOrigin, an empty one with
// ErrSignatureAgentRequired.
//
// Label is the signature's label, which is also the key of its Signature-Agent
// member. Empty means "sig1" for SignRequest and, for AppendSignature, the first
// "sigN" no signature or member on the request uses. A label that is not a
// structured-field key, or one already in use, fails with ErrSignatureLabel.
//
// Nonce, when set, is emitted as the RFC 9421 nonce parameter. Ed25519 is
// deterministic and created/expires have one-second resolution, so two identical
// requests signed in the same second produce the same signature and the second
// one is refused as a replay. A fresh nonce per signature makes each signature
// unique. The helpers read no RNG: a caller that needs unique signatures supplies
// the nonce (the signing transport supplies 64 random bytes). Empty emits no
// nonce. A non-empty nonce must use only base64url characters (A-Z a-z 0-9 - _),
// or signing fails with ErrInvalidNonce.
//
// CoverPrevious is read by AppendSignature only. It makes the new signature cover
// the last signature already on the request, if there is one, as WG-00 §5.2.2 permits a party that
// forwards a request unchanged: every component that signature lists, its
// Signature member and its Signature-Input member. Leave it false when the
// request was changed in any component the earlier signature covers. FORA's
// Broker never sets it: it originates or re-packages every request it sends.
type SignOptions struct {
	Created        int64
	Expires        int64
	Nonce          string
	SignatureAgent string
	Label          string
	CoverPrevious  bool
}

// SignRequest signs req as a FORA RPC under the Web Bot Auth profile and mutates
// it in place. It sets Content-Digest over body, binds the Authorization header
// (even when empty, so a later token injection is detected), sets Signature-Agent
// to the one-member dictionary <label>="<origin>", builds the RFC 9421 signature
// base over @method, @target-uri, content-digest, authorization and that member
// (plus x-entitlement-token when the request carries it), asks the Signer to sign
// it, and writes the Signature-Input and Signature headers, replacing any already
// there. body must be the exact bytes that will be transmitted.
func SignRequest(ctx context.Context, req *http.Request, body []byte, signer Signer, opts SignOptions) error {
	if signer == nil {
		return fmt.Errorf("helpers: nil signer")
	}
	label := opts.Label
	if label == "" {
		label = "sig1"
	}
	if err := checkSignOptions(opts, label); err != nil {
		return err
	}
	req.Header.Set("Content-Digest", ContentDigest(body))
	bindAuthorization(req)
	req.Header.Set(SignatureAgentHeader, signatureAgentMember(label, opts.SignatureAgent))
	params := requestSigParams(req, label, signer, opts)
	return signWithParams(ctx, req, params, signer, sigWriteSet)
}

// AppendSignature adds a signature to req WITHOUT disturbing any signature
// already on it. It preserves an existing Content-Digest (only setting it when
// missing), binds Authorization, appends the new signature's member to the
// Signature-Agent dictionary, and appends to Signature-Input and Signature. The
// new signature covers its own request components and its own member, and, only
// when opts.CoverPrevious is set, the last earlier signature (see SignOptions).
// Appending to a request with no signature produces the same headers as
// SignRequest with the same label.
//
// A request whose Signature-Agent is not a dictionary, such as an agent's legacy
// String form, fails with ErrSignatureAgentForm: a String cannot take a second
// member, and rewriting it would break the earlier signature.
func AppendSignature(ctx context.Context, req *http.Request, body []byte, signer Signer, opts SignOptions) error {
	if signer == nil {
		return fmt.Errorf("helpers: nil signer")
	}
	label := opts.Label
	if label == "" {
		label = nextFreeLabel(req.Header)
	}
	if err := checkSignOptions(opts, label); err != nil {
		return err
	}
	if usedLabels(req.Header)[label] {
		return fmt.Errorf("%w: %q is already in use on the request", ErrSignatureLabel, label)
	}
	if _, err := signatureAgentDictionary(req.Header); err != nil {
		return err
	}
	var prev *sigParams
	if opts.CoverPrevious && joinedHeader(req.Header, "Signature-Input") != "" {
		all, _, err := parseAllSignatures(req.Header)
		if err != nil {
			return fmt.Errorf("helpers: cover previous signature: %w", err)
		}
		prev = &all[len(all)-1]
	}
	if req.Header.Get("Content-Digest") == "" {
		req.Header.Set("Content-Digest", ContentDigest(body))
	}
	bindAuthorization(req)
	member := signatureAgentMember(label, opts.SignatureAgent)
	if existing := joinedHeader(req.Header, SignatureAgentHeader); existing != "" {
		member = existing + ", " + member
	}
	req.Header.Set(SignatureAgentHeader, member)
	params := requestSigParams(req, label, signer, opts)
	if prev != nil {
		params.Covered = coverEarlier(params.Covered, *prev)
	}
	return signWithParams(ctx, req, params, signer, sigWriteAppend)
}

// checkSignOptions refuses what no conformant signature can carry: a missing or
// non-origin Signature-Agent, an unusable label, or a window that is not positive
// or longer than MaxSignatureLifetime.
func checkSignOptions(opts SignOptions, label string) error {
	if opts.SignatureAgent == "" {
		return ErrSignatureAgentRequired
	}
	if err := CheckHTTPSOrigin(opts.SignatureAgent); err != nil {
		return err
	}
	if !validLabel(label) {
		return fmt.Errorf("%w: %q", ErrSignatureLabel, label)
	}
	if life := opts.Expires - opts.Created; opts.Created <= 0 || life <= 0 || life > int64(MaxSignatureLifetime.Seconds()) {
		return fmt.Errorf("%w: created=%d expires=%d", ErrSignatureLifetime, opts.Created, opts.Expires)
	}
	return nil
}

// requestSigParams assembles the parameters of a FORA RPC signature labelled
// label: the covered set coveredFor gives, the signer's keyid and alg, the window,
// the nonce and the Web Bot Auth tag.
func requestSigParams(req *http.Request, label string, signer Signer, opts SignOptions) sigParams {
	return sigParams{
		Label:   label,
		Covered: coveredFor(req, label),
		KeyID:   signer.KeyID(),
		Alg:     signer.Algorithm(),
		Created: opts.Created,
		Expires: opts.Expires,
		Nonce:   opts.Nonce,
		Tag:     WBATag,
	}
}

// bindAuthorization ensures the Authorization header is present so the signature
// commits to its value (empty string included) and a later injection cannot
// piggy-back the same signature.
func bindAuthorization(req *http.Request) {
	if req.Header.Get("Authorization") == "" {
		req.Header.Set("Authorization", "")
	}
}

// sigWriteMode selects whether signWithParams replaces or appends the emitted
// Signature-Input / Signature headers.
type sigWriteMode int

const (
	sigWriteSet sigWriteMode = iota
	sigWriteAppend
)

// ErrInvalidNonce is returned when SignOptions.Nonce has a character outside the
// base64url alphabet. The Go, Python and TypeScript SDKs apply the same rule, so
// a nonce that one SDK accepts is written as the same bytes by all three.
var ErrInvalidNonce = errors.New("helpers: nonce must use only base64url characters")

// validNonce reports whether n is empty or uses only base64url characters.
func validNonce(n string) bool {
	for _, c := range n {
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// signWithParams builds the signature base for params, signs it via signer, and
// writes the Signature-Input / Signature headers per mode. Shared by SignRequest
// and AppendSignature so base construction and header emission live in one place.
func signWithParams(ctx context.Context, req *http.Request, params sigParams, signer Signer, mode sigWriteMode) error {
	if !validNonce(params.Nonce) {
		return ErrInvalidNonce
	}
	base, err := buildSignatureBase(req, params)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(ctx, []byte(base))
	if err != nil {
		return fmt.Errorf("helpers: signer.Sign: %w", err)
	}
	input := params.Label + "=" + signatureInputInner(params)
	value := fmt.Sprintf("%s=:%s:", params.Label, base64.StdEncoding.EncodeToString(sig))
	if mode == sigWriteAppend {
		if existing := joinedHeader(req.Header, "Signature-Input"); existing != "" {
			input = existing + ", " + input
		}
		if existing := joinedHeader(req.Header, "Signature"); existing != "" {
			value = existing + ", " + value
		}
	}
	req.Header.Set("Signature-Input", input)
	req.Header.Set("Signature", value)
	return nil
}

// joinedHeader is every field line under name joined with ", " and trimmed, the
// value RFC 9421 §2.1 reads for a header. Appending to the first line alone would
// drop the others from the rewritten header.
func joinedHeader(h http.Header, name string) string {
	return strings.TrimSpace(strings.Join(h.Values(name), ", "))
}
