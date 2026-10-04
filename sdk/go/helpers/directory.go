package helpers

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// A key directory's response is signed once per key it lists (WG-00 §5.5 and
// Appendix B.1), and FORA requires it. Each response signature covers
// "@authority";req, the authority the directory was fetched from, and
// content-digest, carries created, expires, keyid (the key's RFC 7638 thumbprint)
// and alg, and has tag="http-message-signatures-directory". "@authority";req
// takes its value from the request that fetched the directory, so the signature
// cannot be served again under a different host.

// ErrDirectoryResponseUnsigned signals a key directory whose response carries no
// valid signature by a key the caller needs: none at all, or none by that key.
var ErrDirectoryResponseUnsigned = errors.New("helpers: key directory response is not signed by the key")

// directoryResponseCovered is the covered set of a directory response signature,
// in the order a FORA signer emits it.
var directoryResponseCovered = []CoveredComponent{
	{Name: "@authority", Params: []ComponentParam{{Key: "req", Flag: true}}},
	{Name: "content-digest"},
}

// DirectoryResponseSignature is the three header values a key directory's
// response carries for its response signatures, ready to set on the response.
type DirectoryResponseSignature struct {
	ContentDigest  string
	SignatureInput string
	Signature      string
}

// Apply writes the three headers onto h.
func (d DirectoryResponseSignature) Apply(h http.Header) {
	h.Set("Content-Digest", d.ContentDigest)
	h.Set("Signature-Input", d.SignatureInput)
	h.Set("Signature", d.Signature)
}

// SignDirectoryResponse signs a key directory response once per signer, labels
// sig1..sigN in order. authority is the host[:port] the directory is served
// under, exactly as a client's request names it: lowercase, and without a port
// when it is the scheme's default. body is the exact response body. Each signer's
// KeyID must be the RFC 7638 thumbprint of a key the body lists; a verifier
// matches the two. The window is the caller's: a directory response is cached and
// may be signed for longer than a request.
func SignDirectoryResponse(
	ctx context.Context, authority string, body []byte, signers []Signer, created, expires int64,
) (DirectoryResponseSignature, error) {
	if authority == "" {
		return DirectoryResponseSignature{}, errors.New("helpers: directory response needs the authority it is served under")
	}
	if len(signers) == 0 {
		return DirectoryResponseSignature{}, errors.New("helpers: directory response needs at least one signer")
	}
	if created <= 0 || expires <= created {
		return DirectoryResponseSignature{}, fmt.Errorf("%w: created=%d expires=%d", ErrSignatureLifetime, created, expires)
	}
	digest := ContentDigest(body)
	inputs := make([]string, 0, len(signers))
	sigs := make([]string, 0, len(signers))
	for i, signer := range signers {
		if signer == nil {
			return DirectoryResponseSignature{}, fmt.Errorf("helpers: directory response signer %d is nil", i)
		}
		params := sigParams{
			Label: fmt.Sprintf("sig%d", i+1), Covered: directoryResponseCovered,
			KeyID: signer.KeyID(), Alg: signer.Algorithm(), Created: created, Expires: expires,
			Tag: DirectoryResponseTag,
		}
		inner := signatureInputInner(params)
		raw, err := signer.Sign(ctx, []byte(directoryResponseBase(authority, digest, inner)))
		if err != nil {
			return DirectoryResponseSignature{}, fmt.Errorf("helpers: sign directory response: %w", err)
		}
		inputs = append(inputs, params.Label+"="+inner)
		sigs = append(sigs, params.Label+"=:"+base64.StdEncoding.EncodeToString(raw)+":")
	}
	return DirectoryResponseSignature{
		ContentDigest:  digest,
		SignatureInput: strings.Join(inputs, ", "),
		Signature:      strings.Join(sigs, ", "),
	}, nil
}

// directoryResponseBase is the signature base of a directory response signature:
// the authority, the Content-Digest value, and the verbatim parameters.
func directoryResponseBase(authority, digest, rawInner string) string {
	return strings.Join([]string{
		`"@authority";req: ` + strings.ToLower(authority),
		`"content-digest": ` + digest,
		`"@signature-params": ` + rawInner,
	}, "\n")
}

// VerifyDirectoryResponse checks the response signatures of a fetched key
// directory and returns the RFC 7638 thumbprints of the listed keys that signed
// it. authority is the host[:port] the directory was fetched from, h the response
// headers and body the exact response body; keys are the Ed25519 keys the body
// lists.
//
// The Content-Digest must match the body, or no key is verified and the error
// wraps ErrDigestMismatch. A response with no signature at all wraps
// ErrDirectoryResponseUnsigned. Otherwise each response signature is judged on its
// own, and one that fails is ignored rather than fatal: it must carry
// tag="http-message-signatures-directory" and alg="ed25519", cover exactly
// "@authority";req and content-digest, carry created no later than now plus the
// 300-second skew and expires no earlier than now, and verify under the listed key
// whose thumbprint its keyid names.
func VerifyDirectoryResponse(
	authority string, h http.Header, body []byte, keys []ed25519.PublicKey, now time.Time,
) (map[string]bool, error) {
	digest := joinedHeader(h, "Content-Digest")
	if digest == "" {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryResponseUnsigned, ErrMissingContentDigest)
	}
	if digest != ContentDigest(body) {
		return nil, fmt.Errorf("helpers: key directory response: %w", ErrDigestMismatch)
	}
	all, sigMap, err := parseAllSignatures(h)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDirectoryResponseUnsigned, err)
	}
	byThumb := make(map[string]ed25519.PublicKey, len(keys))
	for _, k := range keys {
		if tp, terr := Thumbprint(k); terr == nil {
			byThumb[tp] = k
		}
	}
	verified := map[string]bool{}
	for _, p := range all {
		pub, ok := byThumb[p.KeyID]
		if !ok || !directoryResponseParamsValid(p, now) {
			continue
		}
		base := directoryResponseBaseFor(authority, digest, p)
		if ed25519.Verify(pub, []byte(base), sigMap[p.Label]) {
			verified[p.KeyID] = true
		}
	}
	return verified, nil
}

// directoryResponseParamsValid applies the per-signature rules other than the
// Ed25519 check: tag, alg, covered set and window.
func directoryResponseParamsValid(p sigParams, now time.Time) bool {
	if p.Tag != DirectoryResponseTag || !strings.EqualFold(p.Alg, AlgEd25519) {
		return false
	}
	if len(p.Covered) != len(directoryResponseCovered) {
		return false
	}
	for _, want := range directoryResponseCovered {
		if !coversComponent(p.Covered, want) {
			return false
		}
	}
	if p.Created == 0 || p.Expires == 0 {
		return false
	}
	return p.Created <= now.Unix()+int64(defaultMaxFutureSkew.Seconds()) && p.Expires >= now.Unix()
}

// directoryResponseBaseFor rebuilds a directory response signature's base in the
// order its own covered set lists, ending with its verbatim parameters.
func directoryResponseBaseFor(authority, digest string, p sigParams) string {
	lines := make([]string, 0, len(p.Covered)+1)
	for _, c := range p.Covered {
		if strings.EqualFold(c.Name, "@authority") {
			lines = append(lines, `"@authority";req: `+strings.ToLower(authority))
			continue
		}
		lines = append(lines, `"content-digest": `+digest)
	}
	return strings.Join(append(lines, `"@signature-params": `+p.RawInner), "\n")
}
