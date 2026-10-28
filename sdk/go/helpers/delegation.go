package helpers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Delegation chain verification — the FORA holder-bound JWT profile.
//
// The profile is the "Delegation" section of the authentication page
// (website/src/content/docs/protocol/authentication.mdx); this file is its only
// implementation and the shared chain cases in testdata/delegation-chains.json
// are derived from the page, not from this code. A Delegation.token is one
// compact JWS whose every child carries its complete signed parent in the
// fora_parent claim; the root is verified with a key the caller configured, a
// child with the Ed25519 key in its own protected jwk header, which must hash to
// the parent's cnf.jkt. Nothing is fetched: trust is the caller's input.
//
// Why the signature is checked with crypto/ed25519 and not go-jose: RFC 9864
// registers the fully-specified alg value "Ed25519" and marks the polymorphic
// "EdDSA" deprecated, and the profile accepts both with an Ed25519 key. The
// pinned go-jose v4 knows only "EdDSA" and rejects "Ed25519" before any key is
// inspected, so a chain signed by a current issuer could never be verified
// through it. The compact serialization is three base64url segments, the
// signing input is the first two joined by ".", and an Ed25519 signature is 64
// bytes, so verifying the original bytes with the standard library is a few
// lines and needs no header rewrite. go-jose still parses the jwk header (it
// knows the OKP form and refuses other curves) and computes the RFC 7638
// thumbprint (Thumbprint), where it fits.

const (
	// MaxDelegationTokenBytes is the size limit of Delegation.token: the wire
	// rule bytes.max_len on the field, checked here again before any parsing and
	// on every embedded parent before it is decoded.
	MaxDelegationTokenBytes = 32768
	// MaxDelegationChainDepth is the most tokens a chain may hold, the root
	// included. A fifth token is never decoded.
	MaxDelegationChainDepth = 4
	// DelegationClockLeeway is the clock skew the exp and nbf checks allow. It
	// never extends the effective expiry the verifier returns.
	DelegationClockLeeway = 60 * time.Second
	// DelegationTokenType is the protected header typ every token must carry.
	DelegationTokenType = "fora-delegation+jwt"
	// MaxDelegationNumericDate is the largest exp or nbf the profile accepts:
	// 9999-12-31T23:59:59Z, the last second a protocol Timestamp can carry, so
	// the effective expiry the verifier returns always fits one. The smallest
	// is 0.
	MaxDelegationNumericDate = 253402300799
)

// TrustedIssuer is one configured root key and the issuer identity it belongs
// to. A root token verifies only with a key whose Identity equals its iss claim
// exactly; several entries may share an Identity while a key is being replaced.
type TrustedIssuer struct {
	Identity string
	Key      ed25519.PublicKey
}

// DelegationInput is everything VerifyDelegation reads. Trust, audience, holder
// and time all come from the caller; the verifier reaches nothing else.
type DelegationInput struct {
	// Token is Delegation.token: the complete chain as one compact JWS.
	Token []byte
	// TrustedIssuers are the configured root keys; in an Exchange they come from
	// the subscription record that owns the gated term.
	TrustedIssuers []TrustedIssuer
	// Audience is the verifier's own identity as a bare domain, the value the
	// Request recipient rule compares an aud entry with.
	Audience string
	// Holder is the RFC 7638 thumbprint of the key the request proved possession
	// of: the RFC 9421 request key on a direct call, the AgentAcceptance key on
	// a purchase a Broker relayed.
	Holder string
	// Now is the clock reading every token is checked against.
	Now time.Time
}

// VerifiedDelegation is the result of a chain that passed every check.
type VerifiedDelegation struct {
	// RootIssuer is the root token's iss, the identity of the trusted key that
	// verified it.
	RootIssuer string
	// Holder is the terminal token's cnf.jkt, equal to DelegationInput.Holder.
	Holder string
	// Scopes are the effective scopes: the terminal token's scope claim,
	// normalized. Nil when the terminal token grants no scoped access.
	Scopes []string
	// ExpiresAt is the earliest exp in the chain, without leeway. A gated offer
	// must not expire later than this.
	ExpiresAt time.Time
	// Depth is the number of tokens in the chain, the root included.
	Depth int
}

// DelegationFailure names why a chain was refused. Every value maps to
// DENIAL_REASON_DELEGATION_INVALID on the wire; the name is for the journal
// and for the shared chain cases.
type DelegationFailure string

const (
	DelegationOversized              DelegationFailure = "oversized"
	DelegationMalformed              DelegationFailure = "malformed"
	DelegationTooDeep                DelegationFailure = "too_deep"
	DelegationBadAlg                 DelegationFailure = "bad_alg"
	DelegationBadTyp                 DelegationFailure = "bad_typ"
	DelegationCritPresent            DelegationFailure = "crit_present"
	DelegationMissingClaim           DelegationFailure = "missing_claim"
	DelegationBadClaim               DelegationFailure = "bad_claim"
	DelegationUnknownClaim           DelegationFailure = "unknown_claim"
	DelegationUnsupportedRestriction DelegationFailure = "unsupported_restriction"
	DelegationAdvisoryShadowsClaim   DelegationFailure = "advisory_shadows_claim"
	DelegationUntrustedIssuer        DelegationFailure = "untrusted_issuer"
	DelegationBadSignature           DelegationFailure = "bad_signature"
	DelegationBadJWK                 DelegationFailure = "bad_jwk"
	DelegationJWKMismatch            DelegationFailure = "jwk_mismatch"
	DelegationChildIssuerMismatch    DelegationFailure = "child_issuer_mismatch"
	DelegationExpired                DelegationFailure = "expired"
	DelegationNotYetValid            DelegationFailure = "not_yet_valid"
	DelegationExpiryWidened          DelegationFailure = "expiry_widened"
	DelegationAudienceMismatch       DelegationFailure = "audience_mismatch"
	DelegationAudienceWidened        DelegationFailure = "audience_widened"
	DelegationScopeWidened           DelegationFailure = "scope_widened"
	DelegationHolderMismatch         DelegationFailure = "holder_mismatch"
)

// ErrDelegationInvalid is the sentinel every DelegationError unwraps to, so a
// caller can map any refusal to DENIAL_REASON_DELEGATION_INVALID with errors.Is.
var ErrDelegationInvalid = errors.New("helpers: delegation invalid")

// DelegationError is a refusal: which check failed, on which token (1 is the
// root, Depth is the terminal token; 0 when the chain as a whole is refused)
// and a short detail for the journal.
type DelegationError struct {
	Failure DelegationFailure
	Token   int
	Detail  string
}

func (e *DelegationError) Error() string {
	if e.Token == 0 {
		return fmt.Sprintf("helpers: delegation invalid: %s: %s", e.Failure, e.Detail)
	}
	return fmt.Sprintf("helpers: delegation invalid: %s on token %d: %s", e.Failure, e.Token, e.Detail)
}

func (e *DelegationError) Unwrap() error { return ErrDelegationInvalid }

func refuse(f DelegationFailure, token int, detail string) error {
	return &DelegationError{Failure: f, Token: token, Detail: detail}
}

// delegationClaims lists every claim the profile allows at the top level. Any
// other claim is a restriction the verifier cannot evaluate and is refused.
var delegationClaims = map[string]bool{
	"iss": true, "aud": true, "cnf": true, "exp": true, "nbf": true, "jti": true,
	"iat": true, "sub": true, "scope": true, "fora_parent": true, "fora_advisory": true,
	"fora_max_spend_cents": true, "fora_max_accesses": true, "fora_quota_period": true,
}

// delegationCaps are profile claims this verifier cannot enforce: it meters
// nothing, so a chain that carries one is refused rather than the cap dropped.
var delegationCaps = []string{"fora_max_spend_cents", "fora_max_accesses", "fora_quota_period"}

// delegationToken is one decoded token of the chain.
type delegationToken struct {
	signingInput []byte
	signature    []byte
	alg          string
	jwk          json.RawMessage // protected jwk header, nil when absent
	claims       map[string]any
	iss          string
	aud          map[string]bool // normalized recipient identities
	jkt          string
	exp, nbf     float64
	hasNbf       bool
	scopes       []string
	parent       string
}

// VerifyDelegation verifies a delegation chain against the profile and returns
// the verified grant. Every refusal is a *DelegationError that unwraps to
// ErrDelegationInvalid; the only other error is an unusable Audience, which is
// the verifier's own configuration, not the chain's fault.
func VerifyDelegation(in DelegationInput) (*VerifiedDelegation, error) {
	if !IsBareDomain(in.Audience) {
		return nil, fmt.Errorf("%w: %q", ErrAudienceIdentity, in.Audience)
	}
	if len(in.Token) > MaxDelegationTokenBytes {
		return nil, refuse(DelegationOversized, 0, fmt.Sprintf("%d bytes, limit %d", len(in.Token), MaxDelegationTokenBytes))
	}

	// Walk inward: the outer token is the terminal one, the innermost the root.
	// Depth and size are checked before each nested decode, so a fifth token or
	// an oversized parent is never parsed.
	var outerFirst []*delegationToken
	raw := string(in.Token)
	for {
		tok, err := decodeDelegationToken(raw, len(outerFirst))
		if err != nil {
			return nil, err
		}
		outerFirst = append(outerFirst, tok)
		if tok.parent == "" {
			break
		}
		if len(outerFirst) >= MaxDelegationChainDepth {
			return nil, refuse(DelegationTooDeep, 0, fmt.Sprintf("more than %d tokens", MaxDelegationChainDepth))
		}
		if len(tok.parent) > MaxDelegationTokenBytes {
			return nil, refuse(DelegationOversized, 0, "embedded parent exceeds the token size limit")
		}
		raw = tok.parent
	}
	depth := len(outerFirst)
	chain := make([]*delegationToken, depth) // root first
	for i, tok := range outerFirst {
		chain[depth-1-i] = tok
	}
	// Token numbers in refusals count from the root, so token i of chain is i+1.

	// Root: a configured key whose identity is the root's iss, and nothing else.
	root := chain[0]
	var keys []ed25519.PublicKey
	for _, ti := range in.TrustedIssuers {
		if ti.Identity == root.iss && len(ti.Key) == ed25519.PublicKeySize {
			keys = append(keys, ti.Key)
		}
	}
	if len(keys) == 0 {
		return nil, refuse(DelegationUntrustedIssuer, 1, fmt.Sprintf("no configured key for issuer %q", root.iss))
	}
	rootOK := false
	for _, k := range keys {
		if ed25519.Verify(k, root.signingInput, root.signature) {
			rootOK = true
			break
		}
	}
	if !rootOK {
		return nil, refuse(DelegationBadSignature, 1, "root signature does not verify with the configured key")
	}

	// Children, outward from the root: the protected jwk is the signing key, it
	// must hash to the parent's cnf.jkt, the child's iss is that thumbprint.
	for i := 1; i < depth; i++ {
		tok, parent := chain[i], chain[i-1]
		n := i + 1
		if tok.jwk == nil {
			return nil, refuse(DelegationBadJWK, n, "child carries no protected jwk header")
		}
		var k jose.JSONWebKey
		if err := k.UnmarshalJSON(tok.jwk); err != nil {
			return nil, refuse(DelegationBadJWK, n, "protected jwk does not parse: "+err.Error())
		}
		pub, ok := k.Key.(ed25519.PublicKey)
		if !ok || !k.IsPublic() {
			return nil, refuse(DelegationBadJWK, n, "protected jwk is not an Ed25519 public key")
		}
		thumb, err := Thumbprint(pub)
		if err != nil {
			return nil, refuse(DelegationBadJWK, n, err.Error())
		}
		if thumb != parent.jkt {
			return nil, refuse(DelegationJWKMismatch, n, "protected jwk is not the key the parent's cnf.jkt names")
		}
		if tok.iss != thumb {
			return nil, refuse(DelegationChildIssuerMismatch, n, "iss is not the thumbprint of the signing key")
		}
		if !ed25519.Verify(pub, tok.signingInput, tok.signature) {
			return nil, refuse(DelegationBadSignature, n, "signature does not verify with the protected jwk")
		}
	}

	// Time, then attenuation against the parent, then audience, on every token.
	now := float64(in.Now.UnixNano()) / 1e9
	leeway := DelegationClockLeeway.Seconds()
	want := normalizeDomain(in.Audience)
	earliest := math.Inf(1)
	for i, tok := range chain {
		n := i + 1
		if now >= tok.exp+leeway {
			return nil, refuse(DelegationExpired, n, "exp has passed")
		}
		if tok.hasNbf && now < tok.nbf-leeway {
			return nil, refuse(DelegationNotYetValid, n, "nbf is in the future")
		}
		if tok.exp < earliest {
			earliest = tok.exp
		}
		if i > 0 {
			parent := chain[i-1]
			if tok.exp > parent.exp {
				return nil, refuse(DelegationExpiryWidened, n, "exp is later than the parent's")
			}
			for a := range tok.aud {
				if !parent.aud[a] {
					return nil, refuse(DelegationAudienceWidened, n, "aud names a recipient the parent did not")
				}
			}
			if !ScopesSubset(tok.scopes, parent.scopes) {
				return nil, refuse(DelegationScopeWidened, n, "scope is not covered by the parent's")
			}
		}
		if !tok.aud[want] {
			return nil, refuse(DelegationAudienceMismatch, n, "aud does not name this recipient")
		}
	}

	terminal := chain[depth-1]
	if in.Holder == "" || terminal.jkt != in.Holder {
		return nil, refuse(DelegationHolderMismatch, depth, "cnf.jkt is not the key the request proved possession of")
	}

	sec, frac := math.Modf(earliest)
	return &VerifiedDelegation{
		RootIssuer: root.iss,
		Holder:     terminal.jkt,
		Scopes:     NormalizeScopes(terminal.scopes),
		ExpiresAt:  time.Unix(int64(sec), int64(frac*1e9)).UTC(),
		Depth:      depth,
	}, nil
}

// decodeDelegationToken splits one compact JWS, checks its protected header
// and the shape of its claims, and leaves signature verification to the chain
// walk. index counts from the outer token; it is turned into a root-first
// token number only once the chain's depth is known, so refusals from here
// carry the position from the terminal token as a negative-free offset.
func decodeDelegationToken(raw string, index int) (*delegationToken, error) {
	// Positions in refusals count from the root; at decode time the depth is
	// unknown, so the position is reported later by the caller when possible.
	// Here the token number is 0 (chain as a whole) with the index in the detail.
	where := fmt.Sprintf("token %d from the outside", index)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, refuse(DelegationMalformed, 0, where+": not a compact JWS")
	}
	// Go's base64 decoder skips CR and LF, so the alphabet is checked by hand:
	// a segment is base64url without padding and nothing else, so the bytes
	// the signature covers are exactly the bytes that were read.
	for _, seg := range parts {
		if seg == "" || !isBase64URL(seg) {
			return nil, refuse(DelegationMalformed, 0, where+": a segment is not unpadded base64url")
		}
	}
	hdrBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return nil, refuse(DelegationMalformed, 0, where+": protected header is not base64url")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, refuse(DelegationMalformed, 0, where+": payload is not base64url")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, refuse(DelegationMalformed, 0, where+": signature is not 64 base64url bytes")
	}
	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil || hdr == nil {
		return nil, refuse(DelegationMalformed, 0, where+": protected header is not a JSON object")
	}
	tok := &delegationToken{signingInput: []byte(parts[0] + "." + parts[1]), signature: sig}
	if err := json.Unmarshal(hdr["alg"], &tok.alg); err != nil || (tok.alg != "EdDSA" && tok.alg != "Ed25519") {
		return nil, refuse(DelegationBadAlg, 0, where+": alg must be EdDSA or Ed25519")
	}
	var typ string
	if err := json.Unmarshal(hdr["typ"], &typ); err != nil || typ != DelegationTokenType {
		return nil, refuse(DelegationBadTyp, 0, where+": typ must be "+DelegationTokenType)
	}
	if _, has := hdr["crit"]; has {
		return nil, refuse(DelegationCritPresent, 0, where+": crit is not allowed")
	}
	// RFC 7797 unencoded payloads are not part of the profile; a b64 parameter
	// without crit is itself invalid under that RFC, and with crit it is caught
	// above, so its presence is malformed either way.
	if _, has := hdr["b64"]; has {
		return nil, refuse(DelegationMalformed, 0, where+": b64 is not allowed")
	}
	if jwk, has := hdr["jwk"]; has {
		tok.jwk = jwk
	}

	// The payload is exactly one JSON object: json.Unmarshal would refuse
	// trailing bytes, but the decoder is needed for UseNumber, and a decoder
	// stops after the first value, so the rest of the input is checked by hand.
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&tok.claims); err != nil || tok.claims == nil {
		return nil, refuse(DelegationMalformed, 0, where+": payload is not a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, refuse(DelegationMalformed, 0, where+": payload carries bytes after the JSON object")
	}
	if err := checkDelegationClaims(tok, where); err != nil {
		return nil, err
	}
	return tok, nil
}

// checkDelegationClaims applies the claims table of the profile to one token:
// required claims present with the right types, no unknown top-level claim, no
// cap this verifier cannot enforce, no profile name inside fora_advisory.
func checkDelegationClaims(tok *delegationToken, where string) error {
	c := tok.claims
	for name := range c {
		if !delegationClaims[name] {
			return refuse(DelegationUnknownClaim, 0, where+": unknown claim "+name)
		}
	}
	for _, capName := range delegationCaps {
		if _, has := c[capName]; has {
			return refuse(DelegationUnsupportedRestriction, 0, where+": "+capName+" cannot be enforced by this verifier")
		}
	}
	for _, name := range []string{"iss", "aud", "cnf", "exp"} {
		if _, has := c[name]; !has {
			return refuse(DelegationMissingClaim, 0, where+": "+name+" is required")
		}
	}
	var ok bool
	if tok.iss, ok = c["iss"].(string); !ok || tok.iss == "" {
		return refuse(DelegationBadClaim, 0, where+": iss must be a non-empty string")
	}
	tok.aud = map[string]bool{}
	var auds []string
	switch v := c["aud"].(type) {
	case string:
		auds = []string{v}
	case []any:
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return refuse(DelegationBadClaim, 0, where+": aud entries must be strings")
			}
			auds = append(auds, s)
		}
	default:
		return refuse(DelegationBadClaim, 0, where+": aud must be a string or an array of strings")
	}
	if len(auds) == 0 {
		return refuse(DelegationBadClaim, 0, where+": aud must name at least one recipient")
	}
	for _, a := range auds {
		if !IsBareDomain(a) {
			return refuse(DelegationBadClaim, 0, where+": aud entry is not a bare host: "+a)
		}
		tok.aud[normalizeDomain(a)] = true
	}
	cnf, ok := c["cnf"].(map[string]any)
	if !ok {
		return refuse(DelegationBadClaim, 0, where+": cnf must be an object")
	}
	if tok.jkt, ok = cnf["jkt"].(string); !ok {
		return refuse(DelegationBadClaim, 0, where+": cnf.jkt must be a string")
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(tok.jkt); err != nil || len(raw) != 32 {
		return refuse(DelegationBadClaim, 0, where+": cnf.jkt is not a base64url SHA-256 thumbprint")
	}
	if tok.exp, ok = numericDate(c["exp"]); !ok {
		return refuse(DelegationBadClaim, 0, where+": exp must be a finite number")
	}
	if v, has := c["nbf"]; has {
		if tok.nbf, ok = numericDate(v); !ok {
			return refuse(DelegationBadClaim, 0, where+": nbf must be a finite number")
		}
		tok.hasNbf = true
	}
	if v, has := c["jti"]; has {
		if s, ok := v.(string); !ok || s == "" {
			return refuse(DelegationBadClaim, 0, where+": jti must be a non-empty string")
		}
	}
	if v, has := c["scope"]; has {
		s, ok := v.(string)
		if !ok {
			return refuse(DelegationBadClaim, 0, where+": scope must be a string")
		}
		tok.scopes = strings.Fields(s)
	}
	if v, has := c["fora_parent"]; has {
		s, ok := v.(string)
		if !ok || s == "" {
			return refuse(DelegationBadClaim, 0, where+": fora_parent must be a non-empty string")
		}
		tok.parent = s
	}
	if v, has := c["fora_advisory"]; has {
		obj, ok := v.(map[string]any)
		if !ok {
			return refuse(DelegationBadClaim, 0, where+": fora_advisory must be an object")
		}
		for name := range obj {
			if delegationClaims[name] {
				return refuse(DelegationAdvisoryShadowsClaim, 0, where+": fora_advisory carries the profile claim "+name)
			}
		}
	}
	return nil
}

// numericDate reads a NumericDate claim: a JSON number between 0 and
// MaxDelegationNumericDate. A value outside that range is finite but not a
// date this profile can return, so it is refused before any conversion.
func numericDate(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f < 0 || f > MaxDelegationNumericDate {
		return 0, false
	}
	return f, true
}

// isBase64URL reports whether s holds only the unpadded base64url alphabet.
func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
