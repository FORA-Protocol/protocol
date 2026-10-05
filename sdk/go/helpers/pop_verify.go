package helpers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// The VERIFY face of the agent-binding proof of possession, the one a delivery
// edge runs. Go runs it for parity with the Python and TypeScript edges, and as the
// oracle for the shared pop-vectors.json verdicts.
//
// A proof is accepted when its signature covers AT LEAST the Web Bot Auth base and
// the two components the profile adds: @method, @target-uri and one
// Signature-Agent member. A proof made by a Web Bot Auth library that covers more,
// @authority for example, verifies too. On top of the signature the edge enforces
// the three-way identity agent_id == keyid == thumbprint(presented key), and it
// verifies offline against the key in X-FORA-Agent-Key.

// PoPFailure names why a delivery proof was refused. The tokens are shared with the
// Python and TypeScript verifiers and pinned by pop-vectors.json.
type PoPFailure string

// The PoPFailure tokens, in the order the checks run.
const (
	PoPMissingAgentKey      PoPFailure = "missing_agent_key"
	PoPBadAgentKey          PoPFailure = "bad_agent_key"
	PoPMissingSignature     PoPFailure = "missing_sig"
	PoPMalformedSignature   PoPFailure = "malformed_sig_input"
	PoPUnsupportedAlg       PoPFailure = "unsupported_alg"
	PoPBadTag               PoPFailure = "bad_tag"
	PoPBadCoveredComponents PoPFailure = "bad_covered_components"
	PoPBadSignatureAgent    PoPFailure = "bad_signature_agent"
	PoPKeyIDMismatch        PoPFailure = "keyid_mismatch"
	PoPThumbprintMismatch   PoPFailure = "thumbprint_mismatch"
	PoPMissingCreated       PoPFailure = "pop_missing_created"
	PoPFutureCreated        PoPFailure = "pop_future_created"
	PoPMissingExpires       PoPFailure = "pop_missing_exp"
	PoPExpired              PoPFailure = "pop_expired"
	PoPSignatureInvalid     PoPFailure = "pop_sig_invalid"
)

// PoPAcceptSignature is the Accept-Signature value a refused delivery proof is
// answered with: the components a proof must cover at least, the dictionary form
// of Signature-Agent, and the created, expires and tag parameters.
const PoPAcceptSignature = `sig1=("@method" "@target-uri" "signature-agent";key="sig1");created;expires;tag="` + WBATag + `"`

// PoPError is the refusal of a delivery proof. AcceptSignature is
// PoPAcceptSignature when the fetcher can fix the refusal by signing again as the
// profile requires — no signature, a wrong tag, a missing required component, or a
// Signature-Agent the profile refuses — and empty otherwise.
type PoPError struct {
	Reason          PoPFailure
	AcceptSignature string
	Err             error
}

func (e *PoPError) Error() string {
	if e.Err != nil {
		return "helpers: delivery proof refused: " + string(e.Reason) + ": " + e.Err.Error()
	}
	return "helpers: delivery proof refused: " + string(e.Reason)
}

func (e *PoPError) Unwrap() error { return e.Err }

// PoPVerifyOptions tune VerifyAgentBinding. Now is the verifier's clock (zero
// means time.Now); MaxFutureSkew bounds how far created may lead it (zero means
// 300 seconds).
type PoPVerifyOptions struct {
	Now           time.Time
	MaxFutureSkew time.Duration
}

// VerifiedAgentBinding is an accepted delivery proof: the agent's keyid, the https
// origin of the key directory its Signature-Agent member names, and its window.
type VerifiedAgentBinding struct {
	KeyID          string
	SignatureAgent string
	Created        int64
	Expires        int64
}

// VerifyAgentBinding verifies the proof of possession on a delivery fetch of
// rawURL, the URL exactly as the request line carried it, bound to agentID, the
// signed URL's agent_id. h is the request's headers. Every refusal is a *PoPError
// naming its PoPFailure.
func VerifyAgentBinding(method, rawURL string, h http.Header, agentID string, opts PoPVerifyOptions) (*VerifiedAgentBinding, error) {
	presented, perr := presentedAgentKey(h)
	if perr != nil {
		return nil, perr
	}
	all, sigs, err := parseAllSignatures(h)
	switch {
	case errors.Is(err, ErrMissingSignatureInput), errors.Is(err, ErrMissingSignature):
		return nil, popRefusal(PoPMissingSignature, true, err)
	case err != nil:
		return nil, popRefusal(PoPMalformedSignature, false, err)
	}
	p := all[0]
	if !strings.EqualFold(p.Alg, AlgEd25519) {
		return nil, popRefusal(PoPUnsupportedAlg, false, nil)
	}
	if p.Tag != WBATag {
		return nil, popRefusal(PoPBadTag, true, nil)
	}
	if !coversPoPProfile(p.Covered) {
		return nil, popRefusal(PoPBadCoveredComponents, true, nil)
	}
	directory, err := signatureDirectory(h, p, len(all))
	if err != nil {
		var missing *MissingComponentError
		if errors.As(err, &missing) {
			return nil, popRefusal(PoPBadCoveredComponents, true, err)
		}
		return nil, popRefusal(PoPBadSignatureAgent, true, err)
	}
	if p.KeyID != agentID {
		return nil, popRefusal(PoPKeyIDMismatch, false, nil)
	}
	if thumb, terr := Thumbprint(presented); terr != nil || thumb != agentID {
		return nil, popRefusal(PoPThumbprintMismatch, false, terr)
	}
	if reason := popFreshness(p, opts); reason != "" {
		return nil, popRefusal(reason, false, nil)
	}
	base, err := popVerifyBase(method, rawURL, h, p)
	if err != nil {
		return nil, popRefusal(PoPBadCoveredComponents, true, err)
	}
	if !ed25519.Verify(presented, []byte(base), sigs[p.Label]) {
		return nil, popRefusal(PoPSignatureInvalid, false, nil)
	}
	return &VerifiedAgentBinding{KeyID: p.KeyID, SignatureAgent: directory, Created: p.Created, Expires: p.Expires}, nil
}

func popRefusal(reason PoPFailure, accept bool, err error) *PoPError {
	e := &PoPError{Reason: reason, Err: err}
	if accept {
		e.AcceptSignature = PoPAcceptSignature
	}
	return e
}

// presentedAgentKey reads X-FORA-Agent-Key: base64url without padding, 32 bytes.
func presentedAgentKey(h http.Header) (ed25519.PublicKey, error) {
	raw := h.Get(AgentKeyHeader)
	if raw == "" {
		return nil, popRefusal(PoPMissingAgentKey, false, nil)
	}
	key, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, popRefusal(PoPBadAgentKey, false, err)
	}
	return ed25519.PublicKey(key), nil
}

// coversPoPProfile reports whether a proof covers at least @method, @target-uri and
// a Signature-Agent reference. Anything else it covers is allowed; which member the
// reference names, and whether it is the only one, is signatureDirectory's call.
func coversPoPProfile(covered []CoveredComponent) bool {
	var method, target, agent bool
	for _, c := range covered {
		switch name := strings.ToLower(c.Name); {
		case name == "@method" && len(c.Params) == 0:
			method = true
		case name == "@target-uri" && len(c.Params) == 0:
			target = true
		case name == signatureAgentLower:
			agent = true
		}
	}
	return method && target && agent
}

func popFreshness(p sigParams, opts PoPVerifyOptions) PoPFailure {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := opts.MaxFutureSkew
	if skew == 0 {
		skew = defaultMaxFutureSkew
	}
	switch {
	case p.Created == 0:
		return PoPMissingCreated
	case p.Created > now.Unix()+int64(skew.Seconds()):
		return PoPFutureCreated
	case p.Expires == 0:
		return PoPMissingExpires
	case now.Unix() >= p.Expires:
		return PoPExpired
	}
	return ""
}

// popVerifyBase rebuilds the proof's signature base in its covered order. @method
// is the method upper-cased and @target-uri the raw URL verbatim, the bytes the
// request line carried; every other component, @authority or a header for
// example, is read the way a request signature reads it.
func popVerifyBase(method, rawURL string, h http.Header, p sigParams) (string, error) {
	var req *http.Request
	lines := make([]string, 0, len(p.Covered)+1)
	for _, c := range p.Covered {
		var value string
		switch strings.ToLower(c.Name) {
		case "@method":
			value = strings.ToUpper(method)
		case "@target-uri":
			value = rawURL
		default:
			if req == nil {
				u, err := url.Parse(rawURL)
				if err != nil {
					return "", fmt.Errorf("helpers: proof covers %q, which a URL that does not parse cannot supply: %w", c.Name, err)
				}
				req = &http.Request{Method: method, URL: u, Host: u.Host, Header: h}
			}
			v, err := componentValue(req, c)
			if err != nil {
				return "", err
			}
			value = v
		}
		lines = append(lines, renderComponent(c)+": "+value)
	}
	return strings.Join(append(lines, `"@signature-params": `+p.RawInner), "\n"), nil
}
