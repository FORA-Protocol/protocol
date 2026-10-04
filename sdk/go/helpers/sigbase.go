package helpers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/dunglas/httpsfv"
)

// RFC 9421 (HTTP Message Signatures) signature-base construction, shared by the
// signer (sign.go) and the verifier (verify.go). The base is the exact byte
// string both sides feed to the crypto: keeping it in one place is what makes
// sign→verify round-trip and what keeps this SDK byte-identical with the
// service-internal implementation it relocates (ADR-020 §8).
//
// Coverage is the Web Bot Auth base plus the FORA RPC set: @method and
// @target-uri (bind the verb and destination so a signature cannot be replayed
// against another path), content-digest (bind the body), authorization (bind the
// bearer so a token cannot be swapped under a signed envelope), and the
// signature's own Signature-Agent member, "signature-agent";key="<label>" (bind
// the key directory the keyid is resolved in). x-entitlement-token is bound
// additionally whenever it is present.

// ComponentParam is a single RFC 9421 §2.1 parameter on a covered-component
// identifier — e.g. the key="sig1" on `"signature-agent";key="sig1"`.
type ComponentParam struct {
	Key string
	Val string
	// Flag marks a parameter with no value, a Boolean true, such as the req on
	// "@authority";req. Val is empty when it is set.
	Flag bool
}

// CoveredComponent is one entry in a signature's covered-component set: a
// component name plus any RFC 9421 component parameters. Plain components
// (@method, content-digest, …) carry nil Params; a dictionary member selected by
// RFC 9421 §2.1.2 carries a single {Key:"key", Val:"<member>"} param — the
// signature's own "signature-agent" member, or an earlier signature's
// "signature" and "signature-input" members when a forwarder covers them.
type CoveredComponent struct {
	Name   string
	Params []ComponentParam
}

// plainComponents builds CoveredComponents with no parameters from names.
func plainComponents(names ...string) []CoveredComponent {
	out := make([]CoveredComponent, 0, len(names))
	for _, n := range names {
		out = append(out, CoveredComponent{Name: n})
	}
	return out
}

// componentParam returns the value of the named parameter on c, or "" if absent.
func componentParam(c CoveredComponent, key string) string {
	for _, p := range c.Params {
		if p.Key == key {
			return p.Val
		}
	}
	return ""
}

// renderComponent serializes a covered-component identifier as it appears in the
// Signature-Input header and the @signature-params line: `"name";k="v";…`. The
// name is rendered verbatim (callers supply already-lowercased names) so the
// header inner list and the signature-base inner list are byte-identical. For a
// param-less component this yields exactly `"name"` — byte-equal to the old
// single-label quoted string, preserving the N=1 base.
func renderComponent(c CoveredComponent) string {
	var b strings.Builder
	b.WriteByte('"')
	b.WriteString(c.Name)
	b.WriteByte('"')
	for _, p := range c.Params {
		if p.Flag {
			fmt.Fprintf(&b, ";%s", p.Key)
			continue
		}
		fmt.Fprintf(&b, ";%s=%q", p.Key, p.Val)
	}
	return b.String()
}

// sigParams captures the parameters of a single Signature-Input label.
type sigParams struct {
	Label   string
	Covered []CoveredComponent
	KeyID   string
	Alg     string
	Created int64
	Expires int64
	Nonce   string
	Tag     string
	// RawInner is the VERBATIM member value from the wire Signature-Input
	// (everything after "label="). RFC 9421 §2.5 terminates the signature base
	// with this exact byte sequence — parameter order and spacing are the
	// signer's choice — so the VERIFY path must rebuild the base from it. Empty
	// on the SIGN path, where the base and the emitted header both come from
	// signatureInputInner and are identical by construction.
	RawInner string
}

// requiredCoveredComponents is the set a FORA RPC signature must cover beyond the
// Web Bot Auth base, by name. The signature's Signature-Agent member is checked
// on its own (signatureDirectory), and the entitlement-token header is required
// conditionally (enforceEntitlementCoverage).
var requiredCoveredComponents = []string{"@method", "@target-uri", "content-digest", "authorization"}

// entitlementHeader is the canonical entitlement-token header (format-neutral —
// the token inside is a JWT/opaque capability token; its format is out of scope
// here). When present on a request the signature MUST commit to it, so an
// unsigned entitlement claim cannot be slipped under a valid signature.
const (
	entitlementHeader      = "X-Entitlement-Token"
	entitlementHeaderLower = "x-entitlement-token"
)

// entitlementValue resolves the entitlement-token header the way the header is
// defined rather than the way a map lookup is convenient: ALL field lines under
// the name, joined with ", " and outer-trimmed, exactly as componentValue
// resolves a covered name.
//
// Get would return only the FIRST line, and that is shadowable. A request may
// legally carry the name twice; an attacker who puts an empty line ahead of a
// real capability token makes Get answer "", the coverage rule below never runs,
// and the unsigned token rides in under a signature that never committed to it.
// It takes no case trick and no unusual client — two field lines is ordinary
// HTTP. Joining removes the shadow: any second line makes the value non-empty.
func entitlementValue(h http.Header) string {
	return strings.TrimSpace(strings.Join(h.Values(entitlementHeader), ", "))
}

// ContentDigest returns the RFC 9530 Content-Digest header value for body:
// sha-256=:<base64(SHA-256(body))>:.
func ContentDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
}

// coveredFor returns the covered-component set for a signature labelled label:
// the FORA RPC set, the signature's own Signature-Agent member, and the
// entitlement-token header when it is populated on req. All names are lowercase
// so the rendered byte output is preserved.
func coveredFor(req *http.Request, label string) []CoveredComponent {
	covered := append(plainComponents(requiredCoveredComponents...), signatureAgentComponent(label))
	// Read the same way the verify gate reads it. A signer resolving this with Get
	// would leave the header UNCOVERED whenever an empty line precedes a real one,
	// binding a value it never committed to — the sign-side half of the same shadow.
	if entitlementValue(req.Header) != "" {
		covered = append(covered, CoveredComponent{Name: entitlementHeaderLower})
	}
	return covered
}

// coverEarlier extends own, the covered set of a new signature, to cover the
// earlier signature prev under WG-00 §5.2.2: every component prev lists that own
// does not already cover, then "signature";key=<prev> and
// "signature-input";key=<prev>. A party may do this only when it forwards the
// request unchanged in every component prev covers.
func coverEarlier(own []CoveredComponent, prev sigParams) []CoveredComponent {
	out := append([]CoveredComponent(nil), own...)
	for _, c := range prev.Covered {
		if !coversComponent(out, c) {
			out = append(out, c)
		}
	}
	link := []ComponentParam{{Key: "key", Val: prev.Label}}
	return append(out,
		CoveredComponent{Name: "signature", Params: link},
		CoveredComponent{Name: "signature-input", Params: link})
}

// coversComponent reports whether set contains c: the same name, compared
// case-insensitively, and the same parameters in the same order.
func coversComponent(set []CoveredComponent, c CoveredComponent) bool {
	for _, s := range set {
		if sameComponent(s, c) {
			return true
		}
	}
	return false
}

func sameComponent(a, b CoveredComponent) bool {
	if !strings.EqualFold(a.Name, b.Name) || len(a.Params) != len(b.Params) {
		return false
	}
	for i := range a.Params {
		if a.Params[i] != b.Params[i] {
			return false
		}
	}
	return true
}

// buildSignatureBase assembles the RFC 9421 §2.5 signature base over the
// covered derived components (@method, @target-uri, …) and literal headers,
// terminated by the @signature-params line carrying the verbatim inner list and
// parameters. Canonical value rules per §2.4.
func buildSignatureBase(req *http.Request, params sigParams) (string, error) {
	var b bytes.Buffer
	for _, c := range params.Covered {
		v, err := componentValue(req, c)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%s: %s\n", renderComponent(c), v)
	}
	// Verify path: the base terminates with the signer's verbatim inner list
	// from the wire (RFC 9421 §2.5) — never a re-rendering in our own parameter
	// order. Sign path: RawInner is empty and the rendered inner is what gets
	// emitted in Signature-Input, so base and header stay identical.
	inner := params.RawInner
	if inner == "" {
		inner = signatureInputInner(params)
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", inner)
	return b.String(), nil
}

// signatureInputInner renders the structured-field inner list + parameter tail,
// the exact value used both inside @signature-params and as the Signature-Input
// header body.
func signatureInputInner(p sigParams) string {
	return "(" + quotedList(p.Covered) + ")" + renderParamsTail(p)
}

func quotedList(items []CoveredComponent) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, renderComponent(it))
	}
	return strings.Join(parts, " ")
}

// renderParamsTail renders the signature parameters in the order the Web Bot Auth
// profile's examples use: created, expires, keyid, alg, nonce, tag. The order is
// the signer's choice (a verifier rebuilds the base from the parameters as
// received), and the three SDKs make the same one so their signatures agree byte
// for byte.
func renderParamsTail(p sigParams) string {
	var b strings.Builder
	if p.Created != 0 {
		fmt.Fprintf(&b, ";created=%d", p.Created)
	}
	if p.Expires != 0 {
		fmt.Fprintf(&b, ";expires=%d", p.Expires)
	}
	if p.KeyID != "" {
		fmt.Fprintf(&b, ";keyid=%q", p.KeyID)
	}
	if p.Alg != "" {
		fmt.Fprintf(&b, ";alg=%q", p.Alg)
	}
	if p.Nonce != "" {
		fmt.Fprintf(&b, ";nonce=\"%s\"", p.Nonce)
	}
	if p.Tag != "" {
		fmt.Fprintf(&b, ";tag=%q", p.Tag)
	}
	return b.String()
}

// componentValue yields the canonicalized value for a covered component:
// @method, @path, @authority, @target-uri, a dictionary member a "key" parameter
// selects (RFC 9421 §2.1.2), or any literal request header.
func componentValue(req *http.Request, c CoveredComponent) (string, error) {
	if len(c.Params) > 0 {
		return memberValue(req, c)
	}
	switch strings.ToLower(c.Name) {
	case "@method":
		return strings.ToUpper(req.Method), nil
	case "@path":
		if req.URL == nil {
			return "", fmt.Errorf("helpers: request URL unset for @path")
		}
		p := req.URL.Path
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@authority":
		auth := req.Host
		if auth == "" && req.URL != nil {
			auth = req.URL.Host
		}
		return strings.ToLower(auth), nil
	case "@target-uri":
		if req.URL == nil {
			return "", fmt.Errorf("helpers: request URL unset for @target-uri")
		}
		return reconstructTargetURI(req), nil
	default:
		// Values (not Get) so an explicitly-set empty header (bound
		// intentionally) is distinguished from an absent one.
		values := req.Header.Values(http.CanonicalHeaderKey(c.Name))
		if len(values) == 0 {
			return "", fmt.Errorf("helpers: header %q missing from request", c.Name)
		}
		return strings.TrimSpace(strings.Join(values, ", ")), nil
	}
}

// memberValue resolves a header component carrying a "key" parameter to the
// canonical structured-field serialization of the dictionary member it names
// (RFC 9421 §2.1.2): the String of a Signature-Agent member with its parameters,
// the byte sequence of a Signature member, the inner list of a Signature-Input
// member. Serializing the parsed member, rather than splicing the wire substring,
// makes signer and verifier agree byte for byte however the member was spaced on
// the wire. No other component parameter is supported.
func memberValue(req *http.Request, c CoveredComponent) (string, error) {
	if strings.HasPrefix(c.Name, "@") || len(c.Params) != 1 || c.Params[0].Key != "key" || c.Params[0].Flag {
		return "", fmt.Errorf("%w: unsupported component parameters on %q", ErrMalformedSignatureInput, c.Name)
	}
	key := c.Params[0].Val
	values := req.Header.Values(http.CanonicalHeaderKey(c.Name))
	if len(values) == 0 {
		return "", fmt.Errorf("helpers: header %q missing from request", c.Name)
	}
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return "", fmt.Errorf("%w: %s is not a dictionary: %w", ErrMalformedSignatureInput, c.Name, err)
	}
	member, ok := dict.Get(key)
	if !ok {
		return "", fmt.Errorf("%w: %s has no member %q", ErrMalformedSignatureInput, c.Name, key)
	}
	out, err := httpsfv.Marshal(member)
	if err != nil {
		return "", fmt.Errorf("%w: serialize %s member %q: %w", ErrMalformedSignatureInput, c.Name, key, err)
	}
	return out, nil
}

// reconstructTargetURI builds an absolute-form target URI from either an
// outbound request (URL.Scheme/Host set) or an inbound one (Host + TLS), so the
// same helper produces an identical value on both client and server sides.
func reconstructTargetURI(req *http.Request) string {
	scheme := req.URL.Scheme
	if scheme == "" {
		if req.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	path := req.URL.Path
	if path == "" {
		path = "/"
	}
	if raw := req.URL.RawQuery; raw != "" {
		return scheme + "://" + host + path + "?" + raw
	}
	return scheme + "://" + host + path
}
