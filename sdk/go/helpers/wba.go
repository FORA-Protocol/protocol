package helpers

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
)

// The Web Bot Auth profile of RFC 9421 request signatures, as FORA pins it:
// draft-ietf-webbotauth-httpsig-protocol-00 ("WG-00"). The authentication page's
// "The Web Bot Auth Profile" is the normative statement; this file holds the pieces
// of it the signer and the verifier share.
//
//   - Signature-Agent is a structured-field Dictionary. The member for a signature
//     is <label>="https://<origin>", and the signature covers it as
//     "signature-agent";key="<label>". Each signature's keyid is resolved in the
//     key directory its own covered member names.
//   - Every signature carries created, expires, keyid, alg="ed25519" and
//     tag="web-bot-auth"; a FORA signer adds a fresh nonce.
//   - A verifier also accepts the legacy sf-string form of Signature-Agent,
//     covered as plain "signature-agent", on a request carrying one signature, a
//     member key that differs from the label, no nonce, and a type=directory member
//     parameter. It refuses the bare unquoted value the v1.0.8 SDKs sent.

// WBATag is the RFC 9421 tag parameter every Web Bot Auth request signature
// carries.
const WBATag = "web-bot-auth"

// DirectoryResponseTag is the tag a key directory's response signature carries
// (WG-00 Appendix B.1).
const DirectoryResponseTag = "http-message-signatures-directory"

// AcceptSignatureHeader is the RFC 9421 §5.1 field a verifier answers with when it
// refuses a signature for a missing component or a form it does not accept, naming
// what it requires (WG-00 §5.3).
const AcceptSignatureHeader = "Accept-Signature"

// MaxSignatureLifetime is the longest window (expires − created) a FORA signer
// gives a request signature. A signature is never a long-lived credential.
const MaxSignatureLifetime = 5 * time.Minute

// directoryTypeParam is the only value of a Signature-Agent member's type
// parameter that names a key directory. A member with any other type is ignored.
const directoryTypeParam = "directory"

// Profile errors. Each is a refusal of the signature's form; see
// AcceptSignatureFor for which of them a verifier answers with Accept-Signature.
var (
	// ErrSignatureTag signals a signature with no tag, or a tag other than
	// "web-bot-auth".
	ErrSignatureTag = errors.New("helpers: signature tag is not \"web-bot-auth\"")
	// ErrSignatureAgentForm signals a Signature-Agent the profile does not accept:
	// the bare unquoted value, a member the signature names but the dictionary does
	// not carry, a member that is not a String or whose type is not directory, the
	// legacy String form on a request carrying more than one signature, or a
	// signature covering several members none of which is keyed to its label.
	ErrSignatureAgentForm = errors.New("helpers: Signature-Agent is not in a form the Web Bot Auth profile accepts")
	// ErrSignatureAgentNotOrigin signals a Signature-Agent value that is not the
	// ASCII serialization of an https origin: https://host[:port], lowercase, with
	// no path, query, fragment or credentials and no default port.
	ErrSignatureAgentNotOrigin = errors.New("helpers: Signature-Agent is not an https origin")
	// ErrSignatureAgentRequired signals a signing call given no Signature-Agent
	// origin. Every Web Bot Auth signature names its signer's key directory.
	ErrSignatureAgentRequired = errors.New("helpers: a signature needs the signer's Signature-Agent origin")
	// ErrSignatureLabel signals a signature label that is not a structured-field
	// key, or one already used by a signature or a Signature-Agent member on the
	// request.
	ErrSignatureLabel = errors.New("helpers: signature label is not a free structured-field key")
	// ErrSignatureLifetime signals a signing window that is not positive or longer
	// than MaxSignatureLifetime.
	ErrSignatureLifetime = errors.New("helpers: signature lifetime must be positive and at most 5 minutes")
)

// MissingComponentError is the refusal of a signature that does not cover a
// component the route requires. errors.Is matches it against
// ErrMissingRequiredComponent.
type MissingComponentError struct {
	// Component is the lowercase name of the component the signature omits.
	Component string
}

func (e *MissingComponentError) Error() string {
	return ErrMissingRequiredComponent.Error() + ": " + e.Component
}

// Is reports ErrMissingRequiredComponent as the sentinel this error stands for.
func (e *MissingComponentError) Is(target error) bool { return target == ErrMissingRequiredComponent }

// CheckHTTPSOrigin reports whether s is the ASCII serialization of an https
// origin, the only value a Signature-Agent member carries in this profile:
// "https://" followed by a lowercase host (an IP literal allowed, an IPv6 one in
// brackets) and, only when it is not 443, ":port". Anything else wraps
// ErrSignatureAgentNotOrigin: another scheme, uppercase, a path (even "/"), a
// query, a fragment, credentials, or a non-ASCII host, which an origin carries
// punycoded.
func CheckHTTPSOrigin(s string) error {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok {
		return fmt.Errorf("%w: %q does not start with https://", ErrSignatureAgentNotOrigin, s)
	}
	if rest == "" || strings.ContainsAny(rest, "/?#@\\%") {
		return fmt.Errorf("%w: %q carries more than a host and port", ErrSignatureAgentNotOrigin, s)
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; c >= 0x80 || c < 0x21 || (c >= 'A' && c <= 'Z') {
			return fmt.Errorf("%w: %q is not a lowercase ASCII origin", ErrSignatureAgentNotOrigin, s)
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Host != rest || u.Hostname() == "" {
		return fmt.Errorf("%w: %q is not a host[:port]", ErrSignatureAgentNotOrigin, s)
	}
	host := u.Hostname()
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return fmt.Errorf("%w: %q is not a host[:port]", ErrSignatureAgentNotOrigin, s)
	}
	if !strings.Contains(host, ":") && !isOriginHostName(host) {
		return fmt.Errorf("%w: %q is not a host[:port]", ErrSignatureAgentNotOrigin, s)
	}
	if port := u.Port(); port != "" || strings.HasSuffix(rest, ":") {
		n, perr := strconv.ParseUint(port, 10, 16)
		if perr != nil || n == 0 || port[0] == '0' {
			return fmt.Errorf("%w: %q carries an invalid port", ErrSignatureAgentNotOrigin, s)
		}
		if n == 443 {
			return fmt.Errorf("%w: %q spells out the default port", ErrSignatureAgentNotOrigin, s)
		}
	}
	return nil
}

// isOriginHostName reports whether name is a lowercase registered name or IPv4
// literal: letters, digits, '-', '.' and '_' only, with no empty label.
func isOriginHostName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return false
		}
	}
	return true
}

// validLabel reports whether label is a structured-field key (RFC 8941 §3.1.2):
// lowercase letter or '*' first, then lowercase letters, digits, '_', '-', '.' or
// '*'.
func validLabel(label string) bool {
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= 'a' && c <= 'z', c == '*':
		case i > 0 && ((c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// signatureAgentMember renders one Signature-Agent dictionary member for label.
// origin has passed CheckHTTPSOrigin, so it carries no character a String would
// have to escape.
func signatureAgentMember(label, origin string) string {
	return label + `="` + origin + `"`
}

// signatureAgentComponent is the covered-component identifier that binds a
// signature to its own Signature-Agent member.
func signatureAgentComponent(label string) CoveredComponent {
	return CoveredComponent{Name: signatureAgentLower, Params: []ComponentParam{{Key: "key", Val: label}}}
}

// usedLabels collects every label already present on the request: the members of
// Signature-Input and Signature, and the keys of a Signature-Agent dictionary. A
// new signature takes a label none of them uses, so its Signature-Agent member
// cannot collide with another signature's.
func usedLabels(h http.Header) map[string]bool {
	used := map[string]bool{}
	for _, name := range []string{"Signature-Input", "Signature", SignatureAgentHeader} {
		values := h.Values(name)
		if len(values) == 0 {
			continue
		}
		dict, err := httpsfv.UnmarshalDictionary(values)
		if err != nil {
			continue
		}
		for _, k := range dict.Names() {
			used[k] = true
		}
	}
	return used
}

// nextFreeLabel returns "sigN" for the smallest N >= 1 no label on the request
// uses.
func nextFreeLabel(h http.Header) string {
	used := usedLabels(h)
	for n := 1; ; n++ {
		if l := "sig" + strconv.Itoa(n); !used[l] {
			return l
		}
	}
}

// signatureAgentDictionary parses the request's Signature-Agent as a Dictionary,
// joining repeated field lines the way the signature base does. An absent header
// is an empty dictionary.
func signatureAgentDictionary(h http.Header) (*httpsfv.Dictionary, error) {
	values := h.Values(SignatureAgentHeader)
	if strings.TrimSpace(strings.Join(values, ", ")) == "" {
		return httpsfv.NewDictionary(), nil
	}
	dict, err := httpsfv.UnmarshalDictionary(values)
	if err != nil {
		return nil, fmt.Errorf("%w: not a dictionary: %w", ErrSignatureAgentForm, err)
	}
	return dict, nil
}

// directoryFromMember reads a Signature-Agent dictionary member as the origin of a
// key directory. The member must be a String; a type parameter, when present,
// must be directory, since WG-00 §5.2.1 has a verifier ignore a member of any other
// type. The value must be an https origin.
func directoryFromMember(m httpsfv.Member, key string) (string, error) {
	item, ok := m.(httpsfv.Item)
	if !ok {
		return "", fmt.Errorf("%w: member %q is an inner list", ErrSignatureAgentForm, key)
	}
	origin, ok := item.Value.(string)
	if !ok {
		return "", fmt.Errorf("%w: member %q is not a String", ErrSignatureAgentForm, key)
	}
	if item.Params != nil {
		if v, has := item.Params.Get("type"); has && !isDirectoryType(v) {
			return "", fmt.Errorf("%w: member %q has a type other than directory", ErrSignatureAgentForm, key)
		}
	}
	if err := CheckHTTPSOrigin(origin); err != nil {
		return "", err
	}
	return origin, nil
}

func isDirectoryType(v any) bool {
	switch t := v.(type) {
	case string:
		return t == directoryTypeParam
	case httpsfv.Token:
		return string(t) == directoryTypeParam
	default:
		return false
	}
}

// legacyDirectory reads a Signature-Agent carried in the legacy form, a single
// String covered as plain "signature-agent". The bare unquoted value the v1.0.8
// SDKs sent parses as a Token, not a String, and is refused.
func legacyDirectory(h http.Header) (string, error) {
	values := h.Values(SignatureAgentHeader)
	if len(values) == 0 {
		return "", &MissingComponentError{Component: signatureAgentLower}
	}
	item, err := httpsfv.UnmarshalItem([]string{strings.Join(values, ", ")})
	if err != nil {
		return "", fmt.Errorf("%w: not a String: %w", ErrSignatureAgentForm, err)
	}
	origin, ok := item.Value.(string)
	if !ok {
		return "", fmt.Errorf("%w: the legacy form must be a quoted String", ErrSignatureAgentForm)
	}
	if err := CheckHTTPSOrigin(origin); err != nil {
		return "", err
	}
	return origin, nil
}

// signatureDirectory returns the key-directory origin a signature names: the
// Signature-Agent member it covers. A signature that covers an earlier one also
// covers that signature's member (WG-00 §5.2.2), so the member followed is the one
// keyed to the signature's own label (WG-00 §5.2.1); a signature covering exactly
// one member follows that one, whatever its key, because the profile accepts a
// member key that differs from the label. A signature covering several members,
// none keyed to its label, names no directory and is refused. sigCount is the
// number of signatures on the request, because the legacy String form, covered as
// plain "signature-agent", is accepted only when there is one.
func signatureDirectory(h http.Header, p sigParams, sigCount int) (string, error) {
	var keyed []string
	plain := 0
	for _, c := range p.Covered {
		if !strings.EqualFold(c.Name, signatureAgentLower) {
			continue
		}
		key := componentParam(c, "key")
		switch {
		case key != "" && len(c.Params) == 1:
			keyed = append(keyed, key)
		case len(c.Params) == 0:
			plain++
		default:
			return "", fmt.Errorf("%w: unsupported parameter on the signature-agent component", ErrSignatureAgentForm)
		}
	}
	switch {
	case plain == 0 && len(keyed) == 0:
		return "", &MissingComponentError{Component: signatureAgentLower}
	case plain > 0 && (plain > 1 || len(keyed) > 0):
		return "", fmt.Errorf("%w: the signature covers Signature-Agent in more than one form", ErrSignatureAgentForm)
	case plain == 1:
		if sigCount > 1 {
			return "", fmt.Errorf("%w: the legacy String form is accepted only on a request carrying one signature",
				ErrSignatureAgentForm)
		}
		return legacyDirectory(h)
	}
	key := keyed[0]
	if len(keyed) > 1 {
		key = ""
		for _, k := range keyed {
			if k == p.Label {
				key = k
			}
		}
		if key == "" {
			return "", fmt.Errorf("%w: %s covers several Signature-Agent members and none keyed to its label",
				ErrSignatureAgentForm, p.Label)
		}
	}
	if len(h.Values(SignatureAgentHeader)) == 0 {
		return "", &MissingComponentError{Component: signatureAgentLower}
	}
	dict, err := signatureAgentDictionary(h)
	if err != nil {
		return "", err
	}
	member, ok := dict.Get(key)
	if !ok {
		return "", fmt.Errorf("%w: no member %q", ErrSignatureAgentForm, key)
	}
	return directoryFromMember(member, key)
}

// AcceptSignature renders the Accept-Signature value a FORA verifier answers a
// refused RPC signature with: the components a FORA RPC signature must cover, the
// dictionary form of Signature-Agent, and the created, expires and tag
// parameters (RFC 9421 §5.1, WG-00 §5.3). entitlement adds x-entitlement-token,
// for a request carrying that header.
func AcceptSignature(entitlement bool) string {
	covered := append(plainComponents("@method", "@target-uri", "content-digest", "authorization"),
		signatureAgentComponent("sig1"))
	if entitlement {
		covered = append(covered, CoveredComponent{Name: entitlementHeaderLower})
	}
	return "sig1=(" + quotedList(covered) + `);created;expires;tag="` + WBATag + `"`
}

// AcceptSignatureFor returns the Accept-Signature value a verifier answers err
// with, and whether it answers with one at all. It does for every refusal the
// client can fix by signing again as the profile requires: a request carrying no
// signature, a signature that omits a required component, a signature with the
// wrong tag, a Signature-Agent in a form the profile refuses, and a
// Signature-Agent member that is not an https origin. It does not for a signature
// that is well formed and fails for any other reason: a bad signature, an unknown
// key, a stale window or a replay.
func AcceptSignatureFor(err error) (string, bool) {
	var missing *MissingComponentError
	switch {
	case errors.As(err, &missing):
		return AcceptSignature(missing.Component == entitlementHeaderLower), true
	case errors.Is(err, ErrMissingSignatureInput), errors.Is(err, ErrMissingSignature),
		errors.Is(err, ErrSignatureTag), errors.Is(err, ErrSignatureAgentForm),
		errors.Is(err, ErrSignatureAgentNotOrigin):
		return AcceptSignature(false), true
	default:
		return "", false
	}
}
