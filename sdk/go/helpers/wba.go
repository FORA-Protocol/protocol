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

	"github.com/FORA-Protocol/protocol/sdk/go/internal/wbadir"
	"github.com/dunglas/httpsfv"
)

// The Web Bot Auth profile of RFC 9421 request signatures, as FORA pins it:
// draft-ietf-webbotauth-httpsig-protocol-01. The authentication page's "The Web
// Bot Auth Profile" is the normative statement; this file holds the pieces of it
// the signer and the verifier share.
//
//   - Signature-Agent is a structured-field Dictionary. The member for a signature
//     is <label>="https://<host>/.well-known/http-message-signatures-directory",
//     the URL of the signer's key directory, and the signature covers it as
//     "signature-agent";key="<label>". Each signature's keyid is resolved in the
//     key directory its own covered member names, and the signer's identity is
//     that URL's host.
//   - A verifier accepts exactly that well-known URL on an https origin, and also
//     a bare https origin, which it completes to the well-known URL. Any other URL
//     (another path, a query, a fragment, another scheme) is refused. A member
//     that carries parameters is ignored (-01 §5.2.1), so a signature whose
//     covered member carries any names no directory and is refused.
//   - Every signature carries created, expires, keyid, alg="ed25519" and
//     tag="web-bot-auth"; a FORA signer adds a fresh nonce.
//   - A verifier also accepts the legacy sf-string form of Signature-Agent,
//     covered as plain "signature-agent", on a request carrying one signature, a
//     member key that differs from the label, no nonce, and no alg, when the
//     Ed25519 key decides the algorithm. An alg that is present must be ed25519.
//     It refuses the bare unquoted value the v1.0.8 SDKs sent.

// WBATag is the RFC 9421 tag parameter every Web Bot Auth request signature
// carries.
const WBATag = "web-bot-auth"

// DirectoryResponseTag is the tag a key directory's response signature carries
// (-01 Appendix B.1).
const DirectoryResponseTag = "http-message-signatures-directory"

// AcceptSignatureHeader is the RFC 9421 §5.1 field a verifier answers with when it
// refuses a signature for a missing component or a form it does not accept, naming
// what it requires (-01 §5.3).
const AcceptSignatureHeader = "Accept-Signature"

// MaxSignatureLifetime is the longest window (expires − created) a FORA signer
// gives a request signature. A signature is never a long-lived credential.
const MaxSignatureLifetime = 5 * time.Minute

// Profile errors. Each is a refusal of the signature's form; see
// AcceptSignatureFor for which of them a verifier answers with Accept-Signature.
var (
	// ErrSignatureTag signals a signature with no tag, or a tag other than
	// "web-bot-auth".
	ErrSignatureTag = errors.New("helpers: signature tag is not \"web-bot-auth\"")
	// ErrSignatureAgentForm signals a Signature-Agent the profile does not accept:
	// the bare unquoted value, a member the signature names but the dictionary does
	// not carry, a member that is not a String, a member that carries parameters
	// (ErrSignatureAgentIgnored), the legacy String form on a request carrying more
	// than one signature, or a signature covering several members none of which is
	// keyed to its label.
	ErrSignatureAgentForm = errors.New("helpers: Signature-Agent is not in a form the Web Bot Auth profile accepts")
	// ErrSignatureAgentIgnored signals that the Signature-Agent member a signature
	// covers carries parameters. Web Bot Auth -01 §5.2.1 has a verifier ignore such
	// a member, so the signature names no key directory. It wraps
	// ErrSignatureAgentForm.
	ErrSignatureAgentIgnored = fmt.Errorf("%w: the covered member carries parameters, so it is ignored",
		ErrSignatureAgentForm)
	// ErrSignatureAgentNotOrigin signals a Signature-Agent value whose scheme and
	// authority are not the ASCII serialization of an https origin:
	// https://host[:port], lowercase, with no credentials and no default port.
	// CheckHTTPSOrigin also returns it for a value that carries anything after the
	// origin.
	ErrSignatureAgentNotOrigin = errors.New("helpers: Signature-Agent is not an https origin")
	// ErrSignatureAgentNotKeyDirectory signals a Signature-Agent value that is an
	// https origin followed by something other than the well-known key directory
	// path: another path (even "/"), a query or a fragment. Web Bot Auth -01 lets
	// a key set live at any URL, but an arbitrary path does not name the host's
	// operator, and FORA identity is the host, so FORA accepts only the well-known
	// URL and the bare origin.
	ErrSignatureAgentNotKeyDirectory = errors.New(
		"helpers: Signature-Agent is not the well-known key directory URL of an https origin")
	// ErrSignatureAgentRequired signals a signing call given no Signature-Agent
	// value. Every Web Bot Auth signature names its signer's key directory.
	ErrSignatureAgentRequired = errors.New("helpers: a signature needs the signer's Signature-Agent key directory")
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
// origin, the origin a Signature-Agent key directory is served from:
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

// readKeyDirectory reads a Signature-Agent value as the key directory it names
// and returns that directory's https origin. Two values name one:
//
//   - the well-known URL https://<origin>/.well-known/http-message-signatures-directory,
//     the form Web Bot Auth -01 signers send;
//   - the bare origin https://<origin>, which FORA completes to that URL. A -01
//     verifier would fetch the origin itself, so this is part of FORA's listed
//     Signature-Agent departure. It keeps every signer that sends the origin
//     working, and it does not widen whose key verifies: the identity is the host
//     in both readings.
//
// <origin> is what CheckHTTPSOrigin accepts. A value with another scheme, or an
// authority that is not such an origin, wraps ErrSignatureAgentNotOrigin. An https
// origin followed by another path, a query or a fragment wraps
// ErrSignatureAgentNotKeyDirectory. The path is compared byte for byte, with no
// normalization.
func readKeyDirectory(value string) (string, error) {
	rest, ok := strings.CutPrefix(value, "https://")
	if !ok {
		return "", fmt.Errorf("%w: %q does not start with https://", ErrSignatureAgentNotOrigin, value)
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	origin := value[:len(value)-len(rest)+end]
	if err := CheckHTTPSOrigin(origin); err != nil {
		return "", err
	}
	switch tail := rest[end:]; {
	case tail == "" || tail == wbadir.Path:
		return origin, nil
	case strings.Contains(tail, "#"):
		return "", fmt.Errorf("%w: %q carries a fragment", ErrSignatureAgentNotKeyDirectory, value)
	case strings.Contains(tail, "?"):
		return "", fmt.Errorf("%w: %q carries a query", ErrSignatureAgentNotKeyDirectory, value)
	default:
		return "", fmt.Errorf("%w: %q names a path other than %s", ErrSignatureAgentNotKeyDirectory, value, wbadir.Path)
	}
}

// keyDirectoryURL is the URL of the key directory served from origin.
func keyDirectoryURL(origin string) string { return origin + wbadir.Path }

// signatureAgentMember renders one Signature-Agent dictionary member for label.
// value has passed readKeyDirectory, so it carries no character a String would
// have to escape.
func signatureAgentMember(label, value string) string {
	return label + `="` + value + `"`
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

// directoryFromMember reads a Signature-Agent dictionary member as the key
// directory it names and returns that directory's origin, applying the member
// rule itemDirectory states. An inner list names no directory.
func directoryFromMember(m httpsfv.Member, key string) (string, error) {
	item, ok := m.(httpsfv.Item)
	if !ok {
		return "", fmt.Errorf("%w: member %q is an inner list", ErrSignatureAgentForm, key)
	}
	return itemDirectory(item, fmt.Sprintf("member %q", key))
}

// itemDirectory is the WG-01 member rule, shared by a dictionary member and the
// legacy String, so both refuse a value with the same token. In order: an item
// that carries parameters is ignored (WG-01 §5.2.1), which leaves the signature
// covering it with no directory (ErrSignatureAgentIgnored); an item that is not a
// String is refused (ErrSignatureAgentForm); and a String must be a value
// readKeyDirectory accepts. what names the item in the error.
func itemDirectory(item httpsfv.Item, what string) (string, error) {
	if p := item.Params; p != nil && len(p.Names()) > 0 {
		return "", fmt.Errorf("%w: %s", ErrSignatureAgentIgnored, what)
	}
	value, ok := item.Value.(string)
	if !ok {
		return "", fmt.Errorf("%w: %s is not a String", ErrSignatureAgentForm, what)
	}
	return readKeyDirectory(value)
}

// legacyDirectory reads a Signature-Agent carried in the legacy form, a single
// String covered as plain "signature-agent", which WG-01 §5.2.1 lets a verifier
// treat as a one-member dictionary, so the member rule applies (itemDirectory).
// The bare unquoted value the v1.0.8 SDKs sent parses as a Token, not a String,
// and is refused.
func legacyDirectory(h http.Header) (string, error) {
	values := h.Values(SignatureAgentHeader)
	if len(values) == 0 {
		return "", &MissingComponentError{Component: signatureAgentLower}
	}
	item, err := httpsfv.UnmarshalItem([]string{strings.Join(values, ", ")})
	if err != nil {
		return "", fmt.Errorf("%w: not a String: %w", ErrSignatureAgentForm, err)
	}
	return itemDirectory(item, "the legacy form")
}

// signatureDirectory returns the origin of the key directory a signature names:
// the Signature-Agent member it covers. A signature that covers an earlier one
// also covers that signature's member (-01 §5.2.2), so the member followed is the
// one keyed to the signature's own label (-01 §5.2.1); a signature covering exactly
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
// parameters (RFC 9421 §5.1, -01 §5.3). entitlement adds x-entitlement-token,
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
// wrong tag, a Signature-Agent in a form the profile refuses (an ignored member
// among them), and a Signature-Agent value that is neither the well-known key
// directory URL nor the bare origin of an https host. Accept-Signature cannot say
// which URL FORA accepts, so the error carries that reason. It does not for a
// signature
// that is well formed and fails for any other reason: a bad signature, an unknown
// key, a stale window or a replay.
func AcceptSignatureFor(err error) (string, bool) {
	var missing *MissingComponentError
	switch {
	case errors.As(err, &missing):
		return AcceptSignature(missing.Component == entitlementHeaderLower), true
	case errors.Is(err, ErrMissingSignatureInput), errors.Is(err, ErrMissingSignature),
		errors.Is(err, ErrSignatureTag), errors.Is(err, ErrSignatureAgentForm),
		errors.Is(err, ErrSignatureAgentNotOrigin), errors.Is(err, ErrSignatureAgentNotKeyDirectory):
		return AcceptSignature(false), true
	default:
		return "", false
	}
}
