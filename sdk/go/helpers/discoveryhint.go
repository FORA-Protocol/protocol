package helpers

import (
	"fmt"
	"net/http"
	"strings"
)

// The edge discovery headers: what a publisher's edge tells an unlicensed agent
// when it refuses it.
//
// A publisher's edge answers a request for licensed content that carries no
// valid signed delivery URL with 403. That answer carries up to two headers,
// specified under "Edge discovery headers" in the fora.proto file header:
//
//	X-Content-Rules: https://publisher.example/.well-known/fora.json
//	X-FORA-Exchange: exchange.example
//
// X-Content-Rules points at the publisher's manifest, which is the authority on
// the licensing terms and on which Exchanges sell the content. X-FORA-Exchange
// names one Exchange that sells it directly, so an agent can start discovery
// there without reading the manifest first. The second is an optimisation over
// the first and never a replacement for it.
//
// Two pure functions live here. ParseDiscoveryHint reads the two headers off a
// response and checks each value's shape. ReconcileDiscoveryHint compares the
// hinted Exchange with the Exchanges the manifest lists, once the agent has
// read it. Neither dials anything: fetching the manifest, and resolving the
// Exchange's endpoint from the Exchange's own manifest, are the resolvers' job.
// The header names an Exchange; it never supplies the address to dial.
//
// The three SDKs answer identically, pinned by the shared corpus
// testdata/discovery-hint-vectors.json.

// HintState is what ParseDiscoveryHint found in one discovery header.
type HintState int

const (
	// HintAbsent means the header was not sent, or the response was not a 403,
	// where the headers carry no meaning. It is the zero value, so a hint nobody
	// filled in reads as "nothing to act on".
	HintAbsent HintState = iota

	// HintValid means the header carried one value of the shape the protocol
	// defines for it.
	HintValid

	// HintMalformed means the header was sent but its value is not of that
	// shape: an X-Content-Rules that is not the absolute URL of a fora.json, an
	// X-FORA-Exchange that is not a bare domain, or either header sent more
	// than once. An agent ignores a malformed header as if it were absent. It
	// is reported apart from absent so a caller can log an edge that is
	// misconfigured.
	HintMalformed
)

// String renders the state as the stable token the shared vectors record.
func (s HintState) String() string {
	switch s {
	case HintAbsent:
		return "absent"
	case HintValid:
		return "valid"
	case HintMalformed:
		return "malformed"
	default:
		return fmt.Sprintf("HintState(%d)", int(s))
	}
}

// DiscoveryHint is the typed reading of a 403's discovery headers.
//
// ContentRules and Exchange hold the header values, with surrounding spaces and
// tabs removed, only when their state is HintValid; otherwise they are empty.
// Exchange is kept exactly as sent apart from that trimming. Compare it with
// another domain through ReconcileDiscoveryHint or CheckAudience, which fold
// case and an explicit ":443", never with ==.
type DiscoveryHint struct {
	ContentRules      string
	ContentRulesState HintState
	Exchange          string
	ExchangeState     HintState
}

// ParseDiscoveryHint reads the X-Content-Rules and X-FORA-Exchange headers of a
// response with the given HTTP status.
//
// The headers carry meaning only on a 403. For any other status both states are
// HintAbsent, whatever the headers hold. Each header is checked on its own, so
// a malformed X-FORA-Exchange does not discard a valid X-Content-Rules, and the
// other way round.
//
// X-Content-Rules is valid when it is exactly "https://" or "http://", then a
// bare domain (IsBareDomain, a port allowed), then WellKnownPath, with nothing
// after it: no userinfo, query, fragment or trailing slash. The http scheme is
// admitted here because whether a leg may run in plaintext is the guarded
// transport's decision, not a shape question; the guarded clients refuse it
// unless plaintext is enabled. X-FORA-Exchange is valid when it is a bare
// domain, the same shape as Offer.exchange.
//
// A header sent more than once is malformed. Header lines are joined with ", "
// before the check, and a comma can appear in neither shape, so a repeated
// header fails the check the same way in every language, including the ones
// whose header types join repeated lines on read.
func ParseDiscoveryHint(status int, h http.Header) DiscoveryHint {
	if status != http.StatusForbidden {
		return DiscoveryHint{}
	}
	var hint DiscoveryHint
	if v, ok := headerValue(h, ContentRulesHeader); ok {
		hint.ContentRulesState = HintMalformed
		if isContentRulesURL(v) {
			hint.ContentRules, hint.ContentRulesState = v, HintValid
		}
	}
	if v, ok := headerValue(h, ExchangeHeader); ok {
		hint.ExchangeState = HintMalformed
		if IsBareDomain(v) {
			hint.Exchange, hint.ExchangeState = v, HintValid
		}
	}
	return hint
}

// headerValue returns every line of the named header joined with ", ", with
// spaces and tabs trimmed from both ends, and whether the header was present at
// all. The lookup is case-insensitive because http.Header.Values canonicalises
// the name.
func headerValue(h http.Header, name string) (string, bool) {
	vals := h.Values(name)
	if len(vals) == 0 {
		return "", false
	}
	return strings.Trim(strings.Join(vals, ", "), " \t"), true
}

// isContentRulesURL reports whether v is the absolute URL of a FORA manifest:
// a lowercase http or https scheme, a bare domain, and WellKnownPath. It is
// string work rather than a URL parse on purpose: the three languages' URL
// parsers disagree on edge cases (a backslash, an empty port, percent-encoding
// in the host), and a fixed shape with no optional parts leaves nothing for
// them to disagree about.
func isContentRulesURL(v string) bool {
	rest, ok := strings.CutPrefix(v, "https://")
	if !ok {
		if rest, ok = strings.CutPrefix(v, "http://"); !ok {
			return false
		}
	}
	host, ok := strings.CutSuffix(rest, WellKnownPath)
	return ok && IsBareDomain(host)
}

// HintAgreement is the outcome of comparing a hint's Exchange with the
// Exchanges the publisher's manifest lists.
type HintAgreement int

const (
	// HintNoExchange means the hint names no usable Exchange: the header was
	// absent or malformed. There is nothing to reconcile, and the agent uses
	// the manifest's Exchanges.
	HintNoExchange HintAgreement = iota

	// HintListed means the manifest lists the hinted Exchange. The hint and the
	// authority agree.
	HintListed

	// HintUnlisted means the manifest does not list the hinted Exchange. The
	// manifest wins: the agent discards the hint, does not transact on an offer
	// from that Exchange, and discovers at the Exchanges the manifest lists.
	HintUnlisted
)

// String renders the agreement as the stable token the shared vectors record.
func (a HintAgreement) String() string {
	switch a {
	case HintNoExchange:
		return "no_exchange"
	case HintListed:
		return "listed"
	case HintUnlisted:
		return "unlisted"
	default:
		return fmt.Sprintf("HintAgreement(%d)", int(a))
	}
}

// ReconcileDiscoveryHint reports whether the publisher's manifest lists the
// Exchange the hint names.
//
// listed holds the domain of every entry in the publisher manifest's
// WellKnownManifest.exchanges. The comparison is the identity match the
// protocol uses for a request's recipient, CheckAudience: exact domain, case
// folded, an explicit ":443" the same as no port, and a subdomain a different
// party. A listed value that is not a bare domain names nobody and matches
// nothing.
//
// The hint is never authorization. HintListed says the two sources agree, not
// that the Exchange's offers can be trusted: those are verified by their own
// signatures, as on every other path.
func ReconcileDiscoveryHint(hint DiscoveryHint, listed []string) HintAgreement {
	if hint.ExchangeState != HintValid {
		return HintNoExchange
	}
	for _, d := range listed {
		if !IsBareDomain(d) {
			continue
		}
		if v, err := CheckAudience(d, hint.Exchange); err == nil && v == AudienceAccepted {
			return HintListed
		}
	}
	return HintUnlisted
}
