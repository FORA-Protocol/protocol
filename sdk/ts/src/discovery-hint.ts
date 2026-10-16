// The edge discovery headers: what a publisher's edge tells an unlicensed agent
// when it refuses it. TS port of the sdk/go oracle (helpers/discoveryhint.go).
//
// A publisher's edge answers a request for licensed content that carries no valid
// signed delivery URL with 403. That answer carries up to two headers, specified
// under "Edge discovery headers" in the fora.proto file header:
//
//   X-Content-Rules: https://publisher.example/.well-known/fora.json
//   X-FORA-Exchange: exchange.example
//
// X-Content-Rules points at the publisher's manifest, which is the authority on
// the licensing terms and on which Exchanges sell the content. X-FORA-Exchange
// names one Exchange that sells it directly, so an agent can start discovery there
// without reading the manifest first. The second is an optimisation over the first
// and never a replacement for it.
//
// parseDiscoveryHint reads the two headers off a response and checks each value's
// shape. reconcileDiscoveryHint compares the hinted Exchange with the Exchanges the
// manifest lists, once the agent has read it. Neither dials anything: fetching the
// manifest, and resolving the Exchange's endpoint from the Exchange's own manifest,
// are the resolvers' job. The header names an Exchange; it never supplies the
// address to dial.
//
// Pure string work, no IO. Pinned to the Go oracle by the shared corpus at
// sdk/go/helpers/testdata/discovery-hint-vectors.json.

import { checkAudience, isBareDomain } from "./hosts.ts";
import { ContentRulesHeader, ExchangeHeader, WellKnownPath } from "./wire.ts";

/**
 * What parseDiscoveryHint found in one discovery header. The tokens are the Go
 * `HintState.String()` vocabulary verbatim.
 *
 * `absent`: the header was not sent, or the response was not a 403, where the
 * headers carry no meaning. `valid`: one value of the shape the protocol defines.
 * `malformed`: sent, but not of that shape, or sent more than once. An agent
 * ignores a malformed header as if it were absent; it is reported apart so a
 * caller can log an edge that is misconfigured.
 */
export type HintState = "absent" | "valid" | "malformed";

/**
 * The outcome of comparing a hint's Exchange with the Exchanges the publisher's
 * manifest lists. The tokens are the Go `HintAgreement.String()` vocabulary.
 *
 * `no_exchange`: the hint names no usable Exchange, so there is nothing to
 * reconcile. `listed`: the manifest lists it. `unlisted`: it does not, and the
 * manifest wins — the agent discards the hint, does not transact on an offer from
 * that Exchange, and discovers at the Exchanges the manifest lists.
 */
export type HintAgreement = "no_exchange" | "listed" | "unlisted";

/**
 * The typed reading of a 403's discovery headers.
 *
 * `contentRules` and `exchange` hold the header values, with surrounding spaces
 * and tabs removed, only when their state is `valid`; otherwise they are
 * undefined. `exchange` is kept exactly as sent apart from that trimming. Compare
 * it with another domain through reconcileDiscoveryHint or checkAudience, which
 * fold case and an explicit `:443`, never with `===`.
 */
export interface DiscoveryHint {
	readonly contentRules: string | undefined;
	readonly contentRulesState: HintState;
	readonly exchange: string | undefined;
	readonly exchangeState: HintState;
}

/**
 * The headers parseDiscoveryHint reads: anything with a case-insensitive `get`
 * that answers null for an absent header — a fetch `Headers`, or the `headers` of
 * this SDK's resolver FetchResponse. A fetch `Headers` joins a repeated header's
 * lines with ", " on read, which the rule below refuses.
 */
export interface HeaderReader {
	get(name: string): string | null;
}

const FORBIDDEN = 403;

/**
 * parseDiscoveryHint reads the X-Content-Rules and X-FORA-Exchange headers of a
 * response with the given HTTP status.
 *
 * The headers carry meaning only on a 403. For any other status both states are
 * `absent`, whatever the headers hold. Each header is checked on its own, so a
 * malformed X-FORA-Exchange does not discard a valid X-Content-Rules, and the
 * other way round.
 *
 * X-Content-Rules is valid when it is exactly `https://` or `http://`, then a bare
 * domain (isBareDomain, a port allowed), then WellKnownPath, with nothing after
 * it: no userinfo, query, fragment or trailing slash. The http scheme is admitted
 * because whether a leg may run in plaintext is the guarded transport's decision,
 * not a shape question; the guarded fetch refuses it unless plaintext is enabled.
 * X-FORA-Exchange is valid when it is a bare domain, the same shape as
 * Offer.exchange.
 *
 * A header sent more than once is malformed: its lines arrive joined with ", ",
 * and a comma can appear in neither shape.
 */
export function parseDiscoveryHint(status: number, headers: HeaderReader): DiscoveryHint {
	if (status !== FORBIDDEN) {
		return { contentRules: undefined, contentRulesState: "absent", exchange: undefined, exchangeState: "absent" };
	}
	const [contentRules, contentRulesState] = judge(headerValue(headers, ContentRulesHeader), isContentRulesURL);
	const [exchange, exchangeState] = judge(headerValue(headers, ExchangeHeader), isBareDomain);
	return { contentRules, contentRulesState, exchange, exchangeState };
}

/**
 * reconcileDiscoveryHint reports whether the publisher's manifest lists the
 * Exchange the hint names.
 *
 * `listed` holds the domain of every entry in the publisher manifest's
 * WellKnownManifest.exchanges. The comparison is the identity match the protocol
 * uses for a request's recipient, checkAudience: exact domain, case folded, an
 * explicit `:443` the same as no port, and a subdomain a different party. A listed
 * value that is not a bare domain names nobody and matches nothing.
 *
 * The hint is never authorization. `listed` says the two sources agree, not that
 * the Exchange's offers can be trusted: those are verified by their own
 * signatures, as on every other path.
 */
export function reconcileDiscoveryHint(hint: DiscoveryHint, listed: Iterable<string>): HintAgreement {
	if (hint.exchangeState !== "valid" || hint.exchange === undefined) {
		return "no_exchange";
	}
	for (const domain of listed) {
		if (isBareDomain(domain) && checkAudience(domain, hint.exchange) === "accepted") {
			return "listed";
		}
	}
	return "unlisted";
}

function judge(value: string | undefined, valid: (v: string) => boolean): [string | undefined, HintState] {
	if (value === undefined) {
		return [undefined, "absent"];
	}
	return valid(value) ? [value, "valid"] : [undefined, "malformed"];
}

// headerValue is the named header's value with spaces and tabs trimmed from both
// ends, or undefined when the header is absent. A fetch Headers already trims and
// joins repeated lines; trimming again is what makes a hand-written reader agree.
function headerValue(headers: HeaderReader, name: string): string | undefined {
	const v = headers.get(name);
	return v === null ? undefined : v.replace(/^[ \t]+|[ \t]+$/g, "");
}

// isContentRulesURL is string work rather than a URL parse on purpose: the three
// languages' URL parsers disagree on edge cases (a backslash, an empty port,
// percent-encoding in the host), and a fixed shape with no optional parts leaves
// nothing for them to disagree about.
function isContentRulesURL(v: string): boolean {
	let rest: string;
	if (v.startsWith("https://")) {
		rest = v.slice("https://".length);
	} else if (v.startsWith("http://")) {
		rest = v.slice("http://".length);
	} else {
		return false;
	}
	if (!rest.endsWith(WellKnownPath)) {
		return false;
	}
	return isBareDomain(rest.slice(0, rest.length - WellKnownPath.length));
}
