// The uses this page offers, and their labels.
//
// The page offers a deliberately narrow set: the three a publisher weighs up
// first. The protocol's function axis is much wider, and the preview service
// accepts more than these, so this list is a product choice rather than the
// vocabulary itself. terms-vocab.guard.mjs checks at build time that every
// token here is registered on the proto function axis, so the choice can
// narrow the vocabulary but never invent a token.

/** The use tokens the controls offer, in the order they are shown. */
export const OFFERED_USES = ['search', 'ai-input', 'ai-train'];

/**
 * What a use token is called in the page's own words.
 *
 * Wider than OFFERED_USES on purpose: the controls offer three, but an offer
 * coming back from the Exchange can name any token the service refused or
 * permitted on the publisher's behalf, and every one of them has to read as
 * English rather than as a token. Each key is checked against the proto
 * function axis by terms-vocab.guard.mjs.
 */
export const USE_LABELS = {
	'search': 'Search',
	'ai-input': 'AI input',
	'ai-index': 'AI index',
	'ai-train': 'AI training',
	'crawl': 'Crawl',
};

/**
 * Split the offered uses into what the visitor permitted and what they did
 * not. Every offered token lands in exactly one list, so the two can never
 * overlap and an unchecked use is refused rather than left unsaid.
 */
export function partitionUses(isPermitted) {
	const functions = OFFERED_USES.filter((token) => isPermitted(token));
	const prohibited = OFFERED_USES.filter((token) => !isPermitted(token));
	return { functions, prohibited };
}
