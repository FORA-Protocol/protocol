import { cdnName } from './cdn-integrations.mjs';

/** Why the page could not be read, in the visitor's words. */
const UNREADABLE_REASONS = {
	bot_protection: (cdn) => `${cdn || 'The network in front of your site'} blocked our request as automated traffic`,
	refused: (cdn) => `${cdn || 'The network in front of your site'} refused our request`,
	not_found: () => 'Your site answered that the page does not exist',
	server_error: () => 'Your site answered with a server error',
	unexpected_status: () => 'Your site answered with an unexpected response',
};
/** Reasons a retry cannot change; the note must not suggest one. */
const BLOCKED_REASONS = new Set(['bot_protection', 'refused']);

/**
 * One sentence on why the page was not read. `unreadable` is the service's
 * `{ reason, status }`; `provider` is the detected CDN token. Pure.
 */
export function unreadableNote(unreadable, provider) {
	const reason = String(unreadable?.reason ?? '');
	const describe = Object.hasOwn(UNREADABLE_REASONS, reason) ? UNREADABLE_REASONS[reason] : () => 'We couldn’t read this page';
	const status = Number.isInteger(unreadable?.status) ? ` (HTTP ${unreadable.status})` : '';
	const next = BLOCKED_REASONS.has(reason) ? 'Trying again will give the same result.' : 'Try again or use another page.';
	return `${describe(cdnName(provider))}${status}, so we could not read the article. ${next}`;
}

/** Facts displayed beside the service's package, never a substitute package. */
export function previewDetails(data, sourceUrl, checkedAt, submittedDomain = data.domain) {
	const page = data.page;
	const source = sourceUrl || page?.url || submittedDomain || '';
	const contentRead = Boolean(page && !page.unreadable);
	// The offer is built from the submitted terms, not the page text, so a
	// blocked page can still carry one; only its title is then a placeholder.
	// The service sends `offers` with one entry; `offer` is the shape it sent
	// before that and goes once the deployed service has moved over.
	const offer = Array.isArray(data.offers) ? data.offers[0] : data.offer;
	const hasOffer = Boolean(offer && typeof offer === 'object'
		&& !Array.isArray(offer) && Object.keys(offer).length);
	const unreadable = page?.unreadable && typeof page.unreadable === 'object'
		? { reason: String(page.unreadable.reason ?? ''), status: page.unreadable.status ?? null }
		: null;
	// The service says where the title came from; a placeholder must never
	// pass for one read from the site.
	const titlePlaceholder = page?.title_source === 'placeholder';
	const notes = {
		detected: 'Detected licensing terms from your site.',
		default: '',
		request: 'Your preview controls override the terms shown here.',
	};
	const manifestStep = Array.isArray(data.steps)
		? data.steps.find((entry) => entry && typeof entry === 'object' && entry.manifest) : null;
	// The per-exchange `ext` block holds an account id placeholder that is only
	// filled in at registration, so the preview shows the file without it.
	const manifest = manifestStep?.manifest ?? null;
	const shownManifest = manifest && Array.isArray(manifest.exchanges)
		? { ...manifest, exchanges: manifest.exchanges.map(({ ext, ...exchange }) => exchange) }
		: manifest;
	return {
		sourceUrl: source, checkedAt, contentRead, hasOffer, unreadable, titlePlaceholder,
		termsNote: Object.hasOwn(notes, data.terms_source) ? notes[data.terms_source] : 'Licensing source not reported.',
		domain: submittedDomain,
		cdn: data.cdn?.provider ?? 'none',
		evidence: (Array.isArray(data.cdn?.evidence) ? data.cdn.evidence : [])
			.filter((entry) => entry && typeof entry === 'object')
			.map((entry) => [String(entry.name || entry.source || ''), String(entry.value ?? '')])
			.filter(([name]) => name !== ''),
		// Preserve the service-generated file independently of CDN or page access.
		manifest: shownManifest,
		termsSource: String(data.terms_source ?? ''),
		termsDocument: String(data.detected_terms?.document_url ?? ''),
		offer: hasOffer ? offer : null,
		// The page says the title is a placeholder in its own words, above the
		// offer, so the service's sentence about it would be said twice.
		warnings: (Array.isArray(data.warnings) ? data.warnings.map(String) : [])
			.filter((warning) => !(titlePlaceholder && /placeholder/i.test(warning))),
	};
}
