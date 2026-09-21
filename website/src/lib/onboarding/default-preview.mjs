/** Facts displayed beside the service's package, never a substitute package. */
export function previewDetails(data, sourceUrl, checkedAt, submittedDomain = data.domain) {
	const page = data.page;
	const source = sourceUrl || page?.url || submittedDomain || '';
	const contentRead = Boolean(page && !page.unreadable);
	const hasOffer = contentRead && Boolean(data.offer && typeof data.offer === 'object'
		&& !Array.isArray(data.offer) && Object.keys(data.offer).length);
	const notes = {
		detected: 'Detected licensing terms from your site.',
		default: 'Demo defaults; no usable licensing terms were returned by this check.',
		request: 'Your preview controls override the terms shown here.',
	};
	const manifestStep = Array.isArray(data.steps)
		? data.steps.find((entry) => entry && typeof entry === 'object' && entry.manifest) : null;
	return {
		title: (contentRead ? String(page.title ?? '').trim() : '') || source,
		sourceUrl: source, checkedAt, contentRead, hasOffer,
		termsNote: Object.hasOwn(notes, data.terms_source) ? notes[data.terms_source] : 'Licensing source not reported.',
		domain: submittedDomain,
		cdn: data.cdn?.provider ?? 'none',
		evidence: (Array.isArray(data.cdn?.evidence) ? data.cdn.evidence : [])
			.filter((entry) => entry && typeof entry === 'object')
			.map((entry) => [String(entry.name || entry.source || ''), String(entry.value ?? '')])
			.filter(([name]) => name !== ''),
		articles: [{ url: String(page?.canonical_url ?? page?.url ?? source), title: String(page?.title ?? '') }],
		source: String(page?.source ?? ''),
		unreadable: page?.unreadable ?? null,
		// Preserve the service-generated file independently of CDN or page access.
		manifest: manifestStep?.manifest ?? null,
		termsSource: String(data.terms_source ?? ''),
		termsDocument: String(data.detected_terms?.document_url ?? ''),
		offer: data.offer ?? null,
		warnings: Array.isArray(data.warnings) ? data.warnings.map(String) : [],
	};
}
