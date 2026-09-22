/** Facts displayed beside the service's package, never a substitute package. */
export function previewDetails(data, sourceUrl, checkedAt, submittedDomain = data.domain) {
	const page = data.page;
	const source = sourceUrl || page?.url || submittedDomain || '';
	const contentRead = Boolean(page && !page.unreadable);
	const hasOffer = contentRead && Boolean(data.offer && typeof data.offer === 'object'
		&& !Array.isArray(data.offer) && Object.keys(data.offer).length);
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
		sourceUrl: source, checkedAt, contentRead, hasOffer,
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
		offer: data.offer ?? null,
		warnings: Array.isArray(data.warnings) ? data.warnings.map(String) : [],
	};
}
