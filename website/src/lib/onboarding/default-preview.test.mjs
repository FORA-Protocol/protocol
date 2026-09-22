import test from 'node:test';
import assert from 'node:assert/strict';
import * as preview from './default-preview.mjs';
import { cdnPresentation } from './cdn-integrations.mjs';

const SOURCE = 'https://publisher.example/News/Story?x=One%2FTwo&x=3';
const CHECKED = '2026-09-21T13:00:00.000Z';
// API.md §1, steps.For, terms.DefaultFree/BuildOffer and preview.manifest in the
// external FORA-329 onboarding service own these wire shapes.
const pricing = { model: 'PRICING_MODEL_FREE', rate: '0', currency: 'EUR' };
const terms = [{ semantics: 'TERM_SEMANTICS_ENUMERATED', pricing,
	restrictions: [{ kind: 'RESTRICTION_KIND_FUNCTION', permitted: ['search', 'ai-input'], prohibited: ['ai-train'] }] }];
const manifest = {
	ver: '1.0', role: 'ROLE_PUBLISHER', domain: 'publisher.example',
	exchanges: [{ domain: 'exchange.example', endpoint: 'https://exchange.example/fora',
		relationship: 'PROVIDER_RELATIONSHIP_DIRECT',
		ext: { resource_owner_id: '<the account id you receive when you register>' } }],
};
// What the page shows: the same file without the per-exchange `ext` placeholder.
const shownManifest = { ...manifest, exchanges: manifest.exchanges.map(({ ext, ...exchange }) => exchange) };
const response = (overrides = {}) => ({
	domain: 'publisher.example',
	page: { url: SOURCE, canonical_url: 'https://publisher.example/canonical', title: '  A real headline  ', source: 'article_url' },
	cdn: { provider: 'none', integration: 'contact_us', evidence: null },
	warnings: null,
	offer: { exchange: 'exchange.example', title: 'A real headline', pricing, terms,
		delivery_method: 'DELIVERY_METHOD_INSTRUCTIONS',
		identity: { canonical_url: 'https://publisher.example/canonical', resource_mutability: 'RESOURCE_MUTABILITY_STATIC' } },
	detected_terms: null,
	sample_feed: JSON.stringify({ domain: 'publisher.example', path: '/canonical', title: 'A real headline',
		terms: [{ semantics: 'enumerated', pricing: { model: 'free', rate: '0', currency: 'EUR' },
			functions: ['search', 'ai-input'], prohibited_functions: ['ai-train'] }] }) + '\n',
	steps: [{ id: 'manifest', title: 'Publish discovery', summary: 'Serve the discovery document.', manifest },
		{ id: 'edge', title: 'Connect your network', summary: 'Contact us.', integration: 'contact_us' }],
	vocabulary: { pricing_models: ['free', 'per_unit'], permitted_functions: ['search', 'ai-input', 'ai-index', 'ai-train', 'crawl'], currency: 'EUR', unit: 'fetches' },
	terms_source: 'default',
	...overrides,
});
const details = (data, sourceUrl = SOURCE) => {
	assert.equal(typeof preview.previewDetails, 'function');
	return preview.previewDetails(data, sourceUrl, CHECKED);
};

test('preview metadata preserves the submitted source and observed check time, not the canonical URL', () => {
	const data = response();
	data.page.url = 'https://publisher.example/redirected';
	const result = details(data);
	assert.equal(result.sourceUrl, SOURCE);
	assert.equal(result.checkedAt, CHECKED);
	assert.equal(result.contentRead, true);
	assert.equal(result.hasOffer, true);
});

test('missing submitted URLs fall back to page URL and then domain', () => {
	const data = response({ page: { url: SOURCE, canonical_url: 'https://publisher.example/canonical', title: '  ' } });
	assert.equal(details(data, '').sourceUrl, SOURCE);
	const missing = details(response({ page: null, offer: null }), '');
	assert.equal(missing.sourceUrl, 'publisher.example');
	assert.equal(missing.contentRead, false);
	assert.equal(missing.hasOffer, false);
});

test('robustness: absent or malformed offers never fabricate a package', () => {
	for (const offer of [undefined, null, {}, [], 'not an offer']) {
		const result = details(response({ offer }));
		assert.equal(result.contentRead, true);
		assert.equal(result.hasOffer, false);
	}
});

test('licensing provenance distinguishes detected, demo defaults, visitor controls and unknown', () => {
	const notes = ['detected', 'default', 'request', undefined].map((terms_source) => details(response({ terms_source, offer: null })).termsNote);
	assert.match(notes[0], /detect/i);
	assert.equal(notes[1], '', 'Demo-default notices are intentionally omitted');
	assert.match(notes[2], /(?:your|visitor).*(?:control|override|term)/i);
	assert.match(notes[3], /(?:unknown|not (?:reported|available|identified))/i);
	assert.equal(new Set(notes).size, 4);
	for (const note of notes) assert.doesNotMatch(note, /no licen[sc]e|no licensing|no terms (?:exist|found)/i);
});

const cdnCases = [
	['CloudFront', 'cloudfront', 'edge_package', 'x-amz-cf-id', /Lambda@Edge/],
	['Cloudflare', 'cloudflare', 'edge_package', 'cf-ray', /worker/i],
	['Fastly', 'fastly', 'edge_package', 'x-served-by', /FORA Edge package/],
	['Akamai', 'akamai', 'contact_us', 'akamai-grn', /signed.*URLs/i],
	['unknown CDN', 'none', 'contact_us', null, /CloudFront, Cloudflare, and Fastly are supported today/],
	// Controlled-origin scenario is test provenance, never a service assertion:
	// the same none payload cannot distinguish direct origin from an unknown CDN.
	['known direct origin', 'none', 'contact_us', null, /CloudFront, Cloudflare, and Fastly are supported today/],
];
function cdnResponse([, provider, integration, header], overrides = {}) {
	const data = response(overrides);
	return { ...data, cdn: { provider, integration,
		evidence: header ? [{ provider, source: 'header', name: header, value: 'present' }] : null },
		steps: data.steps.map((step) => step.id === 'edge' ? { ...step, integration } : step) };
}

test('service CDN fixtures retain configuration and map recognized and unknown presentation', () => {
	for (const row of cdnCases) {
		const [label, provider, , header, description] = row;
		const data = cdnResponse(row);
		const result = preview.previewDetails(data, SOURCE, CHECKED, 'submitted.example');
		assert.equal(result.cdn, provider, label);
		assert.deepEqual(result.manifest, shownManifest, label);
		assert.equal(result.offer, data.offer, label);
		assert.equal(result.domain, 'submitted.example');
		assert.equal(result.sourceUrl, SOURCE);
		assert.equal(result.checkedAt, CHECKED);
		assert.equal(result.hasOffer, true);
		assert.equal(result.termsSource, 'default');
		assert.equal(result.termsDocument, '');
		assert.deepEqual(result.evidence, header ? [[header, 'present']] : []);
		assert.deepEqual(result.warnings, []);
		const ui = cdnPresentation(result.cdn);
		assert.match(ui.description, description, label);
		assert.equal(ui.tone, provider === 'none' ? 'none' : 'ok');
		if (provider !== 'none') assert.ok(ui.badge.includes(label));
		else assert.deepEqual(ui, cdnPresentation('none'));
	}
});

test('unreadable service fixtures retain configuration and detected provenance for every CDN and reason', () => {
	for (const row of cdnCases) for (const [reason, status] of [
		['bot_protection', 403], ['refused', 401], ['not_found', 404], ['server_error', 500], ['unexpected_status', 300],
	]) {
		const data = cdnResponse(row, {
			page: { url: SOURCE, canonical_url: SOURCE, title: '', source: 'article_url', unreadable: { reason, status } },
			offer: null, sample_feed: '', terms_source: 'detected',
			detected_terms: { source: 'rsl', document_url: 'https://publisher.example/rsl.txt',
				content_url: 'https://publisher.example/*', terms, warnings: null },
			warnings: ['The page could not be read.'],
		});
		const result = details(data);
		assert.deepEqual(result.manifest, shownManifest, `${row[0]}: ${reason}`);
		assert.equal(result.cdn, row[1]);
		assert.equal(result.contentRead, false);
		assert.equal(result.hasOffer, false);
		assert.equal(result.offer, null);
		assert.deepEqual(result.warnings, data.warnings);
		assert.equal(result.termsSource, 'detected');
		assert.equal(result.termsDocument, data.detected_terms.document_url);
		assert.match(result.termsNote, /detect/i);
	}
});

test('null and empty lists normalize equally and unavailable manifests are never fabricated', () => {
	for (const list of [null, []]) {
		const data = response({ cdn: { provider: 'none', integration: 'contact_us', evidence: list }, warnings: list });
		const result = details(data);
		assert.deepEqual(result.evidence, []);
		assert.deepEqual(result.warnings, []);
		assert.equal(result.domain, data.domain);
	}
	const data = response();
	data.steps = data.steps.map(({ manifest, ...step }) => step);
	data.warnings = ['the discovery document could not be built for this preview'];
	assert.equal(details(data).manifest, null);
});
