import test from 'node:test';
import assert from 'node:assert/strict';
import * as request from './request.mjs';

import {
	MAX_BODY_BYTES,
	bodyByteLength,
	buildPreviewRequest,
	formatRate,
	isZeroRate,
	normalizeArticleUrl,
	normalizeDomain,
} from './request.mjs';

const pageInput = (url = 'https://example.com/News/Story?x=One%2FTwo&x=3#Details', controls = null) => ({ url, controls });

test('one page URL derives the service domain without losing its path, query or fragment', () => {
	assert.equal(typeof request.buildPagePreviewRequest, 'function');
	for (const [url, domain, articleUrl] of [
		['  https://EXAMPLE.com:443/News/Story?x=One%2FTwo&x=3#Details  ', 'example.com', pageInput().url],
		['http://example.com:80/Case?x=1+2', 'example.com', 'http://example.com/Case?x=1+2'],
	]) {
		assert.deepEqual(request.buildPagePreviewRequest(pageInput(url)), {
			ok: true,
			body: { domain, article_url: articleUrl },
		});
	}
});

// FORA-329 service API.md requires a bare domain with no port; the old
// :8080 acceptance above was superseded by the supplied service contract.
test('the one-URL service adapter rejects non-default ports before sending', () => {
	for (const url of ['http://example.com:8080/a', 'https://example.com:8443/a', 'https://example.com:80/a']) {
		const built = request.buildPagePreviewRequest(pageInput(url));
		assert.equal(built.ok, false, url);
		assert.equal(built.field, 'url');
		assert.ok(built.message);
		assert.equal(built.body, undefined);
	}
});

test('the page URL is required, HTTP(S), and contains no credentials', () => {
	assert.equal(typeof request.buildPagePreviewRequest, 'function');
	for (const url of [null, '', '  ', 'example.com/a', '/a', 'not a URL', 'ftp://example.com/a',
		'https://localhost/a', 'https://-example.com/a', 'https://user:secret@example.com/a', 'https://user@example.com/a']) {
		const built = request.buildPagePreviewRequest(pageInput(url));
		assert.equal(built.ok, false, `reject ${JSON.stringify(url)}`);
		assert.equal(built.field, 'url');
		assert.ok(built.message);
		assert.equal(built.body, undefined);
	}
	assert.equal(request.buildPagePreviewRequest().ok, false);
});

test('page URLs accept the 2048-character boundary and reject anything longer', () => {
	assert.equal(typeof request.buildPagePreviewRequest, 'function');
	const prefix = 'https://example.com/';
	const url = prefix + 'a'.repeat(2048 - prefix.length);
	assert.equal(request.buildPagePreviewRequest(pageInput(url)).ok, true);
	const built = request.buildPagePreviewRequest(pageInput(`${url}a`));
	assert.equal(built.ok, false);
	assert.equal(built.field, 'url');
});

test('the one-URL request retains terms and their validation through the existing wire contract', () => {
	assert.equal(typeof request.buildPagePreviewRequest, 'function');
	const controls = { pricingModel: 'per_unit', rate: '0.002', offeredFunctions: ['search', 'ai-train'], permittedFunctions: ['search'], attributionRequired: true };
	const built = request.buildPagePreviewRequest(pageInput(undefined, controls));
	assert.deepEqual(built, {
		ok: true,
		body: {
			domain: 'example.com', article_url: pageInput().url,
			terms: { pricing_model: 'per_unit', rate: '0.002', permitted_functions: ['search'], prohibited_functions: ['ai-train'], attribution_required: true },
		},
	});
	const invalid = request.buildPagePreviewRequest(pageInput(undefined, { ...controls, rate: '0' }));
	assert.equal(invalid.ok, false);
	assert.equal(invalid.field, 'rate');
});

test('shared page URLs round-trip once while retaining unrelated landing query and hash', () => {
	assert.equal(typeof request.previewPageUrl, 'function');
	assert.equal(typeof request.withPreviewPageUrl, 'function');
	const landing = 'https://fora.example/publishers/onboarding?campaign=one&campaign=two&url=old&url=older#preview';
	const page = 'https://example.com/News/Story?a=One%2FTwo&a=3&next=https%3A%2F%2Fother.example%2F&space=hello+world#Details';
	const shared = request.withPreviewPageUrl(landing, page);
	assert.equal(typeof shared, 'string');
	const parsed = new URL(shared);
	assert.equal(parsed.origin + parsed.pathname, 'https://fora.example/publishers/onboarding');
	assert.equal(parsed.hash, '#preview');
	assert.deepEqual(parsed.searchParams.getAll('campaign'), ['one', 'two']);
	assert.deepEqual(parsed.searchParams.getAll('url'), [page]);
	assert.deepEqual([...new Set(parsed.searchParams.keys())].sort(), ['campaign', 'url']);
	assert.equal(request.previewPageUrl(shared), page);
	assert.equal(request.previewPageUrl('https://fora.example/publishers/onboarding'), null);
	assert.equal(request.previewPageUrl('https://fora.example/publishers/onboarding?url='), '');
	assert.equal(request.previewPageUrl('https://fora.example/publishers/onboarding?url=not+a+URL'), 'not a URL');
});

test('normalizeDomain reduces what a visitor pastes to a bare host', () => {
	assert.equal(normalizeDomain('example.com'), 'example.com');
	assert.equal(normalizeDomain('  Example.COM  '), 'example.com');
	assert.equal(normalizeDomain('https://example.com/blog?x=1#y'), 'example.com');
	assert.equal(normalizeDomain('http://user@example.com:8443/path'), 'example.com:8443');
	assert.equal(normalizeDomain('example.com.'), 'example.com');
	assert.equal(normalizeDomain('news.example.co.uk'), 'news.example.co.uk');
});

test('a port is part of the host, because a different port is a different service', () => {
	assert.equal(normalizeDomain('example.com:8443'), 'example.com:8443');
	assert.equal(normalizeDomain('http://example.com:8080/x'), 'example.com:8080');
	// A port its own scheme already implies says nothing extra.
	assert.equal(normalizeDomain('https://example.com:443/a'), 'example.com');
	assert.equal(normalizeDomain('http://example.com:80'), 'example.com');
	// but the same port written against the other scheme is a real one
	assert.equal(normalizeDomain('https://example.com:80'), 'example.com:80');
});

test('normalizeDomain refuses what is not a host', () => {
	assert.equal(normalizeDomain(''), '');
	assert.equal(normalizeDomain('   '), '');
	assert.equal(normalizeDomain('localhost'), '');
	assert.equal(normalizeDomain('not a domain'), '');
	assert.equal(normalizeDomain('-example.com'), '');
	assert.equal(normalizeDomain('.example.com'), '');
	assert.equal(normalizeDomain(undefined), '');
});

test('normalizeArticleUrl keeps only absolute http(s) addresses', () => {
	assert.equal(normalizeArticleUrl('https://example.com/a'), 'https://example.com/a');
	assert.equal(normalizeArticleUrl('  http://example.com/a  '), 'http://example.com/a');
	assert.equal(normalizeArticleUrl('example.com/a'), '');
	assert.equal(normalizeArticleUrl('ftp://example.com/a'), '');
	assert.equal(normalizeArticleUrl(''), '');
});

test('formatRate writes a plain decimal, whatever the input notation', () => {
	assert.equal(formatRate('0.002'), '0.002');
	assert.equal(formatRate('1e-3'), '0.001');
	assert.equal(formatRate('1E3'), '1000');
	assert.equal(formatRate('.5'), '0.5');
	assert.equal(formatRate('007.50'), '7.5');
	assert.equal(formatRate('0'), '0');
	assert.equal(formatRate(' 2 '), '2');
});

test('formatRate refuses a value that is not a non-negative decimal', () => {
	assert.equal(formatRate('-1'), null);
	assert.equal(formatRate('abc'), null);
	assert.equal(formatRate(''), null);
	assert.equal(formatRate('1.2345678'), null, 'more than six decimals is a typo, not a price');
});

test('isZeroRate recognises zero in every spelling formatRate can produce', () => {
	assert.equal(isZeroRate('0'), true);
	assert.equal(isZeroRate(formatRate('0.000')), true);
	assert.equal(isZeroRate('0.001'), false);
});

test('a request with no controls carries no terms, so the service resolves them', () => {
	const built = buildPreviewRequest({ domain: 'example.com' });
	assert.equal(built.ok, true);
	assert.deepEqual(Object.keys(built.body), ['domain']);
	assert.equal(built.body.domain, 'example.com');
});

test('the body carries only fields the service accepts', () => {
	const built = buildPreviewRequest({
		domain: 'example.com',
		articleUrl: 'https://example.com/a',
		controls: {
			pricingModel: 'per_unit',
			rate: '0.002',
			offeredFunctions: ['search', 'ai-input', 'ai-train'],
			permittedFunctions: ['search'],
			attributionRequired: true,
		},
	});
	assert.equal(built.ok, true);
	assert.deepEqual(Object.keys(built.body).sort(), ['article_url', 'domain', 'terms']);
	assert.deepEqual(
		Object.keys(built.body.terms).sort(),
		['attribution_required', 'permitted_functions', 'pricing_model', 'prohibited_functions', 'rate'],
	);
});

test('free omits the rate entirely', () => {
	const built = buildPreviewRequest({
		domain: 'example.com',
		controls: {
			pricingModel: 'free',
			rate: '0.002',
			offeredFunctions: ['search'],
			permittedFunctions: ['search'],
		},
	});
	assert.equal(built.ok, true);
	assert.equal('rate' in built.body.terms, false);
	assert.equal(built.body.terms.pricing_model, 'free');
});

test('a paid term without a price is refused before the request is sent', () => {
	for (const rate of ['', '0', '0.000', 'abc']) {
		const built = buildPreviewRequest({
			domain: 'example.com',
			controls: { pricingModel: 'per_unit', rate, offeredFunctions: [], permittedFunctions: [] },
		});
		assert.equal(built.ok, false, `rate ${JSON.stringify(rate)} should be refused`);
		assert.equal(built.field, 'rate');
	}
});

test('every offered use lands in exactly one list', () => {
	const offered = ['search', 'ai-input', 'ai-index', 'ai-train', 'crawl'];
	for (const permittedFunctions of [[], ['search'], ['search', 'ai-train'], offered]) {
		const built = buildPreviewRequest({
			domain: 'example.com',
			controls: { pricingModel: 'free', offeredFunctions: offered, permittedFunctions },
		});
		assert.equal(built.ok, true);
		const permitted = built.body.terms.permitted_functions ?? [];
		const prohibited = built.body.terms.prohibited_functions ?? [];
		assert.deepEqual([...permitted, ...prohibited].sort(), [...offered].sort());
		assert.deepEqual(permitted.filter((token) => prohibited.includes(token)), []);
	}
});

test('attribution is sent only when it is required', () => {
	const off = buildPreviewRequest({
		domain: 'example.com',
		controls: { pricingModel: 'free', offeredFunctions: [], permittedFunctions: [], attributionRequired: false },
	});
	assert.equal('attribution_required' in off.body.terms, false);

	const on = buildPreviewRequest({
		domain: 'example.com',
		controls: { pricingModel: 'free', offeredFunctions: [], permittedFunctions: [], attributionRequired: true },
	});
	assert.equal(on.body.terms.attribution_required, true);
});

test('a blank article address is dropped, a malformed one is reported', () => {
	const blank = buildPreviewRequest({ domain: 'example.com', articleUrl: '   ' });
	assert.equal(blank.ok, true);
	assert.equal('article_url' in blank.body, false);

	const bad = buildPreviewRequest({ domain: 'example.com', articleUrl: 'example.com/a' });
	assert.equal(bad.ok, false);
	assert.equal(bad.field, 'article');
});

test('the reported field names an input the form actually has', () => {
	// The ids here are the ones the page puts on its inputs; a name that does not
	// match one means the message is written to a node that does not exist.
	const FORM_FIELDS = new Set(['domain', 'article', 'pricing-model', 'rate', 'uses', 'attribution']);
	const cases = [
		buildPreviewRequest({ domain: '' }),
		buildPreviewRequest({ domain: 'example.com', articleUrl: 'not-a-url' }),
		buildPreviewRequest({ domain: 'example.com', controls: { pricingModel: 'per_unit', rate: '0', offeredFunctions: [], permittedFunctions: [] } }),
		buildPreviewRequest({ domain: 'example.com', controls: { pricingModel: '', offeredFunctions: [], permittedFunctions: [] } }),
	];
	for (const built of cases) {
		assert.equal(built.ok, false);
		assert.ok(FORM_FIELDS.has(built.field), `${built.field} is not a field on the form`);
	}
});

test('an empty domain is reported against the domain field', () => {
	const built = buildPreviewRequest({ domain: '   ' });
	assert.equal(built.ok, false);
	assert.equal(built.field, 'domain');
});

test('the longest input the form allows still fits the service body limit', () => {
	const built = buildPreviewRequest({
		domain: `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.example.com`,
		articleUrl: `https://example.com/${'p'.repeat(2000)}`,
		controls: {
			pricingModel: 'per_unit',
			rate: '0.002',
			offeredFunctions: ['search', 'ai-input', 'ai-index', 'ai-train', 'crawl'],
			permittedFunctions: ['search'],
			attributionRequired: true,
		},
	});
	assert.equal(built.ok, true);
	assert.ok(bodyByteLength(built.body) <= MAX_BODY_BYTES);
});
