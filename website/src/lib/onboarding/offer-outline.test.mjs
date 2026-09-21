import test from 'node:test';
import assert from 'node:assert/strict';

import {
	conditionSentence,
	obligationSentence,
	offerOutline,
	priceSentence,
	resolvedControls,
	sentenceList,
	singularUnit,
	unreadableSentence,
	useLabel,
} from './offer-outline.mjs';

const PAID_OFFER = {
	offer_id: 'of_01',
	title: 'Socrates',
	exchange: 'exchange.example',
	pricing: { model: 'PRICING_MODEL_PER_UNIT', rate: '0.02', currency: 'EUR', unit: 'accesses' },
	delivery_method: 'DELIVERY_METHOD_DIRECT',
	expires_at: '2026-09-17T06:44:59Z',
	terms: [{
		semantics: 'TERM_SEMANTICS_ENUMERATED',
		restrictions: [{
			kind: 'RESTRICTION_KIND_FUNCTION',
			permitted: ['search', 'ai-input'],
			prohibited: ['ai-train'],
		}],
		obligations: [{
			kind: 'OBLIGATION_KIND_ATTRIBUTION',
			trigger: 'OBLIGATION_TRIGGER_ON_USE',
			detail: 'Credit demo.fora-protocol.org with a link to the article',
		}],
		pricing: { model: 'PRICING_MODEL_PER_UNIT', rate: '0.02', currency: 'EUR', unit: 'accesses' },
	}],
};

test('a use token reads as a label, and an unknown one still reads', () => {
	assert.equal(useLabel('search'), 'Search');
	assert.equal(useLabel('ai-input'), 'AI input');
	assert.equal(useLabel('ai-train'), 'AI training');
	assert.equal(useLabel('text-and-data-mining'), 'Text and data mining');
	assert.equal(useLabel(''), '');
});

test('a list reads as a sentence', () => {
	assert.equal(sentenceList(['Search']), 'Search');
	assert.equal(sentenceList(['Search', 'AI input']), 'Search and AI input');
	assert.equal(sentenceList(['A', 'B', 'C']), 'A, B and C');
	assert.equal(sentenceList([]), '');
});

test('the condition names what is allowed and what is not', () => {
	assert.equal(
		conditionSentence(PAID_OFFER.terms[0]),
		'Search and AI input allowed; AI training not allowed',
	);
});

test('a term with nothing permitted still reads', () => {
	assert.equal(
		conditionSentence({ restrictions: [{ kind: 'RESTRICTION_KIND_FUNCTION', prohibited: ['ai-train'] }] }),
		'AI training not allowed',
	);
	assert.equal(conditionSentence({}), 'no use restrictions stated');
	assert.equal(conditionSentence(undefined), 'no use restrictions stated');
});

test('the price reads as money, not as an enum', () => {
	assert.equal(priceSentence({ model: 'PRICING_MODEL_FREE', rate: '0', currency: 'EUR' }), 'free');
	assert.equal(
		priceSentence({ model: 'PRICING_MODEL_PER_UNIT', rate: '0.02', currency: 'EUR', unit: 'accesses' }),
		'EUR 0.02 per access',
	);
	assert.equal(
		priceSentence({ model: 'PRICING_MODEL_FLAT', rate: '500', currency: 'EUR' }),
		'EUR 500, flat fee',
	);
	assert.equal(priceSentence(null), 'not stated');
});

test('a plural metering unit reads as one unit in a price', () => {
	// The registered pricing-unit tokens are plural; a unit price is about one.
	assert.equal(singularUnit('accesses'), 'access');
	assert.equal(singularUnit('fetches'), 'fetch');
	assert.equal(singularUnit('tokens'), 'token');
	assert.equal(singularUnit('pages'), 'page');
	assert.equal(singularUnit('seconds'), 'second');
	assert.equal(singularUnit('bytes'), 'byte');
	assert.equal(singularUnit('sq-km'), 'sq km');
	assert.equal(singularUnit('units-manufactured'), 'units manufactured');
	assert.equal(singularUnit(''), '');
});

test('an obligation names the duty, when it bites and its detail', () => {
	assert.equal(
		obligationSentence(PAID_OFFER.terms[0].obligations[0]),
		'attribution on every use — Credit demo.fora-protocol.org with a link to the article',
	);
	assert.equal(
		obligationSentence({ kind: 'OBLIGATION_KIND_ATTRIBUTION', trigger: 'OBLIGATION_TRIGGER_ON_USE' }),
		'attribution on every use',
	);
});

test('the outline shows every field the offer carries, in reading order', () => {
	const outline = offerOutline(PAID_OFFER);
	assert.equal('heading' in outline, false, 'no article heading');
	assert.deepEqual(
		outline.nodes.map((n) => n.label),
		['title', 'offer id', 'sold by', 'price', 'delivery', 'expires', 'terms'],
	);
	assert.deepEqual(outline.nodes[0], { label: 'title', value: 'Socrates' });
	assert.deepEqual(outline.nodes[2], { label: 'sold by', value: 'exchange.example' });
	assert.equal(outline.nodes[4].value, 'direct');
	assert.equal(outline.nodes[5].value, '2026-09-17 06:44 UTC');

	const terms = outline.nodes.find((n) => n.label === 'terms');
	assert.deepEqual(terms.children.map((c) => c.label), ['condition', 'price', 'obligation', 'semantics']);
	assert.equal(terms.children[1].value, 'EUR 0.02 per access');
});

test('a field the offer adds later still appears', () => {
	const outline = offerOutline({ ...PAID_OFFER, subscription_id: 'sub_9' });
	assert.deepEqual(outline.nodes.find((n) => n.label === 'subscription'), { label: 'subscription', value: 'sub_9' });
});

test('an empty field is left out rather than shown blank', () => {
	const outline = offerOutline({ title: 'A', subscription_id: '', iab_categories: [], ext: {} });
	assert.deepEqual(outline.nodes.map((n) => n.label), ['title', 'terms']);
	assert.deepEqual(outline.nodes[0], { label: 'title', value: 'A' }, 'a one-word title is not mistaken for an enum');
});

// The protocol gives an offer exactly one term, so this is the tolerant path,
// not the expected one: a service on an older protocol must not lose terms.
test('two terms each get their own group', () => {
	const outline = offerOutline({
		...PAID_OFFER,
		terms: [PAID_OFFER.terms[0], { restrictions: [], pricing: { model: 'PRICING_MODEL_FREE' } }],
	});
	const terms = outline.nodes.find((n) => n.label === 'terms');
	assert.deepEqual(terms.children.map((c) => c.label), ['term 1', 'term 2']);
	assert.equal(terms.children[1].children.find((c) => c.label === 'price').value, 'free');
});

test('an offer with no terms says so rather than rendering nothing', () => {
	const outline = offerOutline({ title: 'A' });
	assert.deepEqual(outline.nodes.find((n) => n.label === 'terms'), { label: 'terms', value: 'none stated' });
});

test('an empty offer yields an outline rather than throwing', () => {
	const outline = offerOutline(undefined);
	assert.ok(Array.isArray(outline.nodes));
});

test('the controls open on the terms the Exchange resolved', () => {
	const controls = resolvedControls(PAID_OFFER, ['search', 'ai-input', 'ai-train']);
	assert.deepEqual(controls, {
		pricingModel: 'per_unit',
		rate: '0.02',
		permittedFunctions: ['search', 'ai-input'],
		attributionRequired: true,
	});
});

test('a free offer opens the controls on free, with no price carried over', () => {
	const controls = resolvedControls({
		terms: [{
			restrictions: [{ kind: 'RESTRICTION_KIND_FUNCTION', permitted: ['search'], prohibited: ['ai-train'] }],
			pricing: { model: 'PRICING_MODEL_FREE', rate: '0', currency: 'EUR' },
		}],
	}, ['search', 'ai-input', 'ai-train']);
	assert.deepEqual(controls, {
		pricingModel: 'free',
		rate: '',
		permittedFunctions: ['search'],
		attributionRequired: false,
	});
});

test('a use the offer permits but the controls do not show is left out', () => {
	const controls = resolvedControls({
		terms: [{ restrictions: [{ kind: 'RESTRICTION_KIND_FUNCTION', permitted: ['search', 'crawl'] }] }],
	}, ['search', 'ai-input', 'ai-train']);
	assert.deepEqual(controls.permittedFunctions, ['search']);
});

test('an offer with no terms leaves the controls alone', () => {
	assert.equal(resolvedControls({}, ['search']), null);
	assert.equal(resolvedControls(undefined, ['search']), null);
});

// FORA-329 explicitly replaces reason-specific visitor copy with one read failure.
test('all documented unreadable reasons share useful read-failure copy', () => {
	for (const reason of ['bot_protection', 'refused', 'not_found', 'server_error', 'unexpected_status']) {
		assert.equal(unreadableSentence({ reason, status: 403 }), 'We couldn’t read this page. Try again or use another page.');
	}
});

test('unknown unreadable reasons and missing statuses retain the shared message', () => {
	for (const unreadable of [{ reason: 'teapot', status: 418 }, { reason: 'refused' }, {}]) {
		assert.equal(unreadableSentence(unreadable), 'We couldn’t read this page. Try again or use another page.');
	}
});
