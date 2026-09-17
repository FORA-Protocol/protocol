import test from 'node:test';
import assert from 'node:assert/strict';

import { RATE_LIMIT_COOLDOWN_MS, describeFailure, fieldForPath } from './failure.mjs';

test('a violation path maps onto the control that owns it', () => {
	assert.equal(fieldForPath('domain'), 'domain');
	assert.equal(fieldForPath('article_url'), 'article');
	assert.equal(fieldForPath('terms.rate'), 'rate');
	assert.equal(fieldForPath('terms.pricing_model'), 'pricing-model');
	assert.equal(fieldForPath('terms.permitted_functions'), 'uses');
	assert.equal(fieldForPath('terms.prohibited_functions'), 'uses');
	assert.equal(fieldForPath('terms.attribution_required'), 'attribution');
});

test('an array index in the path does not hide the control', () => {
	assert.equal(fieldForPath('terms[0].rate'), 'rate');
	assert.equal(fieldForPath('terms[2].permitted_functions[1]'), 'uses');
});

test('a path naming something with no control returns null', () => {
	assert.equal(fieldForPath('offer.something'), null);
	assert.equal(fieldForPath(''), null);
	assert.equal(fieldForPath(undefined), null);
});

test('a rejected fetch is described as a connection problem, not a server fault', () => {
	const failure = describeFailure({ networkError: new TypeError('Failed to fetch') });
	assert.equal(failure.kind, 'network');
	assert.equal(failure.headline, 'We could not reach the preview service');
	assert.equal(failure.retryable, true);
	assert.equal(failure.cooldownMs, 0);
});

test('the rate limit asks the visitor to wait and sets a cooldown', () => {
	const failure = describeFailure({ status: 429, body: { error: 'too many previews' } });
	assert.equal(failure.kind, 'rate_limited');
	assert.equal(failure.headline, 'Too many previews from your network');
	assert.equal(failure.cooldownMs, RATE_LIMIT_COOLDOWN_MS);
});

test('each error kind gets its own wording', () => {
	const cases = [
		[400, 'invalid_request', 'invalid_request', 'We could not read that request'],
		[422, 'terms_rejected', 'terms_rejected', 'The Exchange would refuse those terms'],
		[502, 'upstream', 'upstream', 'We could not read your site'],
		[504, 'timeout', 'timeout', 'Your site took too long to answer'],
		[500, 'internal', 'internal', 'Something went wrong on our side'],
	];
	for (const [status, kind, expectedKind, expectedHeadline] of cases) {
		const failure = describeFailure({ status, body: { error: 'service says', kind } });
		assert.equal(failure.kind, expectedKind, `status ${status}`);
		assert.equal(failure.headline, expectedHeadline, `status ${status}`);
	}
});

test('the service message is preferred over the generic detail where there is one', () => {
	const failure = describeFailure({ status: 400, body: { kind: 'invalid_request', error: 'domain is not a bare host' } });
	assert.equal(failure.detail, 'domain is not a bare host');
});

test('an oversized body is reported against the field that can shrink', () => {
	const failure = describeFailure({ status: 413, body: null });
	assert.equal(failure.kind, 'too_large');
	assert.equal(failure.headline, 'That request was too long');
});

test('a body that is not JSON still produces a usable message', () => {
	const failure = describeFailure({ status: 502, body: null });
	assert.equal(failure.kind, 'upstream');
	assert.ok(failure.detail.length > 0);
});

test('an unexpected status falls back to the internal wording', () => {
	const failure = describeFailure({ status: 418, body: null });
	assert.equal(failure.kind, 'internal');
	assert.equal(failure.headline, 'Something went wrong on our side');
});

test('violations arrive with their control already resolved', () => {
	const failure = describeFailure({
		status: 422,
		body: {
			kind: 'terms_rejected',
			error: 'the terms would be refused',
			violations: [
				{ rule: 'pricing.rate_required', path: 'terms.rate', message: 'a per_unit term needs a rate above zero' },
				{ rule: 'offer.unreachable', path: 'offer.x', message: 'not something the page can fix' },
				{ rule: 'ignored', path: 'terms.rate', message: '   ' },
			],
		},
	});
	assert.equal(failure.violations.length, 2, 'a violation with no message is dropped');
	assert.deepEqual(failure.violations[0], {
		message: 'a per_unit term needs a rate above zero',
		path: 'terms.rate',
		field: 'rate',
	});
	assert.equal(failure.violations[1].field, null);
});

test('a response with no violations array yields an empty list, never undefined', () => {
	assert.deepEqual(describeFailure({ status: 500, body: {} }).violations, []);
	assert.deepEqual(describeFailure({ status: 500, body: { violations: 'nope' } }).violations, []);
});
