import test from 'node:test';
import assert from 'node:assert/strict';

import { describeFailure } from './failure.mjs';

test('a rejected fetch is described as a connection problem, not a server fault', () => {
	const failure = describeFailure({ networkError: new TypeError('Failed to fetch') });
	assert.equal(failure.kind, 'network');
	assert.equal(failure.headline, 'We could not reach the preview service');
});

test('the rate limit asks the visitor to wait', () => {
	const failure = describeFailure({ status: 429, body: { error: 'too many previews' } });
	assert.equal(failure.kind, 'rate_limited');
	assert.equal(failure.headline, 'Too many previews from your network');
	assert.equal(failure.detail, 'Wait about a minute, then try again.');
});

test('error kinds remain distinct while content-read failures share wording', () => {
	const cases = [
		[400, 'invalid_request', 'invalid_request', 'We could not read that request'],
		[422, 'terms_rejected', 'terms_rejected', 'The Exchange would refuse those terms'],
		[502, 'upstream', 'upstream', 'We couldn’t read this page.'],
		[504, 'timeout', 'timeout', 'We couldn’t read this page.'],
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

test('an oversized body has an actionable error message', () => {
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

test('violations preserve paths and messages for display', () => {
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
	});
});

test('a response with no violations array yields an empty list, never undefined', () => {
	assert.deepEqual(describeFailure({ status: 500, body: {} }).violations, []);
	assert.deepEqual(describeFailure({ status: 500, body: { violations: 'nope' } }).violations, []);
});

// FORA-329 shared copy covers both service timeout budgets, not just one.
test('upstream and both timeout budgets share retry guidance without exposing raw errors', () => {
	for (const [status, kind, error] of [
		[502, 'upstream', 'address refused'],
		[504, 'timeout', 'site did not answer in time'],
		[504, 'timeout', 'preview ran out of time'],
	]) {
		const failure = describeFailure({ status, body: { kind, error } });
		assert.equal(failure.kind, kind);
		assert.equal(failure.headline, 'We couldn’t read this page.');
		assert.equal(failure.detail, 'Try again or use another page.');
	}
});
