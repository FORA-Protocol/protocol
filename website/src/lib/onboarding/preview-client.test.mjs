import test from 'node:test';
import assert from 'node:assert/strict';

import { fetchPreview, previewUrl } from './preview-client.mjs';

function jsonResponse(status, payload) {
	return {
		ok: status >= 200 && status < 300,
		status,
		json: async () => payload,
	};
}

test('the endpoint is built from the configured base, whatever its trailing slashes', () => {
	assert.equal(previewUrl('https://host.example/onboarding'), 'https://host.example/onboarding/v1/preview');
	assert.equal(previewUrl('https://host.example/onboarding/'), 'https://host.example/onboarding/v1/preview');
	assert.equal(previewUrl('https://host.example//'), 'https://host.example/v1/preview');
});

test('a successful call posts JSON and returns the parsed body', async () => {
	const calls = [];
	const outcome = await fetchPreview({
		fetchImpl: async (url, init) => {
			calls.push({ url, init });
			return jsonResponse(200, { domain: 'example.com' });
		},
		baseUrl: 'https://host.example/onboarding',
		body: { domain: 'example.com' },
	});

	assert.equal(outcome.ok, true);
	assert.deepEqual(outcome.data, { domain: 'example.com' });
	assert.equal(calls.length, 1);
	assert.equal(calls[0].url, 'https://host.example/onboarding/v1/preview');
	assert.equal(calls[0].init.method, 'POST');
	assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
	assert.equal(calls[0].init.body, '{"domain":"example.com"}');
});

test('an error status comes back as a described failure, not a throw', async () => {
	const outcome = await fetchPreview({
		fetchImpl: async () => jsonResponse(429, { error: 'too many previews' }),
		baseUrl: 'https://host.example',
		body: {},
	});
	assert.equal(outcome.ok, false);
	assert.equal(outcome.failure.kind, 'rate_limited');
	assert.equal(outcome.failure.detail, 'Wait about a minute, then try again.');
});

test('a rejected fetch becomes the network failure', async () => {
	const outcome = await fetchPreview({
		fetchImpl: async () => { throw new TypeError('Failed to fetch'); },
		baseUrl: 'https://host.example',
		body: {},
	});
	assert.equal(outcome.ok, false);
	assert.equal(outcome.failure.kind, 'network');
});

test('a cancelled call is reported as aborted and never as a failure', async () => {
	const controller = new AbortController();
	const outcome = await fetchPreview({
		fetchImpl: async () => {
			controller.abort();
			const error = new Error('aborted');
			error.name = 'AbortError';
			throw error;
		},
		baseUrl: 'https://host.example',
		body: {},
		signal: controller.signal,
	});
	assert.deepEqual(outcome, { aborted: true });
});

test('a 200 whose body is not an object is treated as a failure', async () => {
	const outcome = await fetchPreview({
		fetchImpl: async () => ({
			ok: true,
			status: 200,
			json: async () => { throw new SyntaxError('Unexpected token <'); },
		}),
		baseUrl: 'https://host.example',
		body: {},
	});
	assert.equal(outcome.ok, false);
	assert.equal(outcome.failure.kind, 'internal');
});
