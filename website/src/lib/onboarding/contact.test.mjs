import test from 'node:test';
import assert from 'node:assert/strict';

import {
	CONTACT_PATH,
	MAX_EMAIL_LENGTH,
	buildContactRequest,
	describeContactFailure,
	looksLikeEmail,
	sendContact,
} from './contact.mjs';

const interest = (overrides = {}) => ({ email: 'olena@x.example', ...overrides });
const terms = { pricing_model: 'per_unit', rate: '0.02', permitted_functions: ['search'], prohibited_functions: ['ai-train'], attribution_required: true };
const previewed = { domain: 'x.example', article_url: 'https://x.example/news/story', terms };
const response = (status = 202, body = { status: 'sent' }) =>
	new Response(JSON.stringify(body), { status });
const send = (fetchImpl, options = {}) => sendContact({
	fetchImpl, baseUrl: 'https://host.example/onboarding/', body: interest(), ...options,
});
const assertFailure = (outcome) => {
	assert.equal(outcome.ok, false);
	assert.ok(outcome.failure.headline.length > 0);
	assert.ok(outcome.failure.detail.length > 0);
};

test('interest carries the previewed domain, page and terms, omits name, and sends only what the preview had', () => {
	for (const name of [undefined, 'Olena', 'ignored\r\nname']) {
		assert.deepEqual(buildContactRequest(interest({ name, preview: previewed })), {
			ok: true, body: interest(previewed),
		});
	}
	assert.deepEqual(buildContactRequest(interest({ preview: { domain: 'x.example', article_url: previewed.article_url } })), {
		ok: true, body: interest({ domain: 'x.example', article_url: previewed.article_url }),
	});
	for (const preview of [undefined, null, {}, { domain: '', article_url: '', terms: null }]) {
		assert.deepEqual(buildContactRequest(interest({ email: '  olena@x.example  ', preview })), {
			ok: true, body: interest(),
		});
	}
});

test('email validation reports missing, malformed and overlong addresses against the email input', () => {
	for (const email of [undefined, null, '', '   ', 'olena-at-x', 'olena@x', 'a b@c.example', 'a@@b.example', `${'a'.repeat(MAX_EMAIL_LENGTH)}@b.example`]) {
		assert.equal(looksLikeEmail(email), false, JSON.stringify(email));
		const built = buildContactRequest(interest({ email }));
		assert.equal(built.ok, false, JSON.stringify(email));
		assert.equal(built.field, 'contact-email');
		assert.ok(built.message.length > 0);
	}
	for (const email of ['a@b.example', "o'brien@x.example", `${'a'.repeat(MAX_EMAIL_LENGTH - 10)}@b.example`]) {
		assert.equal(looksLikeEmail(email), true, email);
		assert.equal(buildContactRequest(interest({ email })).ok, true);
	}
});

test('raw email CR and LF are refused before trimming', () => {
	for (const email of ['\rolena@x.example', 'olena@x.example\n', '\r\nolena@x.example\r\n', 'olena\n@x.example']) {
		assert.equal(looksLikeEmail(email), false, JSON.stringify(email));
		const built = buildContactRequest(interest({ email }));
		assert.equal(built.ok, false, JSON.stringify(email));
		assert.equal(built.field, 'contact-email');
	}
});

test('interest posts the exact JSON body and signal to the contact path', async () => {
	const controller = new AbortController();
	const built = buildContactRequest(interest({ name: 'ignored', preview: previewed }));
	assert.equal(built.ok, true);
	let request;
	const outcome = await send(async (url, init) => {
		request = { url, init };
		return response();
	}, { body: built.body, signal: controller.signal });
	assert.deepEqual(outcome, { ok: true });
	assert.equal(request.url, `https://host.example/onboarding${CONTACT_PATH}`);
	assert.equal(request.init.method, 'POST');
	assert.equal(request.init.headers['Content-Type'], 'application/json');
	assert.deepEqual(JSON.parse(request.init.body), interest(previewed));
	assert.equal(request.init.signal, controller.signal);
});

test('only HTTP 202 with status sent confirms relay acceptance', async () => {
	assert.deepEqual(await send(async () => response()), { ok: true });
	for (const invalid of [response(200), response(202, { status: 'queued' }), response(202, {}), response(202, null), new Response('', { status: 202 }), new Response('{', { status: 202 })]) {
		assertFailure(await send(async () => invalid));
	}
});

test('rejected requests and network errors return readable failures', async () => {
	for (const status of [400, 429, 500, 503]) {
		assertFailure(await send(async () => response(status, { error: 'Request rejected.' })));
	}
	const outcome = await send(async () => { throw new TypeError('offline'); });
	assertFailure(outcome);
	assert.match(outcome.failure.detail, /try again/i);
	assert.match(describeContactFailure({ status: 429 }).headline, /Too many messages/);
	assert.equal(describeContactFailure({ status: 400, body: { error: 'Invalid email.' } }).detail, 'Invalid email.');
});

test('a cancelled send is reported as aborted', async () => {
	const controller = new AbortController();
	assert.deepEqual(await send(async (_url, init) => {
		assert.equal(init.signal, controller.signal);
		controller.abort();
		throw new DOMException('aborted', 'AbortError');
	}, { signal: controller.signal }), { aborted: true });
	assert.deepEqual(await send(async () => {
		throw new DOMException('aborted', 'AbortError');
	}), { aborted: true });
});
