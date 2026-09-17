import test from 'node:test';
import assert from 'node:assert/strict';

import {
	CONTACT_PATH,
	MAX_NAME_LENGTH,
	buildContactRequest,
	describeContactFailure,
	hasLineBreak,
	looksLikeEmail,
	sendContact,
} from './contact.mjs';

test('the body carries only the three fields the service accepts', () => {
	const built = buildContactRequest({ name: 'Olena', email: 'olena@x.example', domain: 'x.example' });
	assert.equal(built.ok, true);
	assert.deepEqual(Object.keys(built.body).sort(), ['domain', 'email', 'name']);
});

test('a preview that named no domain sends none rather than an empty one', () => {
	const built = buildContactRequest({ name: 'Olena', email: 'olena@x.example', domain: '   ' });
	assert.equal(built.ok, true);
	assert.equal('domain' in built.body, false);
});

test('the name and the address are trimmed', () => {
	const built = buildContactRequest({ name: '  Olena  ', email: '  olena@x.example  ' });
	assert.equal(built.body.name, 'Olena');
	assert.equal(built.body.email, 'olena@x.example');
});

test('a line break is refused before the request leaves the browser', () => {
	for (const enquiry of [
		{ name: 'Olena\r\nBcc: someone@elsewhere.example', email: 'olena@x.example' },
		{ name: 'Olena\nBcc: someone@elsewhere.example', email: 'olena@x.example' },
		{ name: 'Olena', email: 'olena@x.example\r\nBcc: a@b.example' },
	]) {
		const built = buildContactRequest(enquiry);
		assert.equal(built.ok, false, `accepted ${JSON.stringify(enquiry)}`);
	}
});

test('what an enquiry must carry, reported against the input it belongs to', () => {
	const cases = [
		[{ email: 'olena@x.example' }, 'contact-name'],
		[{ name: '   ', email: 'olena@x.example' }, 'contact-name'],
		[{ name: 'a'.repeat(MAX_NAME_LENGTH + 1), email: 'olena@x.example' }, 'contact-name'],
		[{ name: 'Olena' }, 'contact-email'],
		[{ name: 'Olena', email: 'olena-at-x' }, 'contact-email'],
		[{ name: 'Olena', email: 'olena@x' }, 'contact-email'],
	];
	for (const [enquiry, field] of cases) {
		const built = buildContactRequest(enquiry);
		assert.equal(built.ok, false, `accepted ${JSON.stringify(enquiry)}`);
		assert.equal(built.field, field);
		assert.ok(built.message.endsWith('.'), 'the message reads as a sentence');
	}
});

test('looksLikeEmail catches the obvious miss and lets an ordinary address through', () => {
	for (const good of ['a@b.example', 'olena.kovalenko@news.publisher.example', "o'brien@x.example"]) {
		assert.equal(looksLikeEmail(good), true, good);
	}
	for (const bad of ['', 'a@b', 'a b@c.example', 'a@@b.example', 'no-at-sign.example']) {
		assert.equal(looksLikeEmail(bad), false, JSON.stringify(bad));
	}
});

test('hasLineBreak sees both kinds', () => {
	assert.equal(hasLineBreak('a\r\nb'), true);
	assert.equal(hasLineBreak('a\nb'), true);
	assert.equal(hasLineBreak('a b'), false);
});

test('a sent enquiry posts JSON to the contact path', async () => {
	const calls = [];
	const outcome = await sendContact({
		fetchImpl: async (url, init) => {
			calls.push({ url, init });
			return { ok: true, status: 202, json: async () => ({ status: 'sent' }) };
		},
		baseUrl: 'https://host.example/onboarding/',
		body: { name: 'Olena', email: 'olena@x.example' },
	});
	assert.equal(outcome.ok, true);
	assert.equal(calls[0].url, `https://host.example/onboarding${CONTACT_PATH}`);
	assert.equal(calls[0].init.method, 'POST');
	assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
});

test('each failure the service can answer with reads as its own sentence', () => {
	assert.match(describeContactFailure({ status: 429 }).headline, /Too many messages/);
	assert.match(describeContactFailure({ status: 503, body: { error: 'this deployment takes no enquiries' } }).detail,
		/takes no enquiries/);
	assert.match(describeContactFailure({ status: 400, body: { error: 'a name is required' } }).detail, /name is required/);
	assert.match(describeContactFailure({ status: 500 }).headline, /did not go/);
	assert.match(describeContactFailure({ networkError: new TypeError('failed') }).detail, /did not get through/);
});

test('a non-2xx comes back as a failure, not a throw', async () => {
	const outcome = await sendContact({
		fetchImpl: async () => ({ ok: false, status: 429, json: async () => ({ error: 'too many' }) }),
		baseUrl: 'https://host.example',
		body: {},
	});
	assert.equal(outcome.ok, false);
	assert.match(outcome.failure.headline, /Too many messages/);
});

test('a cancelled send is reported as aborted, never as a failure', async () => {
	const controller = new AbortController();
	const outcome = await sendContact({
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
