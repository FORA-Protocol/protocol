// The enquiry the page sends when a visitor asks us to get in touch.
//
// The service accepts a name, an address to reply to, and the domain that was
// previewed. It rejects unknown fields and refuses a line break in any of them,
// so this builds exactly those three and refuses the same things before the
// request leaves the browser: a message the service will not send is one the
// visitor should hear about at once, not after a round trip.

/** Every field the contact endpoint accepts. */
export const CONTACT_FIELDS = ['name', 'email', 'domain'];

/** The path the enquiry posts to, relative to the configured service base. */
export const CONTACT_PATH = '/v1/contact';

/** The service's own bounds, so the page refuses what it would refuse. */
export const MAX_NAME_LENGTH = 200;
export const MAX_EMAIL_LENGTH = 254;

/**
 * Whether a value carries a line break.
 *
 * A break in a name or an address is how a mail header is forged. The service
 * refuses one outright; so does this, rather than stripping it, because a value
 * carrying one was not a name.
 */
export function hasLineBreak(value) {
	return /[\r\n]/.test(String(value ?? ''));
}

/**
 * A plain check that an address could be one.
 *
 * Deliberately loose: the service parses it properly and is the authority. This
 * exists to catch the obvious miss before a round trip, not to re-implement
 * RFC 5322 in a page.
 */
export function looksLikeEmail(value) {
	const text = String(value ?? '').trim();
	if (text.length === 0 || text.length > MAX_EMAIL_LENGTH) return false;
	if (hasLineBreak(text) || /\s/.test(text)) return false;
	return /^[^@]+@[^@.]+(\.[^@.]+)+$/.test(text);
}

/**
 * Build the enquiry body.
 *
 * Returns { ok: true, body } or { ok: false, field, message }, where field is
 * the id of the input the message belongs under.
 */
export function buildContactRequest({ name, email, domain } = {}) {
	const person = String(name ?? '').trim();
	if (person === '') {
		return { ok: false, field: 'contact-name', message: 'Tell us your name.' };
	}
	if (person.length > MAX_NAME_LENGTH) {
		return { ok: false, field: 'contact-name', message: `That name is longer than ${MAX_NAME_LENGTH} characters.` };
	}
	if (hasLineBreak(person)) {
		return { ok: false, field: 'contact-name', message: 'A name cannot contain a line break.' };
	}

	const address = String(email ?? '').trim();
	if (address === '') {
		return { ok: false, field: 'contact-email', message: 'Tell us where to reply.' };
	}
	if (!looksLikeEmail(address)) {
		return { ok: false, field: 'contact-email', message: 'That does not look like an email address we can reply to.' };
	}

	const body = { name: person, email: address };
	const site = String(domain ?? '').trim();
	if (site !== '') body.domain = site;
	return { ok: true, body };
}

/**
 * What the visitor reads when an enquiry does not go.
 *
 * The service's own message is used where it has one, because it names what to
 * change. The rest is this page's wording for cases where it does not.
 */
export function describeContactFailure({ status, body, networkError } = {}) {
	if (networkError) {
		return { headline: 'We could not reach us', detail: 'The message did not get through. Check your connection and try again.' };
	}
	const said = typeof body?.error === 'string' && body.error !== '' ? body.error : '';
	if (status === 429) {
		return { headline: 'Too many messages from your network', detail: 'Wait about a minute, then try again.' };
	}
	if (status === 503) {
		return { headline: 'This page cannot send right now', detail: said || 'Write to us at the address on the site instead.' };
	}
	if (status === 400) {
		return { headline: 'We could not send that', detail: said || 'Check the name and the address, then try again.' };
	}
	return { headline: 'The message did not go', detail: said || 'Try again in a moment.' };
}

/**
 * Send one enquiry.
 *
 * fetch is injected, the same way the preview client takes it, so this is
 * testable without a network.
 */
export async function sendContact({ fetchImpl, baseUrl, body, signal } = {}) {
	const url = `${String(baseUrl ?? '').replace(/\/+$/, '')}${CONTACT_PATH}`;
	let response;
	try {
		response = await fetchImpl(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
			signal,
		});
	} catch (error) {
		if (signal?.aborted === true || error?.name === 'AbortError') return { aborted: true };
		return { ok: false, failure: describeContactFailure({ networkError: error }) };
	}

	let parsed = null;
	try {
		parsed = await response.json();
	} catch {
		parsed = null;
	}
	if (!response.ok) {
		return { ok: false, failure: describeContactFailure({ status: response.status, body: parsed }) };
	}
	return { ok: true };
}
