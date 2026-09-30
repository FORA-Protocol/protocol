// Email-only interest enquiry. The service accepts an omitted name. The page
// adds what the visitor previewed: the domain, the page URL and any terms
// they changed, all optional on the service side.

/** The path the enquiry posts to, relative to the configured service base. */
export const CONTACT_PATH = '/v1/contact';

/** The service's own bounds, so the page refuses what it would refuse. */
export const MAX_EMAIL_LENGTH = 254;

/** Refuse header line breaks before trimming input. */
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
	if (hasLineBreak(value)) return false;
	const text = String(value ?? '').trim();
	if (text.length === 0 || text.length > MAX_EMAIL_LENGTH) return false;
	if (/\s/.test(text)) return false;
	return /^[^@]+@[^@.]+(\.[^@.]+)+$/.test(text);
}

/**
 * Build the enquiry body.
 *
 * `preview` is the body of the last preview request the service answered, so
 * the enquiry names the same domain, page and terms the visitor just looked at.
 *
 * Returns { ok: true, body } or { ok: false, field, message }, where field is
 * the id of the input the message belongs under.
 */
export function buildContactRequest({ email, preview } = {}) {
	const address = String(email ?? '').trim();
	if (address === '') {
		return { ok: false, field: 'contact-email', message: 'Tell us where to reply.' };
	}
	if (!looksLikeEmail(email)) {
		return { ok: false, field: 'contact-email', message: 'That does not look like an email address we can reply to.' };
	}

	const body = { email: address };
	for (const key of ['domain', 'article_url', 'terms']) {
		if (preview?.[key]) body[key] = preview[key];
	}
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
		return { headline: 'We couldn’t confirm your request', detail: 'Check your connection and try again.' };
	}
	const said = typeof body?.error === 'string' && body.error !== '' ? body.error : '';
	if (status === 429) {
		return { headline: 'Too many messages from your network', detail: 'Wait about a minute, then try again.' };
	}
	if (status === 503) {
		return { headline: 'This page cannot send right now', detail: said || 'Write to us at the address on the site instead.' };
	}
	if (status === 400) {
		return { headline: 'We could not send that', detail: said || 'Check the email address, then try again.' };
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
	if (response.status !== 202 || parsed?.status !== 'sent') {
		return { ok: false, failure: { headline: 'We couldn’t confirm your request', detail: 'Please try again.' } };
	}
	return { ok: true };
}
