// Building the preview request body.
//
// The service rejects unknown fields and caps the body at 8192 bytes, so this
// module owns the exact field set and nothing here guesses. It is pure: no
// fetch, no DOM, no clock.

/** Every field the preview endpoint accepts, at the top level. */
export const REQUEST_FIELDS = ['domain', 'article_url', 'terms'];

/** Every field the nested terms object accepts. */
export const TERMS_FIELDS = [
	'pricing_model',
	'rate',
	'permitted_functions',
	'prohibited_functions',
	'attribution_required',
];

/** The service's own limit, in bytes. */
export const MAX_BODY_BYTES = 8192;

/** At most six fraction digits; more precision than that is a typo, not a price. */
const MAX_RATE_DECIMALS = 6;

/**
 * Reduce what a visitor typed to a bare host.
 *
 * Accepts "https://example.com/blog", "Example.COM.", " example.com " and
 * returns "example.com". Returns an empty string when nothing usable is left.
 */
export function normalizeDomain(raw) {
	let text = String(raw ?? '').trim().toLowerCase();
	if (text === '') return '';

	const scheme = /^([a-z][a-z0-9+.-]*):\/\//.exec(text)?.[1] ?? '';
	text = text.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
	text = text.replace(/^[^/@]*@/, '');
	text = text.split('/')[0].split('?')[0].split('#')[0];

	// A port is part of a bare domain on the wire, and a different port is a
	// different service, so it stays. Only the port a scheme already implies is
	// dropped, because writing it out changes nothing.
	const port = /:(\d+)$/.exec(text)?.[1] ?? '';
	if (port !== '' && ((scheme === 'https' && port === '443') || (scheme === 'http' && port === '80'))) {
		text = text.slice(0, -(port.length + 1));
	}

	const host = text.replace(/:\d+$/, '').replace(/\.+$/, '');
	const suffix = text.slice(host.length).replace(/^\.+/, '');
	if (!/^[a-z0-9.-]+$/.test(host)) return '';
	if (!host.includes('.')) return '';
	if (host.startsWith('.') || host.startsWith('-') || host.endsWith('-')) return '';
	if (suffix !== '' && !/^:\d{1,5}$/.test(suffix)) return '';
	return host + suffix;
}

/**
 * Keep an article URL only when it is an absolute http(s) URL. Anything else is
 * dropped rather than sent, because the field is optional and a bad value costs
 * the visitor a round trip that can only fail.
 */
export function normalizeArticleUrl(raw) {
	const text = String(raw ?? '').trim();
	if (text === '') return '';
	let parsed;
	try {
		parsed = new URL(text);
	} catch {
		return '';
	}
	if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return '';
	return parsed.toString();
}

/**
 * Turn a price into the plain decimal string the service expects.
 *
 * A number input hands back things like "1e-3" and ".5", which are valid to the
 * browser and wrong on the wire. Returns null when the value is not a
 * non-negative decimal, or carries more precision than MAX_RATE_DECIMALS.
 */
export function formatRate(raw) {
	const text = String(raw ?? '').trim();
	if (text === '') return null;
	const match = /^\+?(\d*)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/.exec(text);
	if (!match) return null;

	const intPart = match[1] ?? '';
	const fracPart = match[2] ?? '';
	if (intPart === '' && fracPart === '') return null;

	const exponent = match[3] ? Number.parseInt(match[3], 10) : 0;
	let digits = intPart + fracPart;
	let point = intPart.length + exponent;

	if (point <= 0) {
		digits = '0'.repeat(-point) + digits;
		point = 0;
	}
	if (point >= digits.length) {
		digits += '0'.repeat(point - digits.length);
	}

	let head = digits.slice(0, point).replace(/^0+(?=\d)/, '');
	const tail = digits.slice(point).replace(/0+$/, '');
	if (head === '') head = '0';
	if (tail.length > MAX_RATE_DECIMALS) return null;
	return tail === '' ? head : `${head}.${tail}`;
}

/** True when a formatted rate is zero, whatever it was written as. */
export function isZeroRate(formatted) {
	return formatted !== null && /^0(\.0*)?$/.test(formatted);
}

/** Byte length of the body as it will be sent. */
export function bodyByteLength(body) {
	return new TextEncoder().encode(JSON.stringify(body)).length;
}

/**
 * Build the request body.
 *
 * `controls` being null is meaningful rather than lazy: with no terms in the
 * request, the service reads the licensing document the site already publishes
 * and reports where the terms came from. The page sends terms only once the
 * visitor has changed something.
 *
 * Returns { ok: true, body } or { ok: false, field, message }.
 */
export function buildPreviewRequest({ domain, articleUrl, controls } = {}) {
	const host = normalizeDomain(domain);
	if (host === '') {
		return {
			ok: false,
			field: 'domain',
			message: 'Enter a domain, for example example.com.',
		};
	}

	const body = { domain: host };

	const article = normalizeArticleUrl(articleUrl);
	if (String(articleUrl ?? '').trim() !== '' && article === '') {
		return {
			ok: false,
			field: 'article',
			message: 'That article address is not a full URL. Include https:// at the start.',
		};
	}
	if (article !== '') {
		body.article_url = article;
	}

	if (controls) {
		const terms = buildTerms(controls);
		if (!terms.ok) return terms;
		body.terms = terms.terms;
	}

	if (bodyByteLength(body) > MAX_BODY_BYTES) {
		return {
			ok: false,
			field: 'article',
			message: 'That request is too long. Try a shorter article address.',
		};
	}

	return { ok: true, body };
}

function buildTerms(controls) {
	const model = String(controls.pricingModel ?? '');
	if (model === '') {
		return { ok: false, field: 'pricing-model', message: 'Choose a pricing model.' };
	}

	const terms = { pricing_model: model };

	if (model !== 'free') {
		const rate = formatRate(controls.rate);
		if (rate === null) {
			return {
				ok: false,
				field: 'rate',
				message: 'Enter a price as a plain number, for example 0.002.',
			};
		}
		if (isZeroRate(rate)) {
			return {
				ok: false,
				field: 'rate',
				message: 'A paid term needs a price above zero. Choose Free instead.',
			};
		}
		terms.rate = rate;
	}

	// Every offered token lands in exactly one list, so the two can never
	// overlap and an unchecked use is explicitly refused rather than unstated.
	const offered = Array.isArray(controls.offeredFunctions) ? controls.offeredFunctions : [];
	const permittedSet = new Set(Array.isArray(controls.permittedFunctions) ? controls.permittedFunctions : []);
	const permitted = offered.filter((token) => permittedSet.has(token));
	const prohibited = offered.filter((token) => !permittedSet.has(token));

	if (permitted.length > 0) terms.permitted_functions = permitted;
	if (prohibited.length > 0) terms.prohibited_functions = prohibited;

	if (controls.attributionRequired) terms.attribution_required = true;

	return { ok: true, terms };
}
