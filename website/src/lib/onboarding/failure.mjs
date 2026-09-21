// Turning a failed preview call into something a visitor can act on.
//
// Every status and error kind the service can produce is mapped here, in one
// table, so the wording is tested rather than scattered through the page.
// Pure: it takes a status and a parsed body, and returns plain data.

/**
 * Which form control a violation belongs to. The service reports a field path;
 * the page needs the id of the input to attach the message to.
 */
const FIELD_FOR_PATH = {
	'domain': 'domain',
	'article_url': 'article',
	'terms': 'pricing-model',
	'terms.pricing_model': 'pricing-model',
	'terms.rate': 'rate',
	'terms.permitted_functions': 'uses',
	'terms.prohibited_functions': 'uses',
	'terms.attribution_required': 'attribution',
};

/** How long to stop sending automatically after the rate limit answers. */
export const RATE_LIMIT_COOLDOWN_MS = 60_000;

/**
 * Map a violation path onto a control id, or null when it names something the
 * page has no control for. Array indices are dropped so terms[0].rate and
 * terms.rate reach the same control.
 */
export function fieldForPath(path) {
	const normalized = String(path ?? '').replace(/\[\d+\]/g, '').replace(/^\./, '');
	if (normalized === '') return null;
	if (FIELD_FOR_PATH[normalized]) return FIELD_FOR_PATH[normalized];
	const parent = normalized.split('.').slice(0, -1).join('.');
	return FIELD_FOR_PATH[parent] ?? null;
}

/**
 * Describe a failed call.
 *
 * `networkError` is set when fetch itself rejected, which on this page most
 * often means the browser refused the cross-origin call rather than that the
 * service is down. Returns:
 *   { kind, headline, detail, retryable, cooldownMs, violations }
 * where each violation is { message, path, field }.
 */
export function describeFailure({ status, body, networkError } = {}) {
	if (networkError) {
		return {
			kind: 'network',
			headline: "We could not reach the preview service",
			detail: 'The check did not get through. Check your connection and try again.',
			retryable: true,
			cooldownMs: 0,
			violations: [],
		};
	}

	const kind = typeof body?.kind === 'string' && body.kind !== '' ? body.kind : null;
	const serviceMessage = typeof body?.error === 'string' && body.error !== '' ? body.error : '';
	const violations = describeViolations(body?.violations);

	if (status === 429) {
		return {
			kind: 'rate_limited',
			headline: 'Too many previews from your network',
			detail: 'Wait about a minute, then try again.',
			retryable: true,
			cooldownMs: RATE_LIMIT_COOLDOWN_MS,
			violations,
		};
	}

	if (status === 413) {
		return {
			kind: 'too_large',
			headline: 'That request was too long',
			detail: 'Try a shorter article address.',
			retryable: true,
			cooldownMs: 0,
			violations,
		};
	}

	if (status === 400 || kind === 'invalid_request') {
		return {
			kind: 'invalid_request',
			headline: 'We could not read that request',
			detail: serviceMessage || 'Check the domain and try again.',
			retryable: true,
			cooldownMs: 0,
			violations,
		};
	}

	if (status === 422 || kind === 'terms_rejected') {
		return {
			kind: 'terms_rejected',
			headline: 'The Exchange would refuse those terms',
			detail: serviceMessage || 'Adjust the terms below and the sample will update.',
			retryable: true,
			cooldownMs: 0,
			violations,
		};
	}

	if (status === 502 || kind === 'upstream') {
		return {
			kind: 'upstream',
			headline: 'We couldn’t read this page.',
			detail: 'Try again or use another page.',
			retryable: true,
			cooldownMs: 0,
			violations,
		};
	}

	if (status === 504 || kind === 'timeout') {
		return {
			kind: 'timeout',
			headline: 'We couldn’t read this page.',
			detail: 'Try again or use another page.',
			retryable: true,
			cooldownMs: 0,
			violations,
		};
	}

	return {
		kind: 'internal',
		headline: 'Something went wrong on our side',
		detail: serviceMessage || 'Try again in a moment.',
		retryable: true,
		cooldownMs: 0,
		violations,
	};
}

function describeViolations(raw) {
	if (!Array.isArray(raw)) return [];
	return raw
		.filter((entry) => entry && typeof entry === 'object')
		.map((entry) => ({
			message: String(entry.message ?? '').trim(),
			path: String(entry.path ?? '').trim(),
			field: fieldForPath(entry.path),
		}))
		.filter((entry) => entry.message !== '');
}
