// Turning a failed preview call into something a visitor can act on.
//
// Every status and error kind the service can produce is mapped here, in one
// table, so the wording is tested rather than scattered through the page.
// Pure: it takes a status and a parsed body, and returns plain data.

/**
 * Describe a failed call.
 *
 * `networkError` is set when fetch itself rejected, which on this page most
 * often means the browser refused the cross-origin call rather than that the
 * service is down. Returns:
 *   { kind, headline, detail, violations }
 * where each violation is { message, path }.
 */
export function describeFailure({ status, body, networkError } = {}) {
	if (networkError) {
		return {
			kind: 'network',
			headline: "We could not reach the preview service",
			detail: 'The check did not get through. Check your connection and try again.',
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
			violations,
		};
	}

	if (status === 413) {
		return {
			kind: 'too_large',
			headline: 'That request was too long',
			detail: 'Try a shorter article address.',
			violations,
		};
	}

	if (status === 400 || kind === 'invalid_request') {
		return {
			kind: 'invalid_request',
			headline: 'We could not read that request',
			detail: serviceMessage || 'Check the domain and try again.',
			violations,
		};
	}

	if (status === 422 || kind === 'terms_rejected') {
		return {
			kind: 'terms_rejected',
			headline: 'The Exchange would refuse those terms',
			detail: serviceMessage || 'Adjust the terms below and the sample will update.',
			violations,
		};
	}

	if (status === 502 || kind === 'upstream') {
		return {
			kind: 'upstream',
			headline: 'We couldn’t read this page.',
			detail: 'Try again or use another page.',
			violations,
		};
	}

	if (status === 504 || kind === 'timeout') {
		return {
			kind: 'timeout',
			headline: 'We couldn’t read this page.',
			detail: 'Try again or use another page.',
			violations,
		};
	}

	return {
		kind: 'internal',
		headline: 'Something went wrong on our side',
		detail: serviceMessage || 'Try again in a moment.',
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
		}))
		.filter((entry) => entry.message !== '');
}
