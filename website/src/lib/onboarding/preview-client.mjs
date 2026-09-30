// The preview request; the contact form uses its own client.
//
// fetch is injected rather than captured so the module can be tested without a
// network and without a DOM. The caller owns the AbortController.

import { describeFailure } from './failure.mjs';

/** The preview endpoint, relative to the configured service base. */
export const PREVIEW_PATH = '/v1/preview';

/** Join the configured base with the endpoint path, whatever trailing slashes it carries. */
export function previewUrl(baseUrl) {
	return `${String(baseUrl ?? '').replace(/\/+$/, '')}${PREVIEW_PATH}`;
}

/**
 * Send one preview request.
 *
 * Returns { ok: true, data }, { ok: false, failure }, or { aborted: true } when
 * the caller cancelled it — an abort is not a failure and must not be rendered
 * as one.
 */
export async function fetchPreview({ fetchImpl, baseUrl, body, signal } = {}) {
	let response;
	try {
		response = await fetchImpl(previewUrl(baseUrl), {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
			signal,
		});
	} catch (error) {
		if (isAbort(error, signal)) return { aborted: true };
		return { ok: false, failure: describeFailure({ networkError: error }) };
	}

	let parsed = null;
	try {
		parsed = await response.json();
	} catch (error) {
		if (isAbort(error, signal)) return { aborted: true };
		parsed = null;
	}

	if (!response.ok) {
		return { ok: false, failure: describeFailure({ status: response.status, body: parsed }) };
	}
	if (parsed === null || typeof parsed !== 'object') {
		return { ok: false, failure: describeFailure({ status: response.status, body: null }) };
	}
	return { ok: true, data: parsed };
}

function isAbort(error, signal) {
	return signal?.aborted === true || error?.name === 'AbortError';
}
