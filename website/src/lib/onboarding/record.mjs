// Printing a JSON document as coloured, escaped HTML.
//
// The documents themselves come from the service: fora.v1.WellKnownManifest
// says what a discovery document must carry, and a page that writes its own
// copy writes one that drifts. The offer is not JSON here at all -- see
// offer-outline.mjs. Pure: no DOM, no fetch.

/** Escape for HTML text content. */
export function escapeHtml(text) {
	return String(text).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

/**
 * Wrap the parts of a JSON document in the spans the stylesheet colours.
 *
 * Tokenising runs on the raw JSON and every piece is escaped as it is emitted.
 * Escaping first would turn every quote into an entity, after which no key or
 * string value can match and only digits and punctuation come out coloured --
 * including the digit inside a quoted "1", which then reads as a number.
 */
export function highlightJson(json) {
	const pattern = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?)|([{}[\],:])|([\s\S])/g;
	let out = '';
	let match;
	while ((match = pattern.exec(String(json))) !== null) {
		const [, str, colon, num, brace, other] = match;
		if (str !== undefined) {
			out += `<span class="${colon ? 'k' : 's'}">${escapeHtml(str)}</span>`;
			if (colon) out += escapeHtml(colon);
		} else if (num !== undefined) {
			out += `<span class="n">${escapeHtml(num)}</span>`;
		} else if (brace !== undefined) {
			out += `<span class="b">${escapeHtml(brace)}</span>`;
		} else {
			out += escapeHtml(other);
		}
	}
	return out;
}
