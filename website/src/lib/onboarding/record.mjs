// The manifest the console generates for a domain, and the helpers that print
// it as coloured JSON. The offer an agent receives is not JSON on this page --
// see offer-outline.mjs. Pure: no DOM, no fetch.

/**
 * The /.well-known/fora.json the console generates for a domain. It names the
 * Exchange allowed to sell the content, and names the Exchange as the catalog
 * contributor so it can push the catalog on the publisher's behalf.
 */
export function manifestFor(domain, exchangeDomain) {
	return {
		version: '1',
		exchanges: [{
			domain: exchangeDomain,
			endpoint: `https://${exchangeDomain}`,
			supported_profiles: ['fora-news-v1'],
			ext: { resource_owner_id: domain },
		}],
		catalog_contributors: [{ domain: exchangeDomain, relationship: 'operator' }],
	};
}

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
