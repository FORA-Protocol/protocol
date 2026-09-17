// What the page opens on.
//
// The page shows the whole onboarding path straight away rather than an empty
// form, so a visitor sees what they are being offered before typing anything.
// The domain below is the one it previews on load; the result is fetched from
// the preview service like any other, so what a visitor reads is a live check
// and not a stored snapshot.

/** The domain the page previews when it loads. */
export const DEFAULT_DOMAIN = 'demo.fora-protocol.org';

/** How the page names where a record came from, per the service's page.source. */
export const PAGE_SOURCES = {
	'article_url': 'the article you gave us',
	'sitemap': 'your sitemap',
	'home': 'your home page',
};

export function sourcePhrase(pageSource) {
	return PAGE_SOURCES[pageSource] ?? 'your catalog source';
}
