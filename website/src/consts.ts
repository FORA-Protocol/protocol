/**
 * Canonical outbound links, in one place.
 *
 * These URLs appear on the landing page's "Build with FORA" strip and inside
 * documentation prose. They were duplicated, which is the shape that lets a
 * registry move, a scope change or a rename land in one spot and rot in the
 * others — the reader who follows the stale one gets a 404 and concludes the
 * SDK does not exist. Import from here rather than retyping a URL.
 *
 * Usable from `.astro` and from `.mdx` (Astro compiles MDX, so a plain
 * `import { PACKAGES } from '../../../consts'` works in a docs page).
 */

export interface PackageLink {
	/** Display name, as it appears in link text. */
	readonly label: string;
	/** Registry page for the published package. */
	readonly url: string;
	/** Package coordinate as an installer would spell it. */
	readonly coordinate: string;
	/** Icon under website/public/icons, for the landing-page strip. */
	readonly icon: string;
}

export const PACKAGES = {
	ts: {
		label: 'TypeScript SDK',
		url: 'https://www.npmjs.com/package/@fora-protocol/sdk',
		coordinate: '@fora-protocol/sdk',
		icon: '/icons/typescript.svg',
	},
	python: {
		label: 'Python SDK',
		url: 'https://pypi.org/project/fora-protocol-sdk/',
		coordinate: 'fora-protocol-sdk',
		icon: '/icons/python.svg',
	},
	go: {
		label: 'Go SDK',
		url: 'https://pkg.go.dev/github.com/FORA-Protocol/protocol/sdk/go',
		coordinate: 'github.com/FORA-Protocol/protocol/sdk/go',
		icon: '/icons/go.svg',
	},
} as const satisfies Record<string, PackageLink>;

/** Landing-page strip order: the three SDKs, then FORA Server (the reference implementation, a working exchange). */
export const BUILD_LINKS: readonly PackageLink[] = [
	PACKAGES.ts,
	PACKAGES.python,
	PACKAGES.go,
	{
		label: 'FORA Server',
		url: 'https://github.com/FORA-Protocol/reference-implementation',
		coordinate: 'FORA-Protocol/reference-implementation',
		icon: '/icons/github.svg',
	},
];

export const REPO_URL = 'https://github.com/FORA-Protocol/protocol';

/** The Demo Music Catalog: the music demo's tracks, as people and agents search them. */
export const DEMO_MUSIC_CATALOG_URL = 'https://demo-music.fora-protocol.org/';

/**
 * The landing pages, in nav order. The site nav (SiteNav.astro) and the docs
 * header (DocsSocialIcons.astro) both list them, so they cannot drift apart.
 */
export const LANDING_PAGES = [
	{ key: 'protocol', href: '/protocol/', label: 'Protocol' },
	{ key: 'publishers', href: '/publishers/', label: 'For publishers' },
	{ key: 'music', href: '/music/', label: 'For music' },
	{ key: 'resources', href: '/resources/', label: 'Resources' },
] as const;

export type LandingPageKey = (typeof LANDING_PAGES)[number]['key'];

/**
 * The current version of the Movement for an Open Web's Search Only Terms
 * Contract. Each version has a fixed URL that never changes; a new version
 * gets a new one (https://m4ow.uk/socw/).
 */
export const SEARCH_ONLY_CONTRACT_URL = 'https://m4ow.uk/socw/3.txt';
