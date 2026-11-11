// The Resources section (/resources/): one entry per topic, in the order the
// index lists them. A topic has one page that holds its article and its
// formats (slides, a generator, a video); `formats` names what that page has.
// Topics that live elsewhere on the site link there.

export interface Resource {
  href: string;
  title: string;
  summary: string;
  audience: string;
  formats: string[];
  /** ISO date of the last substantive update. */
  updated: string;
}

export const RESOURCES: Resource[] = [
  {
    href: '/resources/ai-crawlers/',
    title: 'What you can do about AI crawlers today',
    summary: 'Refuse training in the form each AI company honors, stay in search and in the AI answers that cite you, and put a price on the rest. With a generator for your robots.txt and headers.',
    audience: 'Publishers',
    formats: ['Guide', 'Generator', 'Slides'],
    updated: '2026-11-11',
  },
  {
    href: '/protocol/#licensing-core',
    title: 'The Universal Licensing Core',
    summary: 'How any license, from CC BY to a TV sync license, becomes one model an agent can act on, clause by clause.',
    audience: 'Publishers and engineers',
    formats: ['Slides', 'License explorer'],
    updated: '2026-11-11',
  },
  {
    href: '/getting-started/search-only-contract/',
    title: 'The search-only contract',
    summary: 'Free search indexing and a fee for every other access, attached to your whole site in a few lines.',
    audience: 'Publishers',
    formats: ['Guide'],
    updated: '2026-11-11',
  },
  {
    href: '/getting-started/poc-walkthrough/',
    title: 'Live demo: an agent buys a license',
    summary: 'An AI agent meets a page that refuses it, buys a license instead, and gets a signed receipt.',
    audience: 'Everyone',
    formats: ['Walkthrough'],
    updated: '2026-10-09',
  },
  {
    href: '/getting-started/live-demo-music/',
    title: 'Live demo: an agent licenses a track',
    summary: 'An agent finds a track in a music catalog and buys two different licenses to it.',
    audience: 'Music rights holders',
    formats: ['Walkthrough'],
    updated: '2026-11-10',
  },
];
