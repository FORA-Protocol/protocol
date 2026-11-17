// The Resources section (/resources/): one entry per topic, in the order the
// index lists them. A topic has one page that holds its article and its
// formats (slides, a generator, a video); `formats` names what that page has.
// Topics that live elsewhere on the site link there. A topic with a `section`
// is listed under that section's heading (SECTIONS), after the topics
// without one; a series of pages, such as the content marketplaces, is one
// section.
import { SERIES, SERIES_SECTION } from './content-marketplaces';

export interface Resource {
  href: string;
  title: string;
  summary: string;
  audience: string;
  formats: string[];
  /** ISO date of the last substantive update. */
  updated: string;
  /** The name of the section the index lists it under; one of SECTIONS. */
  section?: string;
}

/** The index's sections, in order, each with a heading and an intro. */
export const SECTIONS: { name: string; intro: string }[] = [SERIES_SECTION];

export const RESOURCES: Resource[] = [
  {
    href: '/resources/ai-crawlers/',
    title: 'What you can do about AI crawlers today',
    summary: 'Refuse AI training in the form each AI company honors, stay in search and in the AI answers that cite you, and put a price on the rest. With a generator for your robots.txt and headers.',
    audience: 'Publishers',
    formats: ['Guide', 'Generator'],
    updated: '2026-11-12',
  },
  {
    href: '/resources/web-bot-auth/',
    title: 'Web Bot Auth: how an AI agent proves who it is',
    summary: 'How an AI agent signs its requests with a key on its own website, and how your site checks it. Who signs, how keys rotate and are revoked, what to ask your CDN, and how FORA uses it.',
    audience: 'Publishers and engineers',
    formats: ['Guide'],
    updated: '2026-11-16',
  },
  {
    href: '/resources/agent-identity/',
    title: 'How AI agents prove who they are, and what they may do',
    summary: 'Four questions about any AI agent: who it is, whom it acts for, what it may do, and who pays. Which standard answers each, from Web Bot Auth and OAuth to card networks, and what you need for what you sell.',
    audience: 'Publishers and engineers',
    formats: ['Guide'],
    updated: '2026-11-16',
  },
  {
    href: '/resources/transparent-collective/',
    title: 'A fair licensing collective',
    summary: 'How a fair AI licensing collective works on FORA: published money, your own terms per URL, a signed record of every fetch. With a scorecard of the eight schemes running or announced today.',
    audience: 'Publishers and collectives',
    formats: ['Guide', 'Scorecard'],
    updated: '2026-11-14',
  },
  {
    href: '/resources/music-dsp/',
    title: 'FORA for a music DSP',
    summary: 'How a streaming service pays rights holders from a pool, and the FORA term for each part: the license, the stream, the pool, the split, the report, the audit and the ranking. With three ways to split a pool.',
    audience: 'Music rights holders and builders',
    formats: ['Guide', 'Diagrams'],
    updated: '2026-11-14',
  },
  {
    href: '/protocol/#licensing-core',
    title: 'The Universal Licensing Core',
    summary: 'How any license, from CC BY to a TV sync license, becomes one model an agent can act on, clause by clause. With the same license in RSL and in IAB CoMP, and what each can\'t say.',
    audience: 'Publishers and engineers',
    formats: ['Slides', 'License explorer'],
    updated: '2026-11-14',
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
  // The content-marketplaces series, in its own order; a page is listed once it is built.
  ...SERIES.filter((p) => p.built).map(({ href, title, summary, audience, formats, updated }) => ({
    href, title, summary, audience, formats, updated, section: SERIES_SECTION.name,
  })),
];

/** The date a resource page shows in its hero: its entry's `updated`. */
export function resourceUpdated(href: string): string | undefined {
  return RESOURCES.find((r) => r.href === href)?.updated;
}
