// The content-marketplaces series (/resources/content-marketplaces/ and the
// pages under it, plus /resources/standards-map/): the texts every page uses
// word for word, so the seven pages say the same thing the same way. A page
// imports a text from here and never types it again. Change a text here and
// every page changes with it.
//
// Texts that hold links are HTML strings; the components render them with
// set:html. "See About FORA." links to the About FORA card, which every page
// carries with id="about".

/** How real a thing is. StatusTag (src/lib/resource-markup.ts) renders these. */
export const STATUS = {
  live: { label: 'Live', means: 'Released and in use.' },
  beta: { label: 'Beta', means: 'Open to sign up, labelled beta by the vendor.' },
  'closed-beta': { label: 'Closed beta', means: 'By admission only.' },
  pilot: { label: 'Pilot', means: 'The vendor\'s own word for a limited program, such as Microsoft\'s PCM.' },
  design: { label: 'Design', means: 'Designed, not in released software. Every FORA design item carries it.' },
  roadmap: { label: 'Roadmap', means: 'Planned, not designed in public.' },
  experimental: { label: 'Experimental', means: 'The vendor\'s own word for a feature it is testing, such as Google\'s Web Bot Auth signing.' },
  preview: { label: 'Preview', means: 'The vendor\'s own word for a released feature it hasn\'t made generally available, such as AWS\'s.' },
  'not-public': { label: 'Not public', means: 'The vendor doesn\'t say.' },
} as const;
export type StatusKey = keyof typeof STATUS;

/**
 * The positioning statement and the tagline the owner approved on 2026-11-15
 * (messaging review, option A), word for word. The About page and the
 * content-marketplaces page both use them.
 */
export const POSITIONING = 'FORA lets any AI agent find your content, read your license, pay and get a signed receipt, on the terms you set. It is an open protocol and free, open-source software, so any company can also run its own FORA marketplace.';
/** The tagline; the <em> phrase is shown in blue. */
export const TAGLINE = 'Every AI agent is a customer. <em>FORA is your storefront.</em>';

/** "See About FORA.", linked to the page's About FORA card. */
export const SEE_ABOUT = 'See <a href="#about">About FORA</a>.';

/**
 * The About FORA card (Callout kind="about"): once per page, near the end.
 * The owner's text of the fifth round (2026-11-15), word for word.
 */
export const ABOUT_FORA: { title: string; text: string }[] = [
  {
    title: 'Federated Open Resource Access.',
    text: 'FORA is an open protocol and free, open-source software. Any company can run its own content marketplace on it, and every FORA marketplace works with every other.',
  },
  {
    title: 'Where it runs.',
    text: 'Gutefrage runs the whole FORA stack itself on helpster.de: its own Exchange, on its own terms.',
  },
  {
    title: 'Ready to try.',
    text: 'Anyone can run FORA\'s Exchange and publisher console: Gutefrage runs its own, and the code is open to clone. Postindustria offers a ready-made deployment with <a href="/getting-started/publisher-onboarding/">a publisher console</a>, so a publisher can try it and start selling. It charges publishers no fee beyond the payment system\'s transaction fees.',
  },
  {
    title: 'Money and disputes.',
    text: 'Money moves outside the protocol: your operator bills the buyer and pays you under its own rules. The protocol defines a dispute call, filed against a usage report, and each operator handles disputes under its own rules.',
  },
];

/**
 * FORA's terms, each explained once (Callout kind="define"), where the term
 * first matters on a page. Spread one into a Callout:
 * `<Callout kind="define" {...DEFINITIONS.exchange} />`.
 */
export const DEFINITIONS = {
  exchange: {
    tag: 'What is an Exchange?',
    text: 'An Exchange represents publishers\' catalogs. One Exchange can serve as many publishers as needed with no loss for any of them, because every URL is a separate listing with its own terms. Publishers share an Exchange when they\'re happy with how its operator settles.',
  },
  broker: {
    tag: 'What is a Broker?',
    text: 'A search service for AI agents. It asks Exchanges for their signed offers and returns them in order of relevance, optionally narrowed to the kinds of license the agent asks for. The agent decides what it buys, where and why. A Broker never buys, sells or charges, and it can\'t change an offer.',
  },
  operator: {
    tag: 'What is an operator?',
    text: 'The company that runs an Exchange, and often the publisher console that comes with it. It bills buyers and pays publishers under its own rules.',
  },
  edgeFunction: {
    tag: 'What is the edge function?',
    text: 'FORA\'s small program on your CDN, on Cloudflare or Amazon CloudFront. On the paths you license, it refuses AI bots that come without a signed link, and serves the agents that bring one. Readers and search crawlers pass as before.',
  },
  signedLink: {
    tag: 'What is a signed link?',
    text: 'A short-lived link to one page, bound to the agent that bought it. Your CDN checks it before your site serves the page.',
  },
  dealTerm: {
    tag: 'What is a deal term?',
    text: 'For a buyer that already pays you under a contract, your Exchange can show a term priced at zero that only agents naming that deal see. The buyer still owes a usage report. The Exchange doesn\'t verify the name. A false claim is signed, so it can be traced to the key that signed it.',
  },
} as const;

/**
 * The search callout's FORA half. A vendor page writes one or two sentences
 * on what the vendor does to search crawlers, then this text and these links:
 * `<Callout kind="search" text={SEARCH_FORA.text} links={SEARCH_FORA.links}>…</Callout>`.
 */
export const SEARCH_FORA = {
  text: 'FORA\'s edge never refuses Googlebot, Bingbot or Applebot. On the paths you license it refuses AI bots that come without a signed link, AI search crawlers such as PerplexityBot included, by default. The lists are yours to change.',
  links: [
    { href: '/resources/ai-crawlers/', text: 'How to control which bots get in →' },
    { href: '/components/edge-function/bot-detection/', text: 'Bot detection' },
  ],
};

/** The comparison table's eight questions, in this order, on every vendor page. */
export const COMPARE_QUESTIONS = [
  'How do you say what\'s for sale?',
  'How does a buyer find your content?',
  'Who is the buyer, provably?',
  'What lets a given use happen?',
  'Who sets the price, in what unit?',
  'How does money move?',
  'What do you see?',
  'What if the numbers are wrong?',
] as const;

type Eight<T> = [T, T, T, T, T, T, T, T];

/** One [vendor, FORA] pair per question, in the order of COMPARE_QUESTIONS. */
export function compareRows(cells: Eight<[string, string]>) {
  return COMPARE_QUESTIONS.map((q, i) => ({ q, cells: cells[i] }));
}

/** At a glance (GlanceCard): two groups, the same rows in the same order on every vendor page. */
export const GLANCE_GROUPS = [
  {
    name: 'Money',
    rows: [
      { key: 'payer', label: 'Who pays you, and when' },
      { key: 'fees', label: 'Fees' },
      { key: 'reporting', label: 'What you see' },
      { key: 'contract', label: 'Contract' },
      { key: 'status', label: 'Status' },
    ],
  },
  {
    name: 'Your stack',
    rows: [
      { key: 'dns', label: 'DNS' },
      { key: 'cdn', label: 'CDN' },
      { key: 'firewall', label: 'Firewall and bot shield' },
      { key: 'site', label: 'Your site and CMS' },
      { key: 'search', label: 'Search traffic' },
      { key: 'upkeep', label: 'Upkeep' },
      { key: 'leaving', label: 'Leaving' },
    ],
  },
] as const;
export type GlanceKey = (typeof GLANCE_GROUPS)[number]['rows'][number]['key'];

/** The GlanceCard's groups, from one [vendor, FORA] pair per row key. */
export function glanceGroups(cells: Record<GlanceKey, [string, string]>) {
  return GLANCE_GROUPS.map((g) => ({
    name: g.name,
    rows: g.rows.map((r) => ({ label: r.label, cells: cells[r.key] })),
  }));
}

/** FORA's cells that read the same on every page (settled 2026-11-15; CDN, fifth round). */
export const FORA_CELLS = {
  /** GlanceCard, "Who pays you, and when". */
  payer: `Your Exchange operator, under its own terms. ${SEE_ABOUT}`,
  /** GlanceCard, "Fees". */
  fees: `No Exchange fee at FORA's publisher console, beyond the payment system's. ${SEE_ABOUT}`,
  /** GlanceCard, "CDN" (fifth round: a drop-in, no minutes). */
  cdn: 'A drop-in edge function. The rest depends on your own setup; FORA adds to what you run rather than replacing it.',
  /** GlanceCard, "Leaving". */
  leaving: 'Delete the edge function from your CDN.',
  /** Comparison table, "How does money move?". */
  money: `Outside the protocol. ${SEE_ABOUT}`,
  /** Comparison table, "What if the numbers are wrong?". */
  disputes: `Defined in the protocol, handled under your operator's rules. ${SEE_ABOUT}`,
};

/** The series' section on the Resources index. */
export const SERIES_SECTION = {
  name: 'Content marketplaces and standards',
  intro: 'Who pays publishers for AI use today, how each channel works on your site, and which standards declare what. Start with the map.',
};

export interface SeriesPage {
  href: string;
  title: string;
  /** The Resources index card. */
  summary: string;
  audience: string;
  formats: string[];
  updated: string;
  /**
   * False until the page exists. The Resources index lists only built pages,
   * so it never links a route the site doesn't serve; "More in this series"
   * lists all seven, as the copy has it.
   */
  built: boolean;
}

/** The seven pages, in the order the index and "More in this series" list them. */
export const SERIES: SeriesPage[] = [
  {
    href: '/resources/content-marketplaces/',
    title: 'Content marketplaces and FORA',
    summary: 'Who pays publishers for AI use of their content today, how each channel works, what your engineers change for it, and how FORA, the open protocol any company can run a marketplace on, works beside all of them.',
    audience: 'Publishers',
    formats: ['Guide', 'Map'],
    updated: '2026-11-15',
    built: true,
  },
  {
    href: '/resources/content-marketplaces/tollbit/',
    title: 'TollBit and FORA',
    summary: 'How TollBit charges AI bots for your pages, what your engineers set up for it, and how to run both on one site.',
    audience: 'Publishers and engineers',
    formats: ['Guide'],
    updated: '2026-11-15',
    built: true,
  },
  {
    href: '/resources/content-marketplaces/cloudflare/',
    title: 'Cloudflare and FORA',
    summary: 'How Cloudflare charges AI crawlers at its edge, what that takes on your site, and how a publisher on Cloudflare can run both.',
    audience: 'Publishers and engineers',
    formats: ['Guide'],
    updated: '2026-11-15',
    built: true,
  },
  {
    href: '/resources/content-marketplaces/microsoft-pcm/',
    title: 'Microsoft Publisher Content Marketplace and FORA',
    summary: 'How Microsoft\'s pilot marketplace licenses content to Copilot, what it asks of your site, and how to use both.',
    audience: 'Publishers',
    formats: ['Guide'],
    updated: '2026-11-15',
    built: true,
  },
  {
    href: '/resources/content-marketplaces/prorata-gist/',
    title: 'ProRata.ai and Gist, and FORA',
    summary: 'How ProRata pays a share of each Gist answer, what Gist Answers needs from your site, and how to run both.',
    audience: 'Publishers',
    formats: ['Guide'],
    updated: '2026-11-15',
    built: true,
  },
  {
    href: '/resources/content-marketplaces/perplexity/',
    title: "Perplexity's Publishers' Program and Comet Plus, and FORA",
    summary: 'How Comet Plus is built to pay publishers from subscription revenue, what it asks of your site, and how to run both.',
    audience: 'Publishers',
    formats: ['Guide'],
    updated: '2026-11-15',
    built: true,
  },
  {
    href: '/resources/standards-map/',
    title: 'The standards map',
    summary: 'Thirteen open standards tell a machine something about your content: what each answers, who uses it, how they stack, and where FORA sits.',
    audience: 'Publishers and engineers',
    formats: ['Guide', 'Table'],
    updated: '2026-11-15',
    built: true,
  },
];
