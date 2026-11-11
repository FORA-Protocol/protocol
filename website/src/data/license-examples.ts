// The two worked examples in "If you can write it in a contract". The audience
// switch at the top of the section shows one of them: the offer card, the
// quote, the table and the demo link all change with it. Both tables have the
// same rows, so they line up.
// The track is the music demo (/getting-started/live-demo-music/, Harmonia
// Records); the article is an example.
export const EXAMPLES = [
  {
    id: 'article',
    tab: 'For publishers',
    sub: 'Articles, pages, data',
    icon: 'doc',
    quote: "That is why most publishers can only block AI crawlers or sign a one-off deal with one AI company. A search index, an AI answer and a training run are different uses, worth different prices, and robots.txt can only say yes or no. <strong>FORA gives each use its own price and terms.</strong>",
    demo: { text: 'This demo runs on a live exchange. You can try it today.', href: '/getting-started/poc-walkthrough/', link: 'See what an agent gets for an article' },
    title: 'One article, four terms',
    cols: ['Search and citation', 'AI answer input', 'AI answers, subscribers', 'AI training'],
    rows: [
      { label: 'How it is paid', cells: ['Free', 'Per fetch', 'Subscription', 'Not offered'] },
      { label: 'Who may buy', cells: ['Any identified agent', 'Any identified agent', 'Agents of your subscribers', '—'] },
      { label: 'Allowed', cells: ['Search index, citation', 'Input to an AI answer', 'Input to an AI answer', '—'] },
      { label: 'Not allowed', cells: ['AI training', 'AI training', 'AI training', '—'] },
      { label: 'Obligations', cells: ['Attribution', 'Attribution; usage report', 'Attribution; usage report', '—'] },
    ],
    note: 'You set your own uses and prices. A subscription is a term that only your subscribers\' agents see; the fee is agreed outside the offer.',
    offer: {
      name: 'AI answer input',
      fields: [
        ['who may buy', 'any identified agent'],
        ['allowed', 'ai-input'],
        ['not allowed', 'ai-train'],
        ['where', 'worldwide'],
        ['for how long', 'one answer'],
        ['price', 'USD 0.05 per fetch'],
        ['obligations', 'attribution, usage report'],
        ['license', 'news.example/license.txt'],
      ],
      digest: 'license sha256:4c1f9a07…',
      note: 'An offer for one article.',
    },
  },
  {
    id: 'track',
    tab: 'For music',
    sub: 'Tracks, stems, catalogs',
    icon: 'note',
    quote: 'That is why sync, the hardest kind of music licensing, still gets sold by email and rate-card PDF. Media, territory, term, cue sheets and exclusions are hard to express in a form a machine can act on. <strong>FORA expresses all of them.</strong>',
    demo: { text: 'This demo runs on a live exchange. You can try it today.', href: '/getting-started/live-demo-music/', link: 'Watch an agent license a track' },
    title: 'One track, four licenses',
    cols: ['Online Creator', 'Broadcast', 'Advertising', 'Creator subscription'],
    rows: [
      { label: 'How it is paid', cells: ['One-time fee', 'One-time fee', 'One-time fee', 'Subscription'] },
      { label: 'Who may buy', cells: ['Individuals', 'Broadcasters, companies', 'Companies', 'Agents of your subscribers'] },
      { label: 'Allowed', cells: ['Personal video, online', 'Sync, broadcast, streaming', 'Sync, advertising, broadcast, streaming', 'Personal video, online'] },
      { label: 'Not allowed', cells: ['Commercial use, AI training', 'Advertising, AI training', 'Editorial, AI training', 'Commercial use, AI training'] },
      { label: 'Obligations', cells: ['Attribution', 'One production; cue sheet through the broadcaster', 'One ad; placement records; cue sheet for TV', 'Attribution'] },
    ],
    note: 'The first three are the licenses of the music demo. A subscription is a term that only your subscribers\' agents see; the fee is agreed outside the offer.',
    offer: {
      name: 'Online Creator',
      fields: [
        ['who may buy', 'individual'],
        ['allowed', 'sync, stream'],
        ['not allowed', 'ai-train, advertising, broadcast'],
        ['where', 'worldwide'],
        ['for how long', 'perpetual, 1 production'],
        ['price', 'EUR 29, once'],
        ['obligations', 'attribution'],
        ['license', 'music-v0.1.txt'],
      ],
      digest: 'license sha256:bfab2a18…',
      note: 'An offer from the music demo.',
    },
  },
];
