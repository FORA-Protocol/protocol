// How a publisher adopts the Movement for an Open Web's Search Only Terms
// Contract, from MOW's implementation guide (https://m4ow.uk/socw/), checked
// 2026-11-12. One list for the landing pages (ContractSteps.astro) and the
// generator's manual steps; the docs guide
// (/getting-started/search-only-contract/) gives the same steps in full.

export const CONTRACT_GUIDE_URL = 'https://m4ow.uk/socw/';

export interface ContractStep {
  title: string;
  /** May hold inline HTML (a link, <code>). */
  text: string;
}

export const CONTRACT_STEPS: ContractStep[] = [
  {
    title: 'Set your access fee.',
    text: 'The contract sets no default. Choose a fee per item: one price for everything, or one each for written works, images, video, audio and other items. Set it on your own, without agreeing it with other publishers.',
  },
  {
    title: 'Add the contract to your site\'s terms.',
    text: `Two pieces of wording from MOW's <a href="${CONTRACT_GUIDE_URL}">guide</a>: (A) incorporates the contract by its fixed URL, and (B) states your fee. You link the contract and never copy or edit it.`,
  },
  {
    title: 'Add it to robots.txt.',
    text: 'A <code>tdl</code> line in the <code>User-agent: *</code> group tells every crawler where the contract is.',
  },
  {
    title: 'Keep the evidence.',
    text: 'Screenshot each change, and archive your robots.txt with the Internet Archive after you update it.',
  },
];
