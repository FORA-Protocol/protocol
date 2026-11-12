// The AI rules a publisher adds to its site, from three choices and the bot
// list in src/data/ai-bots.ts. Used by the generator (AiRulesGenerator.astro)
// on the server, for the default output, and in the browser, for each change.
//
// Always refused: the training crawlers, the training tokens (Google-Extended,
// Applebot-Extended, __usage_ai-training) and Microsoft training per page.
// Leaving AI search and answers also refuses the AI search crawlers, the live
// fetchers and Copilot grounding.
import { AI_BOTS, type BotKind } from '../data/ai-bots';
import { SEARCH_ONLY_CONTRACT_URL } from '../consts';

export interface RuleChoices {
  /** Stay visible in AI search and answers. */
  visible: boolean;
  /** Attach the search-only contract. */
  contract: boolean;
  /** Add the EU reservation signals (TDMRep, Content Signals). */
  eu: boolean;
  /** The site's own terms page, where the contract's access fee is set. */
  termsUrl: string;
}

export interface Rules {
  robots: string;
  headers: string;
  html: string;
  /** Steps no file can do; may hold links. */
  steps: string[];
}

export const DEFAULT_TERMS_URL = 'https://publisher.example/terms';

export const DEFAULT_CHOICES: RuleChoices = { visible: true, contract: true, eu: true, termsUrl: DEFAULT_TERMS_URL };

const names = (...kinds: BotKind[]) => AI_BOTS.filter((b) => kinds.includes(b.kind)).map((b) => b.name);

export function buildRules({ visible, contract, eu, termsUrl }: RuleChoices): Rules {
  const terms = termsUrl.trim() || DEFAULT_TERMS_URL;
  const url = SEARCH_ONLY_CONTRACT_URL;
  const refused = names('training', 'token').concat(visible ? [] : names('ai-search', 'live-fetch'));

  const robots = ['# AI uses this site does not license without an offer', ...refused.map((n) => `User-agent: ${n}`), 'Disallow: /'];
  const star: string[] = [];
  if (eu) star.push(`Content-Signal: search=yes, ai-train=no${visible ? '' : ', ai-input=no'}`);
  if (contract) star.push(`tdl: ${url}`);
  if (star.length) robots.push('', ...(contract ? [`# License ${url}`] : []), 'User-agent: *', ...star, 'Allow: /');

  const headers = ['X-Robots-Tag: Bingbot: ai-training:disallow'];
  const html = ['<meta name="Bingbot" content="ai-training:disallow" />'];
  if (!visible) {
    headers.push('X-Robots-Tag: Bingbot: ai-grounding:disallow');
    html.push('<meta name="Bingbot" content="ai-grounding:disallow" />');
  }
  if (eu) {
    headers.push('tdm-reservation: 1');
    html.push('<meta name="tdm-reservation" content="1" />');
  }
  if (contract) {
    headers.push(`Link: <${url}>; rel="terms-of-service"`, `Link: <${terms}>; rel="terms-of-service"`);
    html.push(`<link rel="terms-of-service" href="${url}" />`, `<link rel="terms-of-service" href="${terms}" />`);
  }

  const steps: string[] = [];
  if (contract) steps.push('Set your access fee in your terms page: paste the guide\'s wording (A), which incorporates the contract, and (B), which states your fee, and fill in the brackets. The contract itself stays unchanged: <a href="/getting-started/search-only-contract/#adopt-the-contract">the wording to paste</a>.');
  if (!visible) steps.push('In Google Search Console, use the "Search generative AI" setting to keep your site out of AI Overviews and AI Mode. No file can set it.');
  steps.push('Archive your robots.txt with the Internet Archive after each change, as dated evidence.');
  steps.push('Put FORA\'s edge function on the paths you sell. Live fetchers that ignore robots.txt get a 403 that tells them where to buy.');

  return { robots: robots.join('\n'), headers: headers.join('\n'), html: html.join('\n'), steps };
}
