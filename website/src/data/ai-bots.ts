// The AI bots and robots.txt tokens a publisher deals with, sorted by what
// each one does, from each vendor's own documentation. One list for the site:
// the AI crawler resource (/resources/ai-crawlers/) and its generator read it,
// and it is published at /registry/ai-bots.json for the edge package and the
// publisher console. Change it here when a vendor changes what a bot does,
// and update CHECKED.
//
// kind:
//   training   collects pages to train models or build datasets
//   live-fetch loads a page because a person asked; often ignores robots.txt
//   ai-search  builds the index the vendor's AI search and answers draw on
//   search     a search engine's crawler that also feeds its AI features
//   token      a robots.txt token only; no crawler sends it as a User-Agent

export const CHECKED = '2026-11-11';

export type BotKind = 'training' | 'live-fetch' | 'ai-search' | 'search' | 'token';

export interface AiBot {
  /** The User-Agent substring, or the robots.txt token for kind "token". */
  name: string;
  vendor: string;
  kind: BotKind;
  /** What it is for, in a few words. */
  purpose: string;
  /** Whether the vendor says it follows robots.txt. "not always" quotes
   * vendors that say it "may not apply", "may bypass" or "generally ignores". */
  robots: 'yes' | 'not always' | 'not stated';
  /** What refusing it costs the site, per the vendor. */
  cost?: string;
  /** The vendor's documentation. */
  source?: string;
}

const OPENAI = 'https://developers.openai.com/api/docs/bots';
const ANTHROPIC = 'https://support.claude.com/en/articles/8896518-robots-txt-controls';
const META = 'https://developers.facebook.com/docs/sharing/webmasters/web-crawlers/';
const AMAZON = 'https://developer.amazon.com/docs/amazonbot/amazonbot.html';
const MISTRAL = 'https://docs.mistral.ai/robots';
const PERPLEXITY = 'https://docs.perplexity.ai/docs/resources/perplexity-crawlers';
const GOOGLE_COMMON = 'https://developers.google.com/crawling/docs/crawlers-fetchers/google-common-crawlers';
const GOOGLE_USER = 'https://developers.google.com/crawling/docs/crawlers-fetchers/google-user-triggered-fetchers';
const APPLE = 'https://support.apple.com/en-us/119829';
const BING = 'https://blogs.bing.com/search/2026/10/your-content-your-choice-clearer-preferences-for-training-and-grounding/';

export const AI_BOTS: AiBot[] = [
  // training
  { name: 'GPTBot', vendor: 'OpenAI', kind: 'training', purpose: 'Model training', robots: 'yes', source: OPENAI },
  { name: 'ClaudeBot', vendor: 'Anthropic', kind: 'training', purpose: 'Model training', robots: 'yes', source: ANTHROPIC },
  { name: 'Meta-ExternalAgent', vendor: 'Meta', kind: 'training', purpose: 'Model training and indexing', robots: 'yes', source: META },
  { name: 'Amazonbot', vendor: 'Amazon', kind: 'training', purpose: 'Model training and Amazon products', robots: 'yes', source: AMAZON },
  { name: 'MistralAI-Training', vendor: 'Mistral', kind: 'training', purpose: 'Model training', robots: 'yes', source: MISTRAL },
  { name: 'CCBot', vendor: 'Common Crawl', kind: 'training', purpose: 'An open web corpus that AI labs train on', robots: 'yes', source: 'https://commoncrawl.org/ccbot' },
  { name: 'Bytespider', vendor: 'ByteDance', kind: 'training', purpose: 'Crawling for ByteDance', robots: 'not stated' },
  { name: 'AI2Bot', vendor: 'Allen Institute for AI', kind: 'training', purpose: 'Training open language models', robots: 'not stated' },
  { name: 'Diffbot', vendor: 'Diffbot', kind: 'training', purpose: 'A web knowledge graph and datasets', robots: 'not stated' },
  { name: 'Omgilibot', vendor: 'Webz.io', kind: 'training', purpose: 'Web datasets', robots: 'not stated' },

  // live fetch
  { name: 'ChatGPT-User', vendor: 'OpenAI', kind: 'live-fetch', purpose: 'Loads a page when a ChatGPT user asks', robots: 'not always', source: OPENAI },
  { name: 'Claude-User', vendor: 'Anthropic', kind: 'live-fetch', purpose: 'Loads a page when a Claude user asks', robots: 'yes', source: ANTHROPIC },
  { name: 'Perplexity-User', vendor: 'Perplexity', kind: 'live-fetch', purpose: 'Loads a page when a Perplexity user asks', robots: 'not always', source: PERPLEXITY },
  { name: 'Google-Agent', vendor: 'Google', kind: 'live-fetch', purpose: 'Agents on Google infrastructure that browse when a user asks', robots: 'not always', source: GOOGLE_USER },
  { name: 'Meta-ExternalFetcher', vendor: 'Meta', kind: 'live-fetch', purpose: 'Loads a page when a user asks', robots: 'not always', source: META },
  { name: 'Amzn-User', vendor: 'Amazon', kind: 'live-fetch', purpose: 'Loads a page when a user asks', robots: 'not always', source: AMAZON },
  { name: 'MistralAI-User', vendor: 'Mistral', kind: 'live-fetch', purpose: 'Loads a page when a user asks', robots: 'not stated', source: MISTRAL },

  // AI search
  { name: 'OAI-SearchBot', vendor: 'OpenAI', kind: 'ai-search', purpose: 'The index for ChatGPT search', robots: 'yes', cost: 'Not shown in ChatGPT search answers', source: OPENAI },
  { name: 'Claude-SearchBot', vendor: 'Anthropic', kind: 'ai-search', purpose: 'The index for Claude\'s search', robots: 'yes', cost: 'Less visible in Claude\'s search results', source: ANTHROPIC },
  { name: 'PerplexityBot', vendor: 'Perplexity', kind: 'ai-search', purpose: 'The index for Perplexity\'s results; not for training', robots: 'yes', cost: 'Out of Perplexity\'s results', source: PERPLEXITY },
  { name: 'Meta-WebIndexer', vendor: 'Meta', kind: 'ai-search', purpose: 'Citations and links in Meta AI', robots: 'not stated', cost: 'Fewer citations in Meta AI', source: META },
  { name: 'Amzn-SearchBot', vendor: 'Amazon', kind: 'ai-search', purpose: 'Alexa search; not for training', robots: 'yes', cost: 'Out of Alexa search', source: AMAZON },
  { name: 'MistralAI-Index', vendor: 'Mistral', kind: 'ai-search', purpose: 'Mistral\'s search index; not for training', robots: 'yes', cost: 'Out of Mistral\'s search', source: MISTRAL },
  { name: 'DuckAssistBot', vendor: 'DuckDuckGo', kind: 'ai-search', purpose: 'DuckAssist answers; not for training', robots: 'yes', cost: 'Out of DuckAssist; search unaffected', source: 'https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot' },
  { name: 'YouBot', vendor: 'You.com', kind: 'ai-search', purpose: 'You.com search', robots: 'yes', source: 'https://you.com/docs/youbot' },

  // search crawlers that also feed AI
  { name: 'Googlebot', vendor: 'Google', kind: 'search', purpose: 'Google Search, including AI Overviews and AI Mode', robots: 'yes', cost: 'Out of Google Search', source: 'https://developers.google.com/search/docs/appearance/ai-features' },
  { name: 'Bingbot', vendor: 'Microsoft', kind: 'search', purpose: 'Bing and Copilot', robots: 'yes', cost: 'Out of Bing and Copilot', source: BING },
  { name: 'Applebot', vendor: 'Apple', kind: 'search', purpose: 'Spotlight, Siri and Safari, and context for Apple\'s AI answers', robots: 'yes', cost: 'Out of Spotlight, Siri and Safari', source: APPLE },

  // robots.txt tokens
  { name: 'Google-Extended', vendor: 'Google', kind: 'token', purpose: 'Gemini training, and grounding in Gemini Apps and Vertex AI; Google Search unaffected', robots: 'yes', source: GOOGLE_COMMON },
  { name: 'Applebot-Extended', vendor: 'Apple', kind: 'token', purpose: 'Apple\'s model training; search unaffected', robots: 'yes', source: APPLE },
  { name: '__usage_ai-training', vendor: 'Shared (IETF draft)', kind: 'token', purpose: 'Training, for every crawler that honors it: Anthropic now, OpenAI announced, Google early 2027, Microsoft from 1 Feb 2027', robots: 'yes', source: 'https://datatracker.ietf.org/doc/draft-kelley-aipref-training-preference-signal/' },
];

export const BING_SOURCE = BING;
