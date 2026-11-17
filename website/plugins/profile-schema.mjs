// profile-schema reads the machine-readable files of the extension profiles, in the
// repository's schemas/ directory, for the pages that render from them. The endpoint
// src/pages/schemas/[...path].ts publishes the same files under /schemas/.
//
// A profile's search filter keys are one file:
//
//   schemas/<domain>/v<N>/<domain>-v<N>.search-filters.schema.json  ->  fora-<domain>-v<N>
//
// The files are DISCOVERED, not listed, so a new profile's file registers itself. The
// profile page, protocol/ext-<domain>.mdx, carries the profile's offer schema in its
// "JSON Schema" section; its Label definition is what makes a filter value a label.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SCHEMAS = new URL('../../schemas/', import.meta.url);
const DOCS = new URL('../src/content/docs/', import.meta.url);
const FILTERS_FILE = /^([a-z][a-z0-9]*)-(v[0-9]+)\.search-filters\.schema\.json$/;

/** Every file under schemas/, as { path, url }: path is the published path, below /schemas/. */
function profileFiles() {
  const out = [];
  const walk = (dir, prefix) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) walk(new URL(`${e.name}/`, dir), `${prefix}${e.name}/`);
      else if (e.name.endsWith('.json')) out.push({ path: `${prefix}${e.name}`, url: new URL(e.name, dir) });
    }
  };
  walk(SCHEMAS, '');
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

let cached;

/** profile id -> { path, doc, labelPattern } for every search filter file. */
export function loadProfileFilters() {
  if (cached) return cached;
  cached = {};
  for (const f of profileFiles()) {
    const name = f.path.slice(f.path.lastIndexOf('/') + 1);
    const m = FILTERS_FILE.exec(name);
    if (!m) continue;
    const [, domain, version] = m;
    if (f.path !== `${domain}/${version}/${name}`) {
      throw new Error(`schemas/${f.path}: a search filter file belongs in schemas/${domain}/${version}/`);
    }
    const doc = JSON.parse(readFileSync(fileURLToPath(f.url), 'utf8'));
    cached[`fora-${domain}-${version}`] = { path: f.path, doc, labelPattern: offerLabelPattern(domain) };
  }
  return cached;
}

// offerLabelPattern returns the Label pattern of the offer schema on the profile's page,
// or null when the page has no such schema.
function offerLabelPattern(domain) {
  const page = new URL(`protocol/ext-${domain}.mdx`, DOCS);
  if (!existsSync(page)) return null;
  const m = /\n## JSON Schema\n[\s\S]*?```json[ \t]*\n([\s\S]*?)```/.exec(readFileSync(fileURLToPath(page), 'utf8'));
  if (!m) return null;
  return JSON.parse(m[1]).$defs?.Label?.pattern ?? null;
}
