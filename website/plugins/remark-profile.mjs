// remark-profile renders a profile's search filter table from the profile's filter
// schema, so the page and the file FORA Server reads cannot disagree:
//
//   ::profile-filters{profile="fora-music-v1"}
//
// The file is schemas/music/v1/music-v1.search-filters.schema.json (see
// profile-schema.mjs). Each property is one row: the key, its type, Required or
// Optional, and its description. The type is read from the schema: a string whose
// pattern is the profile's Label pattern is a label, and a key that takes one value or
// an array of them is "string or string[]". The description is the property's own,
// then "An array must not be empty." when the array needs an item, then its examples.
//
// Every failure throws, as remark-proto does on an unknown enum: an unknown profile, a
// directive without one, and a property the table cannot describe each fail the build
// naming the page. Runs before remark-proto, so a proto reference in a cell is checked
// and linked like one in prose.
import { visit, SKIP } from 'unist-util-visit';
import { fromMarkdown } from 'mdast-util-from-markdown';
import { gfmTable } from 'micromark-extension-gfm-table';
import { gfmTableFromMarkdown } from 'mdast-util-gfm-table';
import { loadProfileFilters } from './profile-schema.mjs';

const esc = (s) => s.replace(/\|/g, '\\|').replace(/\s*\n\s*/g, ' ').trim();

// example renders one example value as the page writes JSON inline: `["jazz", "blues"]`.
const example = (v) => '`' + (Array.isArray(v) ? `[${v.map((e) => JSON.stringify(e)).join(', ')}]` : JSON.stringify(v)) + '`';

function valueType(key, p, labelPattern) {
  const named = (pattern) => (labelPattern && pattern === labelPattern ? 'label' : 'string');
  if (p.type === 'boolean' || p.type === 'integer' || p.type === 'number') return p.type;
  if (p.type === 'string') return named(p.pattern);
  if (Array.isArray(p.type) && p.type.length === 2 && p.type.includes('string') && p.type.includes('array')) {
    const t = named(p.pattern);
    if (p.items?.type !== 'string') throw new Error(`${key}: the items of an array must be strings`);
    if (p.items.pattern !== p.pattern || p.items.minLength !== p.minLength) {
      throw new Error(`${key}: a single value and an array item must have the same rule`);
    }
    return `${t} or ${t}[]`;
  }
  throw new Error(`${key}: type ${JSON.stringify(p.type)} is not one the filter table describes`);
}

export function filterTableNodes(profile, { doc, labelPattern }) {
  if (doc.type !== 'object' || doc.additionalProperties !== false || !Object.keys(doc.properties ?? {}).length) {
    throw new Error(`${profile}: the filter schema must be an object with properties and additionalProperties false`);
  }
  const required = new Set(doc.required ?? []);
  const rows = Object.entries(doc.properties).map(([key, p]) => {
    const desc = (p.description ?? '').trim();
    if (!desc) throw new Error(`${profile}: ${key} has no description`);
    let cell = desc;
    if (Array.isArray(p.type) && p.type.includes('array') && p.minItems >= 1) cell += ' An array must not be empty.';
    if (p.examples?.length) cell += ` Example: ${p.examples.map(example).join(', ')}.`;
    return `| \`${key}\` | ${valueType(key, p, labelPattern)} | ${required.has(key) ? 'Required' : 'Optional'} | ${esc(cell)} |`;
  });
  const md = '| Key | Type | Required | Description |\n|-----|------|----------|-------------|\n' + rows.join('\n');
  return fromMarkdown(md, { extensions: [gfmTable()], mdastExtensions: [gfmTableFromMarkdown()] }).children;
}

export default function remarkProfile() {
  return (tree, file) => {
    const where = file?.path ?? 'doc';
    visit(tree, (n) => n.type === 'leafDirective' && n.name === 'profile-filters', (node, index, parent) => {
      if (!parent || index == null) return;
      const profile = node.attributes?.profile;
      if (!profile) throw new Error(`${where}: profile-filters needs a profile, for example profile="fora-music-v1"`);
      const filters = loadProfileFilters()[profile];
      if (!filters) throw new Error(`${where}: profile-filters references unknown profile "${profile}"`);
      let nodes;
      try {
        nodes = filterTableNodes(profile, filters);
      } catch (e) {
        throw new Error(`${where}: ${e.message}`);
      }
      parent.children.splice(index, 1, ...nodes);
      return [SKIP, index + nodes.length];
    });
  };
}
