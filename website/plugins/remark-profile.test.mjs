// The ::profile-filters directive renders the profile's filter table from its filter
// schema, and fails the build when it cannot.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { visit } from 'unist-util-visit';
import remarkProfile, { filterTableNodes } from './remark-profile.mjs';
import { loadProfileFilters } from './profile-schema.mjs';

// toString is a cell's text, with inline code as its bare value.
const toString = (node) => { let s = ''; visit(node, (n) => { if (n.type === 'text' || n.type === 'inlineCode') s += n.value; }); return s; };
const run = (tree) => { remarkProfile()(tree, { path: 'test.mdx' }); return tree; };
const directive = (attributes) => ({ type: 'root', children: [{ type: 'leafDirective', name: 'profile-filters', attributes, children: [] }] });

// rows returns the rendered table as { key: [type, required, description] }.
function rows(tree) {
  const out = {};
  visit(tree, 'tableRow', (row, index) => {
    if (index === 0) return; // the header
    const [key, ...rest] = row.children.map((c) => toString(c));
    out[key] = rest;
  });
  return out;
}

const schemaFile = new URL('../../schemas/music/v1/music-v1.search-filters.schema.json', import.meta.url);
const schema = JSON.parse(readFileSync(schemaFile, 'utf8'));

test('profile-filters renders one row per key of the filter schema, in its order', () => {
  const tree = run(directive({ profile: 'fora-music-v1' }));
  let header;
  visit(tree, 'tableRow', (row, index) => { if (index === 0) header = row.children.map((c) => toString(c)); });
  assert.deepEqual(header, ['Key', 'Type', 'Required', 'Description']);
  assert.deepEqual(Object.keys(rows(tree)), Object.keys(schema.properties));
  assert.equal(Object.keys(schema.properties).length, 23);
});

test('the type, the array rule and the examples come from the schema', () => {
  const r = rows(run(directive({ profile: 'fora-music-v1' })));
  assert.deepEqual(r['music.genre'].slice(0, 2), ['label or label[]', 'Optional']);
  assert.deepEqual(r['music.isrc'].slice(0, 2), ['string or string[]', 'Optional']);
  assert.equal(r['music.vocals'][0], 'boolean');
  assert.equal(r['music.bpm_range'][0], 'string');
  assert.match(r['music.genre'][2], /An array must not be empty\. Example: "cinematic", \["jazz", "blues"\]\.$/);
  assert.match(r['music.vocals'][2], /Example: false\.$/);
  assert.doesNotMatch(r['music.vocals'][2], /An array/);
  assert.match(r['music.release_date_range'][2], /Example: "2015\/2019", "2020-06\/", "\/1999-12-31"\.$/);
});

test('an unknown profile fails the build', () => {
  assert.throws(() => run(directive({ profile: 'fora-nosuch-v1' })), /unknown profile "fora-nosuch-v1"/);
});

test('a directive without a profile fails the build', () => {
  assert.throws(() => run(directive({})), /needs a profile/);
});

test('a key the table cannot describe fails the build, naming it', () => {
  const { labelPattern } = loadProfileFilters()['fora-music-v1'];
  const doc = (props) => ({ doc: { type: 'object', additionalProperties: false, properties: props }, labelPattern });
  assert.throws(() => filterTableNodes('p', doc({ 'music.x': { type: 'object', description: 'x' } })), /music\.x: type/);
  assert.throws(() => filterTableNodes('p', doc({ 'music.x': { type: 'string' } })), /music\.x has no description/);
  assert.throws(
    () => filterTableNodes('p', doc({ 'music.x': { type: ['string', 'array'], pattern: labelPattern, items: { type: 'string' }, description: 'x' } })),
    /music\.x: a single value and an array item must have the same rule/,
  );
  assert.throws(() => filterTableNodes('p', { doc: { type: 'object', properties: { 'music.x': {} } }, labelPattern }), /additionalProperties false/);
});
