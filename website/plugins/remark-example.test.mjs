// The example include has to be seen to FAIL, so most of these cases are rejections.
//
// The substitution half is the cheap half: if it broke, every agent-SDK page would
// render a literal "::example{...}" and someone would notice within a build. The
// rejection half is the one that decays silently. It fires only when somebody renames
// or deletes a region in an SDK file, which is exactly the moment the site would
// otherwise go back to showing code that does not compile — the state this whole
// mechanism exists to end. So every failure path is exercised here by name.
//
// The last two tests are not about the plugin at all. They assert that the real
// example files still define the regions the real pages ask for, and that the Python
// README still carries exactly one anchored block. Those are the couplings that a
// refactor in sdk/go or sdk/ts breaks, and they fail here with the region named.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import remarkExample, { fencedBlock, regionsOf } from './remark-example.mjs';

const repo = new URL('../../', import.meta.url);

const run = (tree, path = 'fixture.mdx') => { remarkExample()(tree, { path }); return tree; };
const directive = (attributes) => ({ type: 'root', children: [{ type: 'leafDirective', name: 'example', attributes, children: [] }] });
const first = (tree) => tree.children[0];

const GO_EXAMPLE = 'sdk/go/examples/agent/agent.go';
const TS_EXAMPLE = 'sdk/ts/examples/agent.ts';
const PY_README = 'sdk/python/README.md';
const BROKEN = 'website/plugins/testdata/broken.md';

test('a region becomes a code node in the requested language', () => {
  const tree = run(directive({ file: GO_EXAMPLE, regions: 'client', lang: 'go' }));
  assert.equal(first(tree).type, 'code');
  assert.equal(first(tree).lang, 'go');
  assert.match(first(tree).value, /connect\.NewClient\(baseURL,/);
});

test('the marker lines never reach the page', () => {
  const tree = run(directive({ file: GO_EXAMPLE, regions: 'client,report', lang: 'go' }));
  assert.doesNotMatch(first(tree).value, /fora:\/?example/);
});

test('a region taken from inside a function body renders flush left', () => {
  const tree = run(directive({ file: GO_EXAMPLE, regions: 'client', lang: 'go' }));
  assert.doesNotMatch(first(tree).value.split('\n')[0], /^[ \t]/);
});

test('several regions are joined in the order the page asks for them', () => {
  const tree = run(directive({ file: GO_EXAMPLE, regions: 'fetch,client', lang: 'go' }));
  assert.ok(first(tree).value.indexOf('client.Fetch(') < first(tree).value.indexOf('connect.NewClient('));
});

test('a fence= include takes the block behind the README anchor', () => {
  const tree = run(directive({ file: PY_README, fence: 'agent-example', lang: 'python' }));
  assert.equal(first(tree).lang, 'python');
  assert.match(first(tree).value, /^import asyncio/);
});

test('an unknown region fails the build and names the regions that exist', () => {
  assert.throws(
    () => run(directive({ file: GO_EXAMPLE, regions: 'nosuchregion', lang: 'go' }), 'page.mdx'),
    (err) => /page\.mdx/.test(err.message) && /nosuchregion/.test(err.message) && /Regions in that file: .*client/.test(err.message),
  );
});

test('an unreadable file fails the build', () => {
  assert.throws(
    () => run(directive({ file: 'sdk/go/examples/agent/nope.go', regions: 'client', lang: 'go' })),
    /cannot be read/,
  );
});

test('a missing attribute fails the build', () => {
  assert.throws(() => run(directive({ regions: 'client', lang: 'go' })), /needs a file=/);
  assert.throws(() => run(directive({ file: GO_EXAMPLE, lang: 'go' })), /needs a regions= or a fence=/);
  assert.throws(() => run(directive({ file: GO_EXAMPLE, regions: 'client' })), /needs a lang=/);
});

test('regions= and fence= together fail the build rather than one silently winning', () => {
  assert.throws(
    () => run(directive({ file: GO_EXAMPLE, regions: 'client', fence: 'agent-example', lang: 'go' })),
    /takes one or the other/,
  );
});

test('an unclosed region fails, naming it', () => {
  assert.throws(() => regionsOf('// fora:example alpha\nbody\n', 'x.go'), /never closed: alpha/);
});

test('a region closed without being opened fails', () => {
  assert.throws(() => regionsOf('body\n// fora:/example alpha\n', 'x.go'), /closed at line 2 without being opened/);
});

test('a region defined twice fails, because a page would silently get one of them', () => {
  const twice = '// fora:example a\n1\n// fora:/example a\n// fora:example a\n2\n// fora:/example a\n';
  assert.throws(() => regionsOf(twice, 'x.go'), /defined twice/);
});

test('an empty region fails rather than rendering an empty block', () => {
  assert.throws(
    () => run(directive({ file: BROKEN, regions: 'emptyfixture', lang: 'text' })),
    /is empty/,
  );
});

test('an anchor that appears twice fails, because the site and the test would diverge', () => {
  assert.throws(() => fencedBlock(BROKEN, 'twice-fixture'), /found 2/);
});

test('an unrelated directive is left alone', () => {
  const tree = { type: 'root', children: [{ type: 'leafDirective', name: 'proto-enum', attributes: {}, children: [] }] };
  run(tree);
  assert.equal(first(tree).type, 'leafDirective');
});

// --- the couplings the pages depend on ---------------------------------------------

/** Every ::example directive the site actually ships, as {page, file, regions, fence}. */
function siteDirectives() {
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const child = new URL(`${e.name}${e.isDirectory() ? '/' : ''}`, dir);
      if (e.isDirectory()) walk(child);
      else if (e.name.endsWith('.mdx') || e.name.endsWith('.md')) {
        for (const line of readFileSync(child, 'utf8').split('\n')) {
          const m = /^::example\{(.+)\}\s*$/.exec(line);
          if (!m) continue;
          const attrs = Object.fromEntries([...m[1].matchAll(/(\w+)="([^"]*)"/g)].map((a) => [a[1], a[2]]));
          out.push({ page: child.pathname, ...attrs });
        }
      }
    }
  };
  walk(new URL('website/src/content/docs/', repo));
  return out;
}

test('every region the site asks for is still defined in the file it names', () => {
  const directives = siteDirectives();
  assert.ok(directives.length > 0, 'no ::example directive found — the pages stopped using the mechanism');
  for (const d of directives) {
    if (d.fence) {
      assert.ok(fencedBlock(d.file, d.fence, d.page).length > 0);
      continue;
    }
    const defined = regionsOf(readFileSync(new URL(d.file, repo), 'utf8'), d.file);
    for (const name of d.regions.split(',')) {
      assert.ok(defined.has(name.trim()), `${d.page} asks ${d.file} for region "${name.trim()}", which it no longer defines`);
    }
  }
});

test('the compiled examples and the executed README are the files the site pulls from', () => {
  const files = new Set(siteDirectives().map((d) => d.file));
  for (const want of [GO_EXAMPLE, TS_EXAMPLE, PY_README]) {
    assert.ok(files.has(want), `${want} is no longer included by any page; the site went back to its own copy`);
  }
});
