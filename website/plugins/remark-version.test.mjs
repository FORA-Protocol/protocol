// The version guard has to be seen to fail, so most of these cases are rejections.
//
// The substitution half is the cheap half: if it broke, every page would render the
// literal ":sdk-version" and someone would notice within a build. The rejection half
// is the one that decays silently — it only ever fires on a page nobody has written
// yet — so it is exercised here per package spelling and per node type, and pinned
// against the versions the site legitimately cites and must NOT flag.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { visit } from 'unist-util-visit';
import remarkVersion, { sdkVersion, stalePins } from './remark-version.mjs';

const VERSION = sdkVersion();
const OLD = '0.9.1'; // never the current version, whatever the tree is on

const run = (tree) => { remarkVersion()(tree, { path: 'fixture.mdx' }); return tree; };
const para = (...children) => ({ type: 'root', children: [{ type: 'paragraph', children }] });
const t = (value) => ({ type: 'text', value });
const code = (value) => ({ type: 'inlineCode', value });
const directive = () => ({ type: 'textDirective', name: 'sdk-version', children: [] });
const texts = (tree) => { const v = []; visit(tree, 'text', (n) => v.push(n.value)); return v; };

test('the version comes from the root package.json and looks like a version', () => {
  assert.match(VERSION, /^\d+\.\d+\.\d+/);
});

test(':sdk-version becomes the current version', () => {
  assert.ok(texts(run(para(t('published as '), directive()))).includes(VERSION));
});

test('the directive resolves inside a table cell, which is where the pins live', () => {
  const cell = {
    type: 'root',
    children: [{
      type: 'table',
      children: [{
        type: 'tableRow',
        children: [{ type: 'tableCell', children: [t('npm '), directive()] }],
      }],
    }],
  };
  assert.ok(texts(run(cell)).includes(VERSION));
});

test('an unrelated directive is left alone', () => {
  const other = { type: 'textDirective', name: 'proto-enum', children: [] };
  const tree = para(other);
  run(tree);
  assert.equal(tree.children[0].children[0].type, 'textDirective');
});

// ---- the rejection half ----

test('a stale npm pin in prose fails the build', () => {
  assert.throws(() => run(para(t(`published to npm as @fora-protocol/sdk ${OLD}`))), /not the current/);
});

test('a stale pip pin fails the build', () => {
  assert.throws(() => run(para(t(`install fora-protocol-sdk==${OLD}`))), /not the current/);
});

test('a stale go module pin fails the build', () => {
  assert.throws(() => run(para(t(`go get FORA-Protocol/protocol@v${OLD}`))), /not the current/);
});

test('a stale pin inside a CODE SPAN fails too — the install command is the case that started this', () => {
  assert.throws(() => run(para(code(`go get github.com/FORA-Protocol/protocol@v${OLD}`))), /not the current/);
});

test('the failure names the file and the offending version', () => {
  assert.throws(
    () => run(para(t(`@fora-protocol/sdk ${OLD}`))),
    (e) => e.message.includes('fixture.mdx') && e.message.includes(OLD),
  );
});

test('a CURRENT hand-written pin is accepted — the guard checks staleness, not spelling', () => {
  assert.doesNotThrow(() => run(para(t(`@fora-protocol/sdk ${VERSION}`))));
});

// ---- what it must NOT flag ----

test('an unrelated standard version is not an SDK pin', () => {
  assert.doesNotThrow(() => run(para(t('RSL 1.0, C2PA 2.x and CoMP V1 are unrelated'))));
});

test('a bare version with no package name is not an SDK pin', () => {
  assert.doesNotThrow(() => run(para(t('the 1.0.0 wire promise holds across v1'))));
});

test('a floating version in a command is the sanctioned form', () => {
  assert.doesNotThrow(() => run(para(code('go get github.com/FORA-Protocol/protocol@latest'))));
});

test('stalePins reports the package it matched, so the message can name it', () => {
  const [hit] = stalePins(`fora-protocol-sdk==${OLD}`, VERSION);
  assert.equal(hit.found, OLD);
  assert.equal(hit.package, 'fora-protocol-sdk');
});
