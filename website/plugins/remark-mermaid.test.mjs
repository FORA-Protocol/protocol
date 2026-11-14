import { test } from 'node:test';
import assert from 'node:assert/strict';
import remarkMermaid from './remark-mermaid.mjs';

const run = (tree) => { remarkMermaid()(tree); return tree; };
const code = (lang, value) => ({ type: 'root', children: [{ type: 'code', lang, value }] });

test('a mermaid block becomes a placeholder carrying its source', () => {
  const [node] = run(code('mermaid', 'graph LR\n  A --> B')).children;
  assert.equal(node.type, 'html');
  assert.equal(
    node.value,
    '<div class="mermaid" data-content="graph LR\n  A --&gt; B" data-status="loading"></div>',
  );
});

test('quotes and markup in labels are escaped inside the attribute', () => {
  const [node] = run(code('mermaid', 'A["<b>x</b> & \'y\'"]')).children;
  assert.match(node.value, /data-content="A\[&quot;&lt;b&gt;x&lt;\/b&gt; &amp; &#39;y&#39;&quot;\]"/);
});

test('other code blocks are left alone', () => {
  const [node] = run(code('js', 'a --> b')).children;
  assert.deepEqual(node, { type: 'code', lang: 'js', value: 'a --> b' });
});
