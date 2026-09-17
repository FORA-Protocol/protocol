import test from 'node:test';
import assert from 'node:assert/strict';

import { escapeHtml, highlightJson } from './record.mjs';

test('escapeHtml neutralises markup in a value', () => {
	assert.equal(escapeHtml('<img src=x onerror="a">'), '&lt;img src=x onerror=&quot;a&quot;&gt;');
});

test('highlightJson escapes before it colours, so a title cannot smuggle markup', () => {
	const out = highlightJson(JSON.stringify({ title: '</span><script>alert(1)</script>' }));
	assert.equal(out.includes('<script>'), false);
	assert.ok(out.includes('&lt;script&gt;'));
});

test('a quoted digit stays a string, it is not coloured as a number', () => {
	const out = highlightJson('{"rate": "0.02", "count": 3}');
	assert.ok(out.includes('<span class="s">&quot;0.02&quot;</span>'), 'the rate is a string');
	assert.ok(out.includes('<span class="n">3</span>'), 'the count is a number');
	assert.equal(out.includes('&quot;<span class="n">'), false, 'no number span opens inside a string');
});

test('highlightJson marks keys, strings, numbers and braces apart', () => {
	const out = highlightJson('{"a": "b", "c": 1}');
	assert.ok(out.includes('<span class="k">&quot;a&quot;</span>'), 'key');
	assert.ok(out.includes('<span class="s">&quot;b&quot;</span>'), 'string value');
	assert.ok(out.includes('<span class="n">1</span>'), 'number');
	assert.ok(out.includes('<span class="b">{</span>'), 'brace');
});
