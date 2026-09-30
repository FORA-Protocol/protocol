import test from 'node:test';
import assert from 'node:assert/strict';

import { assertOfferedUsesResolve } from './terms-vocab.guard.mjs';
import { OFFERED_USES, USE_LABELS, partitionUses } from './terms-vocab.mjs';

test('every offered use names a token the protocol registers', () => {
	assert.equal(assertOfferedUsesResolve(), true);
});

test('a use the protocol does not define fails the check', () => {
	assert.throws(
		() => assertOfferedUsesResolve(['search', 'not-a-real-token']),
		/not on the proto function axis/,
	);
});

test('the offered uses are the three the design shows, in order', () => {
	assert.deepEqual(OFFERED_USES, ['search', 'ai-input', 'ai-train']);
});

test('every offered use has a label', () => {
	for (const token of OFFERED_USES) {
		assert.ok(USE_LABELS[token], `${token} has no label`);
	}
});

test('the labels cover the tokens an offer can come back with, not just the three offered', () => {
	for (const token of ['search', 'ai-input', 'ai-index', 'ai-train', 'crawl']) {
		assert.ok(USE_LABELS[token], `${token} has no label`);
	}
});

test('every offered use lands in exactly one list', () => {
	const cases = [
		[() => true, ['search', 'ai-input', 'ai-train'], []],
		[() => false, [], ['search', 'ai-input', 'ai-train']],
		[(t) => t === 'search', ['search'], ['ai-input', 'ai-train']],
		[(t) => t !== 'ai-train', ['search', 'ai-input'], ['ai-train']],
	];
	for (const [predicate, functions, prohibited] of cases) {
		const split = partitionUses(predicate);
		assert.deepEqual(split.functions, functions);
		assert.deepEqual(split.prohibited, prohibited);
		assert.deepEqual(split.functions.filter((t) => split.prohibited.includes(t)), []);
	}
});
