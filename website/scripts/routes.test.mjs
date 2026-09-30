import test from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest, redirectSources, uncoveredRetirements } from './routes.mjs';

test('parseManifest drops comments and blank lines', () => {
	assert.deepEqual(parseManifest('# a comment\n\n/b/\n/a/\n'), ['/a/', '/b/']);
});

test('redirectSources normalises the trailing slash', () => {
	const s = redirectSources('[{"source":"/old/","target":"/new/"},{"source":"/other","target":"/new/"}]');
	assert.ok(s.has('/old'));
	assert.ok(s.has('/other'));
});

test('redirectSources rejects a rule missing its target', () => {
	assert.throws(() => redirectSources('[{"source":"/old/"}]'), /needs both a source and a target/);
});

test('redirectSources rejects a document that is not an array', () => {
	assert.throws(() => redirectSources('{}'), /must be a JSON array/);
});

test('a retired route with no rule is reported', () => {
	const uncovered = uncoveredRetirements(['/a/', '/gone/'], ['/a/'], new Set());
	assert.deepEqual(uncovered, ['/gone/']);
});

test('a retired route with a rule is accepted', () => {
	const uncovered = uncoveredRetirements(['/a/', '/gone/'], ['/a/'], new Set(['/gone']));
	assert.deepEqual(uncovered, []);
});

test('adding routes retires nothing', () => {
	assert.deepEqual(uncoveredRetirements(['/a/'], ['/a/', '/b/'], new Set()), []);
});
