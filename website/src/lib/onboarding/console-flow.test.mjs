// The public onboarding page and the publisher guide describe the publisher
// console, so they name its steps the way it does. The authority is the list the
// reference implementation's console draws in its wizard header; both files here
// follow it by hand, and this keeps them from drifting apart or back. They are
// read as text because neither can be imported here: one is a page, the other MDX.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');

const SURFACES = {
	'public onboarding page': read('../../pages/publishers/onboarding.astro'),
	'publisher guide': read('../../content/docs/getting-started/publisher-onboarding.mdx'),
};

const STEPS = ['Your business', 'Your domain', 'Your terms', 'Connect your site'];
const CONNECT_TASKS = ['Serve your discovery file', 'Install the package on your CDN'];

// Screens the console no longer has, and the words these two files replaced.
const RETIRED = [
	'Publish a file',
	'Add your first domain',
	'Skip for now',
	'Who gets paid?',
	'Step 1 ·',
	'Step 2 ·',
	'discovery document',
	'Per access',
];

for (const [surface, text] of Object.entries(SURFACES)) {
	test(`the ${surface} names the console's steps and the last step's two tasks`, () => {
		for (const name of [...STEPS, ...CONNECT_TASKS]) {
			assert.ok(text.includes(name), `the ${surface} does not name "${name}"`);
		}
	});

	test(`the ${surface} tells the first run's four steps from a later domain's three`, () => {
		assert.match(text, /four steps/i);
		assert.match(text, /three steps/i);
	});

	test(`the ${surface} uses no name the console has retired`, () => {
		for (const name of RETIRED) {
			assert.ok(!text.includes(name), `the ${surface} still says "${name}"`);
		}
	});
}
