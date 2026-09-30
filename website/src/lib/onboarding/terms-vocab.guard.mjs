// Build-time check that the offered uses name real protocol tokens.
//
// Node only: it reads the committed descriptor through the same loader the
// remark-proto guard uses, so it must not be imported by the page. It runs from
// terms-vocab.test.mjs, which npm test executes ahead of the build in
// ci-local.sh and in docs-ci.yml.

import { loadSchema } from '../../../plugins/proto-schema.mjs';
import { OFFERED_USES, USE_LABELS } from './terms-vocab.mjs';

/**
 * Both the tokens the controls offer and the tokens the page has a label for
 * must be real. The label map is the wider of the two, so it is checked as
 * well: a label for a token the protocol does not define would put a use in
 * front of a publisher that no Exchange can act on.
 */
export function assertOfferedUsesResolve(tokens = [...OFFERED_USES, ...Object.keys(USE_LABELS)]) {
	const registered = new Set(loadSchema().vocab.function ?? []);
	const unknown = [...new Set(tokens)].filter((token) => !registered.has(token));
	if (unknown.length > 0) {
		throw new Error(
			`the onboarding preview names ${unknown.length} use token(s) that are not on the `
			+ `proto function axis: ${unknown.join(', ')}. Either the token is misspelled, `
			+ `or it belongs in proto/fora/v1/vocab.proto first.`,
		);
	}
	return true;
}
