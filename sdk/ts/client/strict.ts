// Strict response decoding: `strict: true` checks every RPC success answer, before it is
// parsed, with the one strict check the SDK has (../src/strict.ts), and reports a refusal
// the way every other answer failure is reported, as `malformed`.

import { strictViolation } from "../src/strict.ts";
import { malformed } from "./errors.ts";

/**
 * refuseUnlessStrict refuses, as `malformed`, an answer that fails the strict schema of
 * `message` (fully-qualified, e.g. "fora.v1.ResourceResponse") or one of the cross-field
 * rules. Called on a success answer; an error answer is checked by checkStrictEnvelope.
 */
export function refuseUnlessStrict(op: string, raw: unknown, message: string): void {
	const problem = strictViolation(raw, message);
	if (problem !== undefined) throw malformed(op, new Error(`strict decoding: ${problem}`));
}
