// The Web Bot Auth -01 rows the TypeScript SDK does not meet yet: one list, read by every
// replay.
//
// The Go oracle reads and writes draft-ietf-webbotauth-httpsig-protocol-01
// Signature-Agent values. Every signer writes the well-known key directory URL, a bare
// origin completed to it, and the verifier ignores a member that carries parameters and
// refuses any URL but the well-known one. The TypeScript SDK still implements -00.
//
// Each entry names a corpus row and the face a test exercises on it,
// "<corpus>#<row>:<face>". The face "sign" re-signs the row and compares the bytes, and
// "verify" verifies it; a test registers through wba01It with the face it exercises. Each
// entry carries the -01 rule the row needs. A test over a listed row MUST fail (it.fails),
// and only on an assertion, the way pytest's raises=AssertionError does: a listed test
// that passes, or that breaks for another reason, fails the suite. The port deletes each
// entry in the change that makes its row pass, so this list shrinks to nothing.

import { it } from "vitest";

const SIGNS_URL = "a signer writes the well-known key directory URL, a bare origin completed to it (-01 §5.2.1)";
const READS_URL = "a member naming the well-known key directory URL names that directory (-01 §5.5)";
const PARAMETER = "a member with a parameter is ignored (-01 §5.2.1), so the signature names no directory";
const OTHER_URL = "another path, a query or a fragment is refused with refusal kind not_key_directory";
const SIGN_ACCEPTS_URL = "a signer accepts the well-known key directory URL as its configured value";
const SIGN_OTHER_URL = "a signer refuses another path, a query or a fragment as signature_agent_not_key_directory";

const WBA = "wba-signature-agent-vectors";
const SIGN_REQUEST = "sign-request-vectors";
const POP = "pop-vectors";
const MULTISIG = "multisig-chain-vectors";

function rows(corpus: string, face: "sign" | "verify", reason: string, names: string[]): Record<string, string> {
	return Object.fromEntries(names.map((n) => [`${corpus}#${n}:${face}`, reason]));
}

const SIGN_REQUEST_ROWS = [
	"post_with_authorization",
	"post_empty_authorization_bound",
	"append_relay_leg",
	"post_with_nonce",
	"post_empty_authorization_bound_with_nonce",
	"append_relay_leg_with_nonce",
	"doc_single_hop_example",
	"doc_broker_example",
];

export const PENDING_WBA_01: Record<string, string> = {
	// wba-signature-agent-vectors.json, verifier rows.
	...rows(WBA, "verify", READS_URL, [
		"vectors/well_known_url",
		"vectors/well_known_url_with_port",
		"vectors/legacy_string_well_known_url",
		"vectors/member_key_differs_from_label",
		"vectors/repeated_field_lines_member_on_first",
		"vectors/repeated_field_lines_member_on_second",
		"vectors/escaped_quote_in_another_member",
		"vectors/ignored_member_beside_the_signers",
	]),
	...rows(WBA, "verify", PARAMETER, [
		"vectors/member_with_parameter",
		"vectors/member_type_directory_string",
		"vectors/member_type_directory_token",
		"vectors/member_with_other_parameter",
		"vectors/member_type_other",
		"vectors/member_not_a_string_with_parameter",
		"vectors/legacy_string_with_parameter",
		"vectors/repeated_field_lines_member_with_parameter",
	]),
	...rows(WBA, "verify", OTHER_URL, [
		"vectors/other_path",
		"vectors/origin_with_trailing_slash",
		"vectors/well_known_path_with_trailing_slash",
		"vectors/well_known_path_in_another_case",
		"vectors/query",
		"vectors/bare_origin_with_query",
		"vectors/fragment",
		"vectors/escaped_quote_in_the_covered_value",
	]),
	// wba-signature-agent-vectors.json, signer rows.
	...rows(WBA, "sign", SIGNS_URL, ["signer/origin_completed", "signer/origin_with_port_completed"]),
	...rows(WBA, "sign", SIGN_ACCEPTS_URL, ["signer/well_known_url_as_given"]),
	...rows(WBA, "sign", SIGN_OTHER_URL, ["signer/other_path", "signer/query", "signer/fragment"]),
	// sign-request-vectors.json: every row now carries the well-known URL member.
	...rows(SIGN_REQUEST, "sign", SIGNS_URL, SIGN_REQUEST_ROWS),
	...rows(SIGN_REQUEST, "verify", READS_URL, SIGN_REQUEST_ROWS),
	// pop-vectors.json: the proofs the Go signer made.
	...rows(POP, "sign", SIGNS_URL, ["valid", "valid_no_nonce", "expired"]),
	...rows(POP, "verify", READS_URL, ["valid", "valid_no_nonce", "expired"]),
	// multisig-chain-vectors.json: every hop's member now names the well-known URL.
	...rows(MULTISIG, "verify", READS_URL, [
		"positive_independent_two",
		"positive_covering_two",
		"positive_covering_three",
		"positive_covering_two_nonce",
		"canonical_case_two",
		"duplicate_bound_two",
	]),
	...rows(MULTISIG, "sign", SIGNS_URL, [
		"positive_independent_two",
		"positive_covering_two",
		"positive_covering_three",
		"positive_covering_two_nonce",
		"hop_budget_three_independent_over_two",
		"hop_budget_three_covering_over_two",
		"absent_authorization_two",
		"absent_authorization_over_budget",
		"duplicate_authorization_two",
		"canonical_case_two",
		"duplicate_bound_two",
	]),
};

// isAssertion tells an assertion failure from any other error.
function isAssertion(err: unknown): boolean {
	return err instanceof Error && err.name === "AssertionError";
}

type TestBody = () => unknown;

/** wba01It returns the registration for a test over one corpus row: vitest's `it`, or,
 * when the row is pending for this face, a test that must fail on an assertion. A pending
 * body that throws anything else returns normally, which it.fails reports as a failure. */
export function wba01It(corpus: string, row: string, face: "sign" | "verify"): (name: string, fn: TestBody) => void {
	const reason = PENDING_WBA_01[`${corpus}#${row}:${face}`];
	if (reason === undefined) return (name, fn) => it(name, async () => void (await fn()));
	return (name, fn) =>
		it.fails(`${name} (pending -01: ${reason})`, async () => {
			try {
				await fn();
			} catch (err) {
				if (isAssertion(err)) throw err;
			}
		});
}
