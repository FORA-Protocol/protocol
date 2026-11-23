// The Web Bot Auth -01 rows the TypeScript SDK does not meet yet: one list, read by every
// replay.
//
// The Go oracle reads and writes draft-ietf-webbotauth-httpsig-protocol-01 (WG-01)
// Signature-Agent values. Every signer writes the well-known key directory URL, a bare
// origin completed to it, and the verifier ignores a member that carries parameters and
// refuses any URL but the well-known one. The TypeScript SDK still implements -00.
//
// Each entry names a corpus row and the face a test exercises on it,
// "<corpus>#<row>:<face>": "sign" signs the row's inputs and compares the bytes, "verify"
// verifies the row. It records the WG-01 rule the row needs and the outcome the SDK
// produces on that face today.
//
// A test over a listed row MUST fail (it.fails), and for one reason only. The test hands
// the SDK's outcome to `observe` before it asserts the oracle row. An outcome other than
// the recorded one, a test that never reports its outcome, a failure that is not an
// assertion, and a test that passes all fail the suite. An entry therefore fails when its
// row starts to pass and when the SDK starts to fail it differently. The port deletes each
// entry in the change that makes its row pass, so this list shrinks to nothing.
//
// Every key a test registers is recorded. vitest runs each file in its own module graph,
// so each (corpus, face) pair in the list is owned by one test file, which declares it
// with wba01Owns; that file checks every pending entry of the pair was registered there,
// and wba-signature-agent.parity.test.ts checks every pair is owned exactly once.

import { expect, it } from "vitest";

/** One pending row: the WG-01 rule it needs, and the SDK's outcome on it today. Where the
 * tests over a row exercise different faces, `today` maps each test's name to its
 * outcome. */
export type Pending = { rule: string; today: string | Readonly<Record<string, string>> };

/** A pending row's outcome is not the one the list records. */
export class PendingOutcomeChangedError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "PendingOutcomeChangedError";
	}
}

/** A verify face's outcome: "valid", or the refusal reason and its Accept-Signature. */
export function verifyOutcome(valid: boolean, reason?: string, acceptSignature?: string): string {
	if (valid) return "valid";
	return acceptSignature ? `refused ${reason}; Accept-Signature: ${acceptSignature}` : `refused ${reason}`;
}

/** A sign face's outcome: the Signature-Agent the SDK writes. */
export function signOutcome(signatureAgent: string | null | undefined): string {
	return `writes Signature-Agent: ${signatureAgent}`;
}

/** The outcome of a face that threw instead of answering. */
export function raisedOutcome(err: unknown): string {
	if (err instanceof Error && "reason" in err) return `throws ${err.name} (${String(err.reason)})`;
	return `throws ${err instanceof Error ? err.name : String(err)}`;
}

const SIGNS_URL = "a signer writes the well-known key directory URL, a bare origin completed to it (WG-01 §5.2.1)";
const READS_URL = "a member naming the well-known key directory URL names that directory (WG-01 §5.5)";
const PARAMETER = "a member with a parameter is ignored (WG-01 §5.2.1), so the signature names no directory";
const OTHER_URL = "another path, a query or a fragment is refused with refusal kind not_key_directory";
const SIGN_ACCEPTS_URL = "a signer accepts the well-known key directory URL as its configured value";
const SIGN_OTHER_URL = "a signer refuses another path, a query or a fragment as signature_agent_not_key_directory";

const RPC_ACCEPT =
	'sig1=("@method" "@target-uri" "content-digest" "authorization" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"';
const POP_ACCEPT = 'sig1=("@method" "@target-uri" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"';
const RPC_REFUSED_AT_MEMBER = verifyOutcome(false, "signature", RPC_ACCEPT);
const POP_REFUSED_AT_MEMBER = verifyOutcome(false, "bad_signature_agent", POP_ACCEPT);
const REFUSES_URL = "throws WebBotAuthError (signature_agent_not_origin)";
const TWO_ORIGINS = 'sig1="https://agent.example", sig2="https://broker.example"';
const THREE_ORIGINS = `${TWO_ORIGINS}, sig3="https://relay.example:8443"`;

const WBA = "wba-signature-agent-vectors";
const SIGN_REQUEST = "sign-request-vectors";
const POP = "pop-vectors";
const MULTISIG = "multisig-chain-vectors";

function rows(corpus: string, face: "sign" | "verify", entry: Pending, names: string[]): Record<string, Pending> {
	return Object.fromEntries(names.map((n) => [`${corpus}#${n}:${face}`, entry]));
}

const SIGN_REQUEST_ORIGINS: Array<[string, string]> = [
	["post_with_authorization", "https://agent.example"],
	["post_empty_authorization_bound", "https://agent.example:8443"],
	["append_relay_leg", "https://relay.example"],
	["post_with_nonce", "https://agent.example"],
	["post_empty_authorization_bound_with_nonce", "https://agent.example:8443"],
	["append_relay_leg_with_nonce", "https://relay.example"],
	["doc_single_hop_example", "https://research.acme.com"],
	["doc_broker_example", "https://broker.example"],
];

export const PENDING_WBA_01: Record<string, Pending> = {
	// wba-signature-agent-vectors.json, verifier rows.
	...rows(WBA, "verify", { rule: READS_URL, today: RPC_REFUSED_AT_MEMBER }, [
		"vectors/well_known_url",
		"vectors/well_known_url_with_port",
		"vectors/legacy_string_well_known_url",
		"vectors/member_key_differs_from_label",
		"vectors/repeated_field_lines_member_on_first",
		"vectors/repeated_field_lines_member_on_second",
		"vectors/escaped_quote_in_another_member",
		"vectors/ignored_member_beside_the_signers",
	]),
	...rows(WBA, "verify", { rule: PARAMETER, today: RPC_REFUSED_AT_MEMBER }, [
		"vectors/member_with_parameter",
		"vectors/member_with_other_parameter",
		"vectors/member_type_other",
		"vectors/member_not_a_string_with_parameter",
		"vectors/legacy_string_with_parameter",
		"vectors/repeated_field_lines_member_with_parameter",
	]),
	// The SDK follows a type=directory member as -00 did, into the directory the row
	// records none for, so the key is not found there.
	...rows(WBA, "verify", { rule: PARAMETER, today: verifyOutcome(false, "signature") }, [
		"vectors/member_type_directory_string",
		"vectors/member_type_directory_token",
	]),
	...rows(WBA, "verify", { rule: OTHER_URL, today: RPC_REFUSED_AT_MEMBER }, [
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
	...rows(WBA, "sign", { rule: SIGNS_URL, today: signOutcome('sig1="https://agent.example"') }, [
		"signer/origin_completed",
	]),
	...rows(WBA, "sign", { rule: SIGNS_URL, today: signOutcome('sig1="https://relay.example:8443"') }, [
		"signer/origin_with_port_completed",
	]),
	...rows(WBA, "sign", { rule: SIGN_ACCEPTS_URL, today: REFUSES_URL }, ["signer/well_known_url_as_given"]),
	...rows(WBA, "sign", { rule: SIGN_OTHER_URL, today: REFUSES_URL }, [
		"signer/other_path",
		"signer/query",
		"signer/fragment",
	]),
	// sign-request-vectors.json: every row carries the well-known URL member. The SDK
	// signs each row's configured origin as the bare origin.
	...Object.fromEntries(
		SIGN_REQUEST_ORIGINS.map(([row, origin]) => [
			`${SIGN_REQUEST}#${row}:sign`,
			{ rule: SIGNS_URL, today: signOutcome(`sig1="${origin}"`) },
		]),
	),
	...rows(
		SIGN_REQUEST,
		"verify",
		{ rule: READS_URL, today: RPC_REFUSED_AT_MEMBER },
		SIGN_REQUEST_ORIGINS.map(([row]) => row),
	),
	// pop-vectors.json: the proofs the Go signer made carry the URL member.
	...rows(POP, "sign", { rule: SIGNS_URL, today: signOutcome('sig1="https://agent.example"') }, [
		"valid",
		"valid_no_nonce",
		"expired",
	]),
	...rows(POP, "verify", { rule: READS_URL, today: POP_REFUSED_AT_MEMBER }, ["valid", "valid_no_nonce", "expired"]),
	// multisig-chain-vectors.json: the positive chains' members name the URL.
	...rows(MULTISIG, "verify", { rule: READS_URL, today: RPC_REFUSED_AT_MEMBER }, [
		"positive_independent_two",
		"positive_covering_two",
		"positive_covering_three",
		"positive_covering_two_nonce",
		"canonical_case_two",
		"duplicate_bound_two",
	]),
	...rows(MULTISIG, "sign", { rule: SIGNS_URL, today: signOutcome(TWO_ORIGINS) }, [
		"positive_independent_two",
		"positive_covering_two",
		"positive_covering_two_nonce",
		"canonical_case_two",
		"duplicate_bound_two",
	]),
	...rows(MULTISIG, "sign", { rule: SIGNS_URL, today: signOutcome(THREE_ORIGINS) }, [
		"positive_covering_three",
		"hop_budget_three_independent_over_two",
		"hop_budget_three_covering_over_two",
		"absent_authorization_over_budget",
	]),
};

/** Every key a test in this file registered, pending or not. */
const registered = new Set<string>();

// isAssertion tells an assertion failure from any other error.
function isAssertion(err: unknown): boolean {
	return err instanceof Error && err.name === "AssertionError";
}

/** What a test over a row reports the SDK's outcome to. */
export type Observe = (outcome: string) => void;
type TestBody = (observe: Observe) => unknown;

const ignore: Observe = () => undefined;

/** wba01It returns the registration for a test over one corpus row: vitest's `it`, or,
 * when the row is pending for this face, a test that must fail on an assertion after
 * reporting the recorded outcome. Anything else returns normally, which it.fails reports
 * as a failure, with the reason written to stderr. */
export function wba01It(corpus: string, row: string, face: "sign" | "verify"): (name: string, fn: TestBody) => void {
	const key = `${corpus}#${row}:${face}`;
	registered.add(key);
	const entry = PENDING_WBA_01[key];
	if (entry === undefined) return (name, fn) => it(name, async () => void (await fn(ignore)));
	return (name, fn) =>
		it.fails(`${name} (pending -01: ${entry.rule})`, async () => {
			const recorded = typeof entry.today === "string" ? entry.today : entry.today[name];
			let observed = false;
			const observe: Observe = (outcome) => {
				observed = true;
				if (outcome !== recorded) {
					throw new PendingOutcomeChangedError(
						`${key} [${name}]: the SDK's outcome is now ${JSON.stringify(outcome)}, the pending list records ${JSON.stringify(recorded)}. Delete the entry if the row passes, or record the new outcome.`,
					);
				}
			};
			try {
				await fn(observe);
			} catch (err) {
				if (isAssertion(err) && observed) throw err;
				console.error(
					observed ? String(err) : `${key} [${name}]: the test never reported its outcome (${String(err)})`,
				);
				return;
			}
			console.error(`${key} [${name}]: the row passes; delete its pending entry`);
		});
}

/** wba01Owns declares that this file registers every pending entry of one (corpus, face)
 * pair, and registers the test that checks it after the file's tests are collected. */
export function wba01Owns(corpus: string, face: "sign" | "verify"): void {
	it(`every pending ${corpus} ${face} entry is registered by a test in this file`, () => {
		const prefix = `${corpus}#`;
		const suffix = `:${face}`;
		const missing = Object.keys(PENDING_WBA_01).filter(
			(k) => k.startsWith(prefix) && k.endsWith(suffix) && !registered.has(k),
		);
		expect(missing).toEqual([]);
	});
}
