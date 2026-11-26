// What a corpus replay compares with (ADR-002): the outcome of a call in the one corpus
// format, the outcome this port's expected-failure file records for a row, the typed
// reason an error-detail row records, and lookups over a corpus's rows.

import { type ErrorDetail, REASON_FIELDS, reason } from "@fora-protocol/sdk-l1/errordetail";
import { expect } from "vitest";
import registry from "../../../parity/corpora.json";
import expectedFailuresFile from "../expected-failures.json";

/** The corpus outcome (ADR-002 rule 3) of a call that accepted, or refused for
 * `reason`, the token the SDK reported. A refusal without a token renders as
 * "refused:", which matches no row. */
export function outcomeOf(accepted: boolean, reason?: string): string {
	return accepted ? "accepted" : `refused:${reason ?? ""}`;
}

/** One entry of this port's expected-failure file. */
interface ExpectedFailure {
	row: string;
	outcome: string;
	why: string;
}

// The registry names this port's expected-failure file; the import above must be it.
const EXPECTED_FAILURES_PATH = "sdk/ts/tests/expected-failures.json";
if (registry.expected_failures.ts !== EXPECTED_FAILURES_PATH) {
	throw new Error(`the registry names ${registry.expected_failures.ts}, not ${EXPECTED_FAILURES_PATH}`);
}
const expectedFailures = new Map((expectedFailuresFile.entries as ExpectedFailure[]).map((e) => [e.row, e.outcome]));

/** The outcome a replay asserts for the row at `pointer` (`<corpus>#<row>`): the
 * outcome this port's expected-failure file records for it, or else the row's own.
 * So a listed row fails when it starts passing and when it fails differently
 * (ADR-002 rule 6). */
export function expectedOutcome(pointer: string, outcome: string): string {
	return expectedFailures.get(pointer) ?? outcome;
}

/** The row named `name`; throws when the corpus has none. */
export function rowNamed<T extends { name: string }>(rows: readonly T[], name: string): T {
	const row = rows.find((r) => r.name === name);
	if (row === undefined) throw new Error(`missing vector ${name}`);
	return row;
}

/** The labels in `required` that no row carries. */
export function missingLabels(rows: readonly { label: string }[], required: readonly string[]): string[] {
	const labels = new Set(rows.map((r) => r.label));
	return required.filter((l) => !labels.has(l));
}

/** A row of error-detail-vectors.json. */
export type ErrorDetailVector = {
	name: string;
	domain: string;
	message: string;
	metadata: Record<string, string> | null;
	reason_field: string;
	reason_enum: string;
	field_errors: { path: string; error: string }[] | null;
	wire_json: unknown;
};
export type ErrorDetailVectorsFile = { canonicalization: string; vectors: ErrorDetailVector[] };

/** Exactly the row's `reason_field` member of `detail` is populated, and its typed
 * reason is the row's `reason_enum`. */
export function expectRecordedReason(detail: ErrorDetail, row: { reason_field: string; reason_enum: string }): void {
	const record = detail as Record<string, unknown>;
	expect(REASON_FIELDS.filter((f) => record[f] != null)).toEqual([row.reason_field]);
	const got = reason(detail);
	expect(got).not.toBeNull();
	expect(got?.field).toBe(row.reason_field);
	expect(got?.value).toBe(row.reason_enum);
}
