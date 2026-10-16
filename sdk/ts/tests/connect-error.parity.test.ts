// Connect error-envelope parity (TypeScript side) — replay of the shared Go-oracle corpus.
//
// Mirrors the sdk/python sibling test_connect_error_parity.py and the Go leg
// sdk/go/connect/connect_error_corpus_test.go.
//
// error-detail-vectors.json pins the DETAIL's own proto-JSON. This corpus pins the
// ENVELOPE the detail arrives in, which is the form this SDK actually reads: the detail's
// `value` (the binary ErrorDetail, base64) first, and Connect's `debug` projection only
// when no `value` is present. The derived rows hold that order: `*.value_only` carries no
// projection, `value_wins_over_debug` carries a projection of a different detail, and
// `undecodable_value_skipped` carries an intact projection beside a value that is not an
// ErrorDetail and must still read as no detail.
//
// The projection is lowerCamelCase and no server option changes it — connect-go builds
// it with its own protojson codec at default options — while the response bodies the
// same server emits are snake_case. Reading `debug` with a snake-only schema therefore
// used to return a detail carrying `domain` and `message` (single words spell the same
// either way) and NO typed reason, for a refusal the Exchange had named precisely. The
// failure was silent: the parse succeeded, and the unknown reason block was removed by
// the .strip() forward-compatibility policy that exists for a newer protocol version.
//
// Every vector here was CAPTURED from a real connect-go handler, so the fix is asserted
// against what the wire does rather than against a description of it. Each row is also
// decoded with strict decoding on, which must refuse exactly the rows marked
// `strict_malformed` and read every other row as the lenient client does.
import { describe, it, expect } from "vitest";
import { ErrorDetailSchema } from "../../../gen/ts/wire/schemas.ts";
import { errorDetailFrom, reason } from "../src/errordetail.ts";
import { ForaCallError } from "../client/errors.ts";
import { decodeResponse } from "../client/transport.ts";
import vectorsFile from "../../go/connect/testdata/connect-error-vectors.json";

type ConnectErrorVector = {
	name: string;
	code: string;
	http_status: number;
	envelope: unknown;
	expect: {
		has_detail: boolean;
		domain: string;
		message: string;
		metadata: Record<string, string> | null;
		reason_field: string;
		reason_enum: string;
		detail: Record<string, unknown> | null;
	};
	peer_message: string;
	strict_malformed: boolean;
};
type VectorsFile = { note: string; vectors: ConnectErrorVector[] };

const vectors = (vectorsFile as VectorsFile).vectors;

// The row through a strict decode: refused as malformed with the code kept and no detail
// when the corpus marks it strict_malformed, otherwise exactly the lenient read.
function assertStrictRead(v: ConnectErrorVector, lenient: ForaCallError): void {
	let thrown: unknown;
	try {
		decodeResponse("discover", { status: v.http_status, body: JSON.stringify(v.envelope) }, true);
	} catch (e) {
		thrown = e;
	}
	expect(thrown, v.name).toBeInstanceOf(ForaCallError);
	const strict = thrown as ForaCallError;
	expect(strict.code, v.name).toBe(v.code);
	expect(strict.status, v.name).toBe(v.http_status);
	if (v.strict_malformed) {
		expect(strict.kind, `${v.name}: ${String(strict.cause)}`).toBe("malformed");
		expect(strict.detail, v.name).toBeUndefined();
		expect(strict.peerMessage ?? "", v.name).toBe("");
		return;
	}
	expect(strict.kind, `${v.name}: ${String(strict.cause)}`).toBe(lenient.kind);
	expect(strict.detail ?? null, v.name).toEqual(lenient.detail ?? null);
	expect(strict.peerMessage ?? "", v.name).toBe(lenient.peerMessage ?? "");
}

describe("sdk/ts reads a Connect error envelope the way the sdk/go oracle does", () => {
	it("connect-error vector set is non-empty", () => {
		expect(vectors.length).toBeGreaterThan(0);
	});

	it("every vector records the status connect-go maps its code onto", () => {
		// Recorded by the emitter and, until now, read by nobody — so the corpus carried a
		// column that asserted nothing. It matters because this reader is reached from a
		// non-2xx, and which non-2xx decides the failure CLASS when an envelope names no
		// code of its own.
		for (const v of vectors) {
			expect(Number.isInteger(v.http_status), v.name).toBe(true);
			expect(v.http_status, `${v.name}: code ${v.code}`).toBeGreaterThanOrEqual(400);
			expect(v.http_status).toBeLessThan(600);
		}
	});

	for (const v of vectors) {
		it(`extracts the Go projection: ${v.name}`, () => {
			const detail = errorDetailFrom(v.envelope);

			// BEFORE the early return, because the row that carries no detail is the one
			// this column exists for: its envelope has a `message` of its own and the
			// client must still report none. The field lives on the ForaCallError, one
			// tier above the detail the rest of this replay projects.
			//
			// The rule is provenance: it carries a message the PEER emitted and nothing
			// else. A transport's synthesized text is not that — connect-go writes a
			// status line where this client writes nothing — so filling the field from
			// the envelope would make its value a property of the language rather than
			// of the answer.
			let thrown: unknown;
			try {
				decodeResponse("discover", {
					status: v.http_status,
					body: JSON.stringify(v.envelope),
				});
			} catch (e) {
				thrown = e;
			}
			expect(thrown, v.name).toBeInstanceOf(ForaCallError);
			expect((thrown as ForaCallError).peerMessage ?? "").toBe(v.peer_message);
			// The Connect code the envelope names, on its own field: every row, detail or
			// not, because the code is a property of the answer rather than of the detail.
			expect((thrown as ForaCallError).code, v.name).toBe(v.code);
			expect((thrown as ForaCallError).detail ?? null).toEqual(detail);
			assertStrictRead(v, thrown as ForaCallError);

			if (!v.expect.has_detail) {
				expect(detail).toBeNull();
				return;
			}
			expect(detail).not.toBeNull();
			const got = detail as NonNullable<typeof detail>;
			expect(got.domain).toBe(v.expect.domain);
			expect(got.message).toBe(v.expect.message);

			// Metadata keys are the EMITTER's, not the proto's. The corpus carries a
			// deliberately lowerCamelCase key so a normalizer that walked into the map
			// would rewrite it and fail here.
			expect(got.metadata ?? {}).toEqual(v.expect.metadata ?? {});

			// The whole detail, not only the projection: a nested member lost on the way
			// (field_errors, a metadata entry) fails here. Both sides go through the
			// generated schema, so declared defaults are filled on each alike.
			expect(got).toEqual(ErrorDetailSchema.parse(v.expect.detail));

			const typed = reason(got);
			if (v.expect.reason_field === "") {
				expect(typed).toBeNull();
				return;
			}
			expect(typed).not.toBeNull();
			expect(typed?.field).toBe(v.expect.reason_field);
			expect(typed?.value).toBe(v.expect.reason_enum);
		});
	}

	// The regression itself, stated once in the open rather than only via the corpus. A
	// snake-only read of this envelope parses successfully and reports no reason — which
	// is why nothing caught it before the corpus existed. The entry carries no `value`,
	// which is the one case the projection is read at all.
	it("decodes the lowerCamelCase debug projection when no value is present", () => {
		const detail = errorDetailFrom({
			code: "permission_denied",
			message: "balance too low",
			details: [
				{
					type: "fora.v1.ErrorDetail",
					debug: {
						domain: "fora.v1.ExchangeService",
						message: "balance too low",
						transactionDenial: { reason: "DENIAL_REASON_INSUFFICIENT_BALANCE" },
					},
				},
			],
		});
		expect(detail).not.toBeNull();
		expect(reason(detail as NonNullable<typeof detail>)).toEqual({
			field: "transaction_denial",
			value: "DENIAL_REASON_INSUFFICIENT_BALANCE",
		});
	});
});
