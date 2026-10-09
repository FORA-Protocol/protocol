// ErrorDetail binary decoding (TypeScript side) — replay of the shared Go-oracle corpus
// sdk/go/connect/testdata/error-detail-wire-vectors.json.
//
// Mirrors sdk/python/tests and the Go leg gen_error_detail_wire_vectors_test.go.
//
// This SDK reads details[].value without a protobuf runtime, through a decoder driven by
// hand-written tables. The corpus pins those tables from both sides: `wire` is the same
// tables read from the compiled descriptor, which ours must EQUAL, and `vectors` are
// binary encodings, together setting every field of the subtree, that must decode to the
// proto-JSON Go renders for them.
import { describe, expect, it } from "vitest";

import {
	decodeErrorDetailValue,
	ERROR_DETAIL_WIRE_ENUMS,
	ERROR_DETAIL_WIRE_MESSAGES,
} from "../src/errordetail-wire.ts";
import { errorDetailFrom, REASON_FIELDS } from "../src/errordetail.ts";
import { ErrorDetailSchema } from "../../../gen/ts/wire/schemas.ts";
import corpus from "../../go/connect/testdata/error-detail-wire-vectors.json";

type WireVector = { name: string; value: string; detail: Record<string, unknown> };
const file = corpus as {
	wire: { messages: unknown; enums: unknown };
	vectors: WireVector[];
};

describe("the ErrorDetail decoder tables are the descriptor's", () => {
	it("messages", () => {
		expect(ERROR_DETAIL_WIRE_MESSAGES).toEqual(file.wire.messages);
	});
	it("enums", () => {
		expect(ERROR_DETAIL_WIRE_ENUMS).toEqual(file.wire.enums);
	});
});

describe("sdk/ts decodes a binary ErrorDetail the way the sdk/go oracle does", () => {
	it("the vector set is non-empty", () => {
		expect(file.vectors.length).toBeGreaterThan(0);
	});

	for (const v of file.vectors) {
		it(v.name, () => {
			expect(decodeErrorDetailValue(v.value, REASON_FIELDS)).toEqual(v.detail);
			// And through the public reader, as a Connect envelope carrying only the value.
			const detail = errorDetailFrom([{ type: "fora.v1.ErrorDetail", value: v.value }]);
			expect(detail).toEqual(ErrorDetailSchema.parse(v.detail));
		});
	}
});

/** Unpadded base64 of raw bytes. */
function b64(bytes: number[]): string {
	return Buffer.from(bytes).toString("base64").replace(/=+$/, "");
}

describe("protobuf decoding rules the corpus does not spell out", () => {
	// dispute_failure{reason:4} then request_auth_failure{reason:1}: two members of the
	// reason oneof. Protobuf keeps the last one written.
	const twoReasons = [0x6a, 0x02, 0x08, 0x04, 0x8a, 0x01, 0x02, 0x08, 0x01];

	it("keeps only the last member of the reason oneof", () => {
		expect(decodeErrorDetailValue(b64(twoReasons), REASON_FIELDS)).toEqual({
			request_auth_failure: { reason: "REQUEST_AUTH_FAILURE_REASON_SIGNATURE_MISSING" },
		});
	});

	it("skips a known field whose wire type does not fit its kind", () => {
		// domain (2) written as a varint, then message (1) as a string.
		const bytes = [0x10, 0x05, 0x0a, 0x01, 0x78];
		expect(decodeErrorDetailValue(b64(bytes), REASON_FIELDS)).toEqual({ message: "x" });
	});

	it("merges a singular message written twice", () => {
		// transaction_denial{reason:2} then transaction_denial{offer_id:"o"}.
		const bytes = [0x52, 0x02, 0x08, 0x02, 0x52, 0x03, 0x1a, 0x01, 0x6f];
		expect(decodeErrorDetailValue(b64(bytes), REASON_FIELDS)).toEqual({
			transaction_denial: { reason: "DENIAL_REASON_INSUFFICIENT_BALANCE", offer_id: "o" },
		});
	});

	it("accepts the URL alphabet and padding", () => {
		// domain "???": its standard base64 carries a "/", which the URL alphabet spells "_".
		const bytes = Buffer.from([0x12, 0x03, 0x3f, 0x3f, 0x3f]);
		expect(bytes.toString("base64")).toContain("/");
		for (const value of [bytes.toString("base64"), bytes.toString("base64url")]) {
			expect(decodeErrorDetailValue(value, REASON_FIELDS), value).toEqual({ domain: "???" });
		}
		const padded = Buffer.from([0x12, 0x02, 0x61, 0x62]).toString("base64");
		expect(padded.endsWith("=")).toBe(true);
		expect(decodeErrorDetailValue(padded, REASON_FIELDS)).toEqual({ domain: "ab" });
	});

	it("refuses a truncated buffer, a group and invalid UTF-8", () => {
		for (const bytes of [
			[0x12, 0x05, 0x61],
			[0x0b, 0x0c],
			[0x12, 0x02, 0xc3, 0x28],
			[0x12],
		]) {
			expect(decodeErrorDetailValue(b64(bytes), REASON_FIELDS), JSON.stringify(bytes)).toBeUndefined();
		}
	});

	it("refuses a value that is not base64", () => {
		expect(decodeErrorDetailValue("not base64!", REASON_FIELDS)).toBeUndefined();
	});

	it("reads metadata with several entries", () => {
		const entry = (k: string, v: string) => {
			const body = [0x0a, k.length, ...Buffer.from(k), 0x12, v.length, ...Buffer.from(v)];
			return [0x1a, body.length, ...body];
		};
		const bytes = [...entry("a", "1"), ...entry("b", "2"), ...entry("a", "3")];
		expect(decodeErrorDetailValue(b64(bytes), REASON_FIELDS)).toEqual({
			metadata: { a: "3", b: "2" },
		});
	});
});
