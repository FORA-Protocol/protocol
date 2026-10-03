// Strict response decoding: ClientOptions.strict.
//
// The generated schemas the client parses answers with drop an unknown field, so an older
// client keeps working against a newer Exchange. Under `strict: true` the client checks
// every success answer against the published STRICT JSON Schema of its message and the
// proto's cross-field rules first, and refuses one that fails as `malformed`. An error
// answer's Connect envelope and every ErrorDetail in it are checked the same way.
import { describe, expect, it } from "vitest";

import { createClient, ForaCallError, type ClientOptions } from "../client/index.ts";
import { decodeResponse } from "../client/transport.ts";

const RESPONSE = { ver: "1.0", exchange: "exchange.test" };

function client(answer: unknown, opts: ClientOptions = {}) {
	return createClient("https://exchange.test", {
		send: async () => ({ status: 200, body: JSON.stringify(answer) }),
		guardedSend: async () => ({ status: 200, body: JSON.stringify(answer) }),
		endpointResolver: { resolveEndpoint: async (host) => `https://${host}` },
		...opts,
	});
}

const QUERY = { exchange: "exchange.test", uris: ["https://site.test/a"] };

async function failure(p: Promise<unknown>): Promise<ForaCallError> {
	try {
		await p;
	} catch (e) {
		expect(e).toBeInstanceOf(ForaCallError);
		return e as ForaCallError;
	}
	throw new Error("the call did not fail");
}

describe("strict decoding", () => {
	it("accepts a well-formed answer", async () => {
		const result = await client(RESPONSE, { strict: true }).discover(QUERY);
		expect(result.exchange).toBe("exchange.test");
	});

	it("refuses an unknown field at the top level", async () => {
		const answer = { ...RESPONSE, surprise: true };
		// The default stays forward-compatible: the field is dropped.
		await expect(client(answer).discover(QUERY)).resolves.toBeDefined();
		const f = await failure(client(answer, { strict: true }).discover(QUERY));
		expect(f.kind).toBe("malformed");
		expect(f.message).toContain("surprise");
	});

	it("refuses an unknown field nested in a message", async () => {
		const answer = {
			...RESPONSE,
			offers: [{ exchange: "exchange.test", offer_id: "o-1", surprise: 1 }],
		};
		const f = await failure(client(answer, { strict: true }).discover(QUERY));
		expect(f.kind).toBe("malformed");
		expect(f.message).toContain("/offers/0");
	});

	it("refuses a camelCase spelling, which is an unknown field", async () => {
		const answer = { ver: "1.0", reportId: "r-1" };
		const f = await failure(
			client(answer, { strict: true }).reportUsage({ exchange: "exchange.test", transaction_id: "t" }),
		);
		expect(f.kind).toBe("malformed");
	});

	it("applies the cross-field rules to the answer itself", async () => {
		// terms_digest set with no billing_ref breaks
		// get_account_status_response.terms_digest_requires_billing_ref.
		const answer = { ver: "1.0", terms_digest: `sha256:${"a".repeat(64)}` };
		const opts = { strict: true } as const;
		const f = await failure(client(answer, opts).getAccountStatus({ exchange: "exchange.test" }));
		expect(f.kind).toBe("malformed");
		expect(f.message).toContain("get_account_status_response.terms_digest_requires_billing_ref");
	});

	it("applies the cross-field rules to a nested message", async () => {
		const answer = {
			...RESPONSE,
			offers: [
				{ exchange: "exchange.test", pricing: { model: "PRICING_MODEL_FREE", rate: "5" } },
			],
		};
		const f = await failure(client(answer, { strict: true }).discover(QUERY));
		expect(f.message).toContain("pricing.free.zero_rate");
		expect(f.message).toContain("/offers/0/pricing");
	});

	it("reads a null member of a message as absent, and leaves an ext open", async () => {
		const answer = {
			...RESPONSE,
			rate_limit: null,
			ext: { anything: { goes: null } },
		};
		await expect(client(answer, { strict: true }).discover(QUERY)).resolves.toBeDefined();
	});

	it("refuses an error envelope carrying an unknown member, keeping the code", async () => {
		const answering = (strict: boolean) =>
			createClient("https://exchange.test", {
				strict,
				send: async () => ({
					status: 403,
					body: JSON.stringify({ code: "permission_denied", message: "no", unknown_member: 1 }),
				}),
			}).discover(QUERY);

		// The default client reads the peer's refusal and ignores the member.
		const lenient = await failure(answering(false));
		expect(lenient.kind).toBe("refused");

		const f = await failure(answering(true));
		expect(f.kind).toBe("malformed");
		expect(f.code).toBe("permission_denied");
		expect(f.status).toBe(403);
		expect(f.detail).toBeUndefined();
		expect(String(f.cause)).toContain("unknown_member");
	});
});

// A binary ErrorDetail (a transaction denial), base64 the way connect-go writes it, with
// `extra` bytes appended.
function denialValue(extra: number[] = []): string {
	const reason = [0x08, 0x02]; // TransactionDenial.reason = INSUFFICIENT_BALANCE
	const raw = [0x12, 0x02, 0x6f, 0x6b, 0x52, reason.length, ...reason, ...extra];
	return btoa(String.fromCharCode(...raw)).replace(/=+$/, "");
}

const DETAIL = "fora.v1.ErrorDetail";

// [name, status, body, refused by a strict decode]. Every case also runs leniently, which
// must not refuse it as malformed: the strict refusal comes from `strict` alone.
const ENVELOPE_CASES: Array<[string, number, string, boolean]> = [
	[
		"valid envelope",
		403,
		JSON.stringify({
			code: "permission_denied",
			message: "no",
			details: [{ type: DETAIL, value: denialValue() }],
		}),
		false,
	],
	["null members read as absent", 500, JSON.stringify({ code: "internal", message: null, details: null }), false],
	[
		"a detail of another type is not decoded",
		500,
		JSON.stringify({
			code: "internal",
			details: [{ type: "google.rpc.RetryInfo", value: "AA", debug: { any: "thing" } }],
		}),
		false,
	],
	["a body that is not JSON is a gateway's", 502, "<html>bad gateway</html>", false],
	["an empty body is a gateway's", 503, "", false],
	["no code", 500, JSON.stringify({ message: "x" }), true],
	["code not a Connect code", 500, JSON.stringify({ code: "teapot" }), true],
	["code not a string", 500, JSON.stringify({ code: 13 }), true],
	["message not a string", 500, JSON.stringify({ code: "internal", message: 1 }), true],
	["JSON but not an object", 500, JSON.stringify(["internal"]), true],
	["details not an array", 500, JSON.stringify({ code: "internal", details: {} }), true],
	[
		"entry with an unknown member",
		500,
		JSON.stringify({ code: "internal", details: [{ type: "x", value: "AA", extra: 1 }] }),
		true,
	],
	["entry with no type", 500, JSON.stringify({ code: "internal", details: [{ value: "AA" }] }), true],
	["entry with neither value nor debug", 500, JSON.stringify({ code: "internal", details: [{ type: "x" }] }), true],
	["value not base64", 500, JSON.stringify({ code: "internal", details: [{ type: "x", value: "*not*" }] }), true],
	[
		"binary ErrorDetail with an unknown field",
		403,
		JSON.stringify({
			code: "permission_denied",
			details: [{ type: DETAIL, value: denialValue([0x98, 0x06, 0x01]) }],
		}),
		true,
	],
	[
		"debug projection that is not an object",
		403,
		JSON.stringify({ code: "permission_denied", details: [{ type: DETAIL, debug: "x" }] }),
		true,
	],
	[
		"debug projection setting two reasons",
		403,
		JSON.stringify({
			code: "permission_denied",
			details: [
				{
					type: DETAIL,
					debug: {
						transactionDenial: { reason: "DENIAL_REASON_INSUFFICIENT_BALANCE" },
						disputeFailure: { reason: "DISPUTE_FAILURE_REASON_DUPLICATE" },
					},
				},
			],
		}),
		true,
	],
];

function thrownBy(fn: () => unknown): ForaCallError {
	try {
		fn();
	} catch (e) {
		expect(e).toBeInstanceOf(ForaCallError);
		return e as ForaCallError;
	}
	throw new Error("the decode did not fail");
}

describe("strict decoding of an error envelope", () => {
	for (const [name, status, body, refused] of ENVELOPE_CASES) {
		it(name, () => {
			const lenient = thrownBy(() => decodeResponse("discover", { status, body }));
			expect(lenient.kind).not.toBe("malformed");

			const strict = thrownBy(() => decodeResponse("discover", { status, body }, true));
			expect(strict.kind === "malformed", String(strict.cause)).toBe(refused);
			// The strict read keeps the code the lenient read reports, refused or not.
			expect(strict.code).toBe(lenient.code);
		});
	}
});
