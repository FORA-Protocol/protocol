// Strict response decoding: ClientOptions.strict.
//
// The generated schemas the client parses answers with drop an unknown field, so an older
// client keeps working against a newer Exchange. Under `strict: true` the client checks
// every success answer against the published STRICT JSON Schema of its message and the
// proto's cross-field rules first, and refuses one that fails as `malformed`.
import { describe, expect, it } from "vitest";

import { createClient, ForaCallError, type ClientOptions } from "../client/index.ts";

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

	it("leaves error envelopes alone", async () => {
		const f = await failure(
			createClient("https://exchange.test", {
				strict: true,
				send: async () => ({
					status: 403,
					body: JSON.stringify({ code: "permission_denied", message: "no", unknown_member: 1 }),
				}),
			}).discover(QUERY),
		);
		expect(f.kind).toBe("refused");
		expect(f.code).toBe("permission_denied");
	});
});
