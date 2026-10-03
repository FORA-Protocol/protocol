// BrokerClient.execute and the batch form of Client.execute (TypeScript side) — mirror
// of sdk/go/connect/broker_execute_test.go.
//
// Driven through an INJECTED send, like the rest of this client's verb tests: what is
// under test is the request the client builds and signs, the refusals it makes before
// sending, and how it decodes the Broker's combined answer — not undici.
import { describe, expect, it } from "vitest";

import {
	createBrokerClient,
	createClient,
	type ForaCallError,
	type UnaryRequest,
	type UnarySend,
} from "../client/index.ts";
import { createVerifier, type VerifiedOffer } from "../core/verifier.ts";
import { verifyOfferAcceptance, verifyRequestAcceptance } from "../src/acceptance.ts";
import { signOffer } from "../src/offer-sign.ts";

const REQUESTER = { id: "agent-1", domain: "agent.test", type: "REQUESTER_TYPE_AGENT" };
/** The directory the agent signs as; REQUESTER.domain is its host. */
const AGENT_DIRECTORY = "https://agent.test";

function recordingSend(
	answer: unknown,
	status = 200,
): { send: UnarySend; seen: UnaryRequest[] } {
	const seen: UnaryRequest[] = [];
	const send: UnarySend = async (req) => {
		seen.push(req);
		return { status, body: JSON.stringify(answer) };
	};
	return { send, seen };
}

function bodyOf(req: UnaryRequest): Record<string, unknown> {
	return JSON.parse(new TextDecoder().decode(req.body)) as Record<string, unknown>;
}

async function keyPair(): Promise<CryptoKeyPair> {
	return (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
		"sign",
		"verify",
	])) as CryptoKeyPair;
}

/** An offer issued and signed by `exchange`, verified the way a client verifies it. */
async function offerAt(
	id: string,
	exchange: string,
): Promise<{ offer: Record<string, unknown>; verified: VerifiedOffer }> {
	const kp = await keyPair();
	const publicKey = new Uint8Array(
		await crypto.subtle.exportKey("raw", kp.publicKey),
	) as Uint8Array<ArrayBuffer>;
	const unsigned: Record<string, unknown> = {
		offer_id: id,
		exchange,
		expires_at: "2099-01-01T00:00:00Z",
	};
	const signature = await signOffer(unsigned, kp.privateKey);
	const offer = { ...unsigned, signature, signature_algorithm: "EdDSA" };
	const sorted = await createVerifier("strict", {
		resolve: async () => publicKey,
		now: () => Date.parse("2024-01-01T00:00:00Z"),
	}).sort([offer]);
	const verified = sorted.verified[0];
	if (verified === undefined) throw new Error(`fixture offer did not verify: ${id}`);
	return { offer, verified };
}

const COMBINED = {
	ver: "1.0",
	items: [
		{ offer_id: "offer-a1", transaction_id: "tx-a1", cost: { amount: "1.25", currency: "USD" } },
		{
			offer_id: "offer-b1",
			refusal: {
				exchange: "exchange-b.test",
				code: "permission_denied",
				detail: {
					domain: "fora.v1.ExchangeService",
					message: "no account",
					transaction_denial: { reason: "DENIAL_REASON_ACCOUNT_NOT_REGISTERED" },
				},
			},
		},
		{ offer_id: "offer-a2", transaction_id: "tx-a2", cost: { amount: "1.25", currency: "EUR" } },
	],
	exchanges: [
		{ exchange: "exchange-a.test", offer_ids: ["offer-a1", "offer-a2"], agent_identity_hash: "thumb" },
		{ exchange: "exchange-b.test", offer_ids: ["offer-b1"] },
	],
	totals: [
		{ amount: "1.25", currency: "USD" },
		{ amount: "1.25", currency: "EUR" },
	],
};

describe("BrokerClient.execute", () => {
	it("relays a mixed batch as one signed request and decodes the combined answer", async () => {
		const a1 = await offerAt("offer-a1", "exchange-a.test");
		const b1 = await offerAt("offer-b1", "exchange-b.test");
		const a2 = await offerAt("offer-a2", "exchange-a.test");
		const keys = await keyPair();
		const { send, seen } = recordingSend(COMBINED);
		const broker = createBrokerClient("https://broker.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			signatureAgent: AGENT_DIRECTORY,
			send,
		});

		const resp = await broker.execute([a1.verified, b1.verified, a2.verified], {
			idempotencyKey: "relay-key",
		});

		expect(seen[0]?.url).toBe("https://broker.test/fora.v1.BrokerService/ExecuteTransaction");
		const body = bodyOf(seen[0] as UnaryRequest);
		expect(body["ver"]).toBe("1.0");
		expect(body["idempotency_key"]).toBe("relay-key");
		expect(body["requester"]).toEqual(REQUESTER);
		const items = body["items"] as Array<Record<string, unknown>>;
		const offers = [a1.offer, b1.offer, a2.offer];
		expect(items.map((item) => item["offer"])).toEqual(offers);
		for (const [i, item] of items.entries()) {
			const acceptance = item["agent_acceptance"] as Record<string, string>;
			await expect(
				verifyOfferAcceptance(
					{
						offerSig: offers[i]?.["signature"] as string,
						requesterId: REQUESTER.id,
						requesterDomain: REQUESTER.domain,
						idempotencyKey: "relay-key",
					},
					acceptance["signature"] as string,
					keys.publicKey,
				),
			).resolves.toBe(true);
		}
		// One request acceptance over the complete ordered set: each Exchange the Broker
		// relays to derives its own projection from it.
		const requestAcceptance = body["agent_request_acceptance"] as Record<string, unknown>;
		const signedItems = offers.map((o) => ({
			offerSig: o["signature"] as string,
			exchange: o["exchange"] as string,
		}));
		await expect(
			verifyRequestAcceptance(
				{
					items: signedItems,
					requesterId: REQUESTER.id,
					requesterDomain: REQUESTER.domain,
					idempotencyKey: "relay-key",
				},
				requestAcceptance["signature"] as string,
				keys.publicKey,
			),
		).resolves.toBe(true);

		// The refused group rides in the body, the other Exchange's results unchanged.
		expect(resp.items?.[1]?.refusal?.code).toBe("permission_denied");
		expect(resp.items?.[1]?.refusal?.detail?.transaction_denial?.reason).toBe(
			"DENIAL_REASON_ACCOUNT_NOT_REGISTERED",
		);
		expect(resp.items?.[0]?.transaction_id).toBe("tx-a1");
		expect(resp.items?.[2]?.refusal).toBeUndefined();
		// Per-currency totals, never summed across currencies.
		expect(resp.totals?.map((t) => t.currency)).toEqual(["USD", "EUR"]);
		expect(resp.exchanges?.[0]?.offer_ids).toEqual(["offer-a1", "offer-a2"]);
	});

	it("sends a single offer as the degenerate one-item purchase", async () => {
		const one = await offerAt("offer-one", "exchange-a.test");
		const keys = await keyPair();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const broker = createBrokerClient("https://broker.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			signatureAgent: AGENT_DIRECTORY,
			send,
		});

		await broker.execute([one.verified]);

		const body = bodyOf(seen[0] as UnaryRequest);
		expect((body["items"] as unknown[]).length).toBe(1);
		expect(body["agent_request_acceptance"]).toBeDefined();
		expect(body["idempotency_key"]).toBeTypeOf("string");
	});

	it("refuses locally, before anything is sent", async () => {
		const good = [(await offerAt("offer-a", "exchange-a.test")).verified];
		const unaddressed = (
			await createVerifier("off", { resolve: async () => undefined, now: () => 0 }).sort([
				{ offer_id: "x", signature: "ab", signature_algorithm: "EdDSA" },
			])
		).verified;
		const keys = await keyPair();
		const signer = { privKey: keys.privateKey, keyid: "agent.v1" };
		const { send, seen } = recordingSend({ ver: "1.0" });

		const cases: Array<[string, Parameters<typeof createBrokerClient>[1], VerifiedOffer[], string]> =
			[
				[
					"requester domain is not the signing directory",
					{ requester: { ...REQUESTER, domain: "someone-else.test" }, signer, signatureAgent: AGENT_DIRECTORY, send },
					good,
					"malformed",
				],
				["no signature agent", { requester: REQUESTER, signer, send }, good, "malformed"],
				["no requester", { signer, signatureAgent: AGENT_DIRECTORY, send }, good, "malformed"],
				[
					"requester with no id",
					{ requester: { ...REQUESTER, id: "" }, signer, signatureAgent: AGENT_DIRECTORY, send },
					good,
					"malformed",
				],
				[
					"requester with no domain",
					{ requester: { ...REQUESTER, domain: "" }, signer, signatureAgent: AGENT_DIRECTORY, send },
					good,
					"malformed",
				],
				["no signer", { requester: REQUESTER, signatureAgent: AGENT_DIRECTORY, send }, good, "not_signable"],
				["no offers", { requester: REQUESTER, signer, signatureAgent: AGENT_DIRECTORY, send }, [], "malformed"],
				[
					"offer names no exchange",
					{ requester: REQUESTER, signer, signatureAgent: AGENT_DIRECTORY, send },
					unaddressed,
					"malformed",
				],
			];
		for (const [name, options, offers, kind] of cases) {
			const err = (await createBrokerClient("https://broker.test", options)
				.execute(offers)
				.catch((e: unknown) => e)) as ForaCallError;
			expect(err.kind, name).toBe(kind);
		}
		expect(seen).toEqual([]);
	});

	it("treats an explicit :443 and a different case as the same signing directory", async () => {
		const one = await offerAt("offer-one", "exchange-a.test");
		const keys = await keyPair();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const broker = createBrokerClient("https://broker.test", {
			requester: { ...REQUESTER, domain: "Agent.Test:443" },
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			signatureAgent: AGENT_DIRECTORY,
			send,
		});
		await broker.execute([one.verified]);
		expect(seen.length).toBe(1);
	});

	it("surfaces the Broker's own refusal as a typed failure", async () => {
		const one = await offerAt("offer-one", "exchange-a.test");
		const keys = await keyPair();
		const { send } = recordingSend(
			{
				code: "unauthenticated",
				message: "requester mismatch",
				details: [
					{
						type: "fora.v1.ErrorDetail",
						value: "ChJyZXF1ZXN0ZXIgbWlzbWF0Y2gSFWZvcmEudjEuQnJva2VyU2VydmljZYoBAggC",
						debug: {
							domain: "fora.v1.BrokerService",
							message: "requester mismatch",
							requestAuthFailure: { reason: "REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID" },
						},
					},
				],
			},
			401,
		);
		const broker = createBrokerClient("https://broker.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			signatureAgent: AGENT_DIRECTORY,
			send,
		});

		const err = (await broker.execute([one.verified]).catch((e: unknown) => e)) as ForaCallError;

		expect(err.kind).toBe("refused");
		expect(err.detail?.request_auth_failure?.reason).toBe(
			"REQUEST_AUTH_FAILURE_REASON_SIGNATURE_INVALID",
		);
	});
});

describe("Client.execute with several offers", () => {
	it("buys several offers from one Exchange in one request", async () => {
		const first = await offerAt("offer-1", "exchange.test");
		const second = await offerAt("offer-2", "exchange.test");
		const keys = await keyPair();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send,
		});

		await client.execute([first.verified, second.verified], { idempotencyKey: "batch-key" });

		expect(seen[0]?.url).toBe("https://exchange.test/fora.v1.ExchangeService/ExecuteTransaction");
		const body = bodyOf(seen[0] as UnaryRequest);
		expect((body["items"] as unknown[]).length).toBe(2);
		const requestAcceptance = body["agent_request_acceptance"] as Record<string, unknown>;
		await expect(
			verifyRequestAcceptance(
				{
					items: [first.offer, second.offer].map((o) => ({
						offerSig: o["signature"] as string,
						exchange: "exchange.test",
					})),
					requesterId: REQUESTER.id,
					requesterDomain: REQUESTER.domain,
					idempotencyKey: "batch-key",
				},
				requestAcceptance["signature"] as string,
				keys.publicKey,
			),
		).resolves.toBe(true);
	});

	it("refuses offers from more than one Exchange before sending", async () => {
		const first = await offerAt("offer-1", "exchange.test");
		const other = await offerAt("offer-2", "exchange-b.test");
		const keys = await keyPair();
		const { send, seen } = recordingSend({ ver: "1.0" });
		const client = createClient("https://exchange.test", {
			requester: REQUESTER,
			signer: { privKey: keys.privateKey, keyid: "agent.v1" },
			send,
		});

		await expect(client.execute([first.verified, other.verified])).rejects.toMatchObject({
			kind: "malformed",
		});
		expect(seen).toEqual([]);
	});
});
